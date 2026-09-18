using System.Windows;
using System.Windows.Threading;
using LicenseTester.License;

namespace LicenseTester;

public partial class MainWindow : Window
{
    private readonly LicenseClient _client = new();
    private string _fingerprint = "";
    private string? _publicKeyPem;
    private StoredLicense? _stored;
    private DispatcherTimer? _heartbeatTimer;
    private bool _busy;

    private const long HeartbeatIntervalSeconds = 24 * 60 * 60;

    public MainWindow()
    {
        InitializeComponent();
        Loaded += OnLoaded;
    }

    // ============ 启动 ============

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        _fingerprint = DeviceFingerprint.Compute();
        TxtFingerprint.Text = _fingerprint;

        Log("════ 卡密授权测试客户端 ════");
        Log($"设备指纹 : {_fingerprint}");
        Log($"存储位置 : {TicketStore.StorageLocation}");

        _stored = TicketStore.Load();
        if (_stored is not null)
        {
            TxtServer.Text = _stored.ServerUrl;
            TxtProduct.Text = _stored.Product;
            Log($"发现本地票据 : {_stored.LicenseKeyMasked}（{_stored.Product}）");
        }
        else
        {
            Log("未发现本地票据，需要激活。");
        }

        _publicKeyPem = TicketStore.LoadPublicKey();
        if (_publicKeyPem is not null)
        {
            Log("已加载本地缓存的验签公钥。");
        }
        else
        {
            Log("本地无验签公钥，请先点「从服务端获取」。");
        }

        RefreshStatus();
        StartHeartbeatTimer();
        await CheckStartupGateAsync();

        // 启动时若票据临近或超过续期周期，自动续一次
        if (_stored is not null && _publicKeyPem is not null)
        {
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (now - _stored.LastHeartbeat >= HeartbeatIntervalSeconds)
            {
                Log("距上次心跳已超过 24 小时，自动续期…");
                await HeartbeatAsync();
            }
        }
    }

    /// <summary>
    /// 启动闸门。三档处理：
    ///   1. 时间被回拨        → 必须联网校验，不给跳过
    ///   2. 已过校验期        → 强制校验（正式软件此时应停止服务）
    ///   3. 进入提醒期        → 提示一次，可跳过；选「否」= 今天不再提示
    /// </summary>
    private async Task CheckStartupGateAsync()
    {
        if (_stored is null) return;

        var tg = TimeGuard.Check(_stored);

        // 1) 时间被回拨
        if (!tg.Ok)
        {
            Log("⚠ " + tg.Reason);
            var go = MessageBox.Show(
                tg.Reason + "\n\n是否立即联网校验？",
                "时间异常", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (go == MessageBoxResult.Yes) await CheckAsync();
            return;
        }

        // 2) 已过校验期
        if (_stored.NextCheckAt is long nc && tg.EstimatedNow >= nc)
        {
            Log("⚠ 已过校验期 —— 正式软件此时必须停止服务");
            var go = MessageBox.Show(
                $"已过校验期（应校验时间 {Fmt(nc)}）。\n\n" +
                "正式软件此时必须停止服务，直到校验通过。\n\n是否立即校验？",
                "需要校验", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (go == MessageBoxResult.Yes) await CheckAsync();
            return;
        }

        // 3) 进入提醒期
        if (_stored.RemindAt is long ra && tg.EstimatedNow >= ra && !_stored.MuteRemind)
        {
            int today = int.Parse(DateTime.Now.ToString("yyyyMMdd"));
            if (_stored.SnoozeDate == today)
            {
                Log("已进入校验提醒期（今天已选择不再提示）");
                return;
            }

            Log("⚠ 已进入校验提醒期");
            var go = MessageBox.Show(
                $"授权校验将于 {Fmt(_stored.NextCheckAt ?? 0)} 到期。\n\n" +
                "「是」= 立即校验\n「否」= 今天不再提示",
                "校验提醒", MessageBoxButton.YesNo, MessageBoxImage.Information);

            if (go == MessageBoxResult.Yes)
            {
                await CheckAsync();
            }
            else
            {
                _stored.SnoozeDate = today;
                TicketStore.Save(_stored);
                Log("已设置今天不再提示");
            }
        }
    }

    private void StartHeartbeatTimer()
    {
        _heartbeatTimer = new DispatcherTimer { Interval = TimeSpan.FromMinutes(1) };
        _heartbeatTimer.Tick += async (_, _) =>
        {
            if (_stored is null || _busy) return;
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (now - _stored.LastHeartbeat >= HeartbeatIntervalSeconds)
            {
                await HeartbeatAsync();
            }
        };
        _heartbeatTimer.Start();
    }

    // ============ 激活 ============

    private async void BtnActivate_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;

        var key = TxtLicenseKey.Text.Trim();
        if (string.IsNullOrWhiteSpace(key))
        {
            Warn("请先输入卡密。");
            return;
        }

        await RunBusy(async () =>
        {
            Sync();
            Log($"── 发起激活：{Mask(key)} @ {_client.BaseUrl}（软件：{_client.Product}）");

            var resp = await _client.ActivateAsync(key, _fingerprint, Environment.MachineName);

            if (resp.Code != 0)
            {
                Log($"✗ 激活失败 [{resp.Code}] {resp.Msg}");
                SetStatus($"激活失败：{resp.Msg}", isError: true);
                return;
            }

            var data = resp.Data;
            if (data is null || string.IsNullOrWhiteSpace(data.Ticket))
            {
                Log("✗ 激活响应缺少票据");
                return;
            }

            // 激活成功后必须本地验签，确认拿到的确实是服务端签发的合法票据
            if (_publicKeyPem is null)
            {
                Log("本地无验签公钥，正在从服务端获取…");
                if (!await EnsurePublicKeyAsync()) return;
            }

            var verify = TicketVerifier.Verify(data.Ticket, _publicKeyPem!, _fingerprint);
            Log($"本地验签：{(verify.Ok ? "✓ 通过" : "✗ " + verify.Reason)}");
            if (!verify.Ok)
            {
                SetStatus("激活返回的票据验签失败", isError: true);
                return;
            }

            _stored = new StoredLicense
            {
                ServerUrl = _client.BaseUrl,
                Product = _client.Product,
                LicenseKey = key,
                LicenseKeyMasked = Mask(key),
                Ticket = data.Ticket,
                ExpiresAt = data.ExpiresAt,
                LastHeartbeat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            };

            if (data.License is not null)
            {
                var li = data.License;
                Log($"激活次数 : {li.ActivationCount}/{li.MaxActivations}");
                Log($"绑定设备 : {li.MaxDevices} 台上限");
                Log($"解绑次数 : {li.UnbindCount}/{li.MaxUnbinds}");
            }

            if (data.Entitlement is not null)
            {
                ApplyEntitlement(data.Entitlement, data.ServerTime);
                LogEntitlement(data.Entitlement);
            }
            else
            {
                TimeGuard.Anchor(_stored, data.ServerTime);
                TicketStore.Save(_stored);
            }

            Log($"✓ 激活成功，票据已加密保存（{TicketVerifier.DaysLeft(data.ExpiresAt)} 天后到期）");
            RefreshStatus();
        });
    }

    // ============ 心跳续期 ============

    private async void BtnHeartbeat_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        await HeartbeatAsync();
    }

    private async Task HeartbeatAsync()
    {
        if (_stored is null)
        {
            Warn("本地没有票据，请先激活。");
            return;
        }

        await RunBusy(async () =>
        {
            Sync();
            Log("── 发起心跳续期…");
            var resp = await _client.HeartbeatAsync(_stored!.Ticket, _fingerprint);

            if (resp.Code != 0)
            {
                Log($"✗ 心跳被拒 [{resp.Code}] {resp.Msg}");
                if (resp.Code is 2001 or 1002 or 1004)
                {
                    SetStatus($"授权已失效：{resp.Msg}", isError: true);
                }
                return;
            }

            var data = resp.Data;
            if (data is null) return;

            if (_publicKeyPem is not null)
            {
                var verify = TicketVerifier.Verify(data.Ticket, _publicKeyPem, _fingerprint);
                Log($"新票据验签：{(verify.Ok ? "✓ 通过" : "✗ " + verify.Reason)}");
                if (!verify.Ok) return;
            }

            _stored!.Ticket = data.Ticket;
            _stored.ExpiresAt = data.ExpiresAt;
            _stored.LastHeartbeat = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            // 心跳也带回服务端时间，顺手重新锚定，让回拨检测持续有效
            TimeGuard.Anchor(_stored, data.ServerTime);
            TicketStore.Save(_stored);

            Log($"✓ 续期成功，新到期时间 {Fmt(data.ExpiresAt)}");
            RefreshStatus();
        });
    }

    // ============ 定期校验 ============

    private async void BtnCheck_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        await CheckAsync();
    }

    private async Task CheckAsync()
    {
        if (_stored is null)
        {
            Warn("本地没有票据，请先激活。");
            return;
        }

        await RunBusy(async () =>
        {
            Sync();
            Log("── 发起定期校验…");

            var resp = await _client.CheckAsync(_stored!.Ticket, _fingerprint);

            if (resp.Code != 0)
            {
                Log($"✗ 校验失败 [{resp.Code}] {resp.Msg}");
                if (resp.Code is 1008 or 2001 or 1002)
                {
                    SetStatus($"✗ {resp.Msg}", isError: true);
                }
                return;
            }

            var data = resp.Data;
            if (data is null) return;

            if (_publicKeyPem is not null)
            {
                var verify = TicketVerifier.Verify(data.Ticket, _publicKeyPem, _fingerprint);
                Log($"新票据验签：{(verify.Ok ? "✓ 通过" : "✗ " + verify.Reason)}");
                if (!verify.Ok) return;
            }

            _stored!.Ticket = data.Ticket;
            _stored.ExpiresAt = data.ExpiresAt;
            _stored.LastHeartbeat = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            if (data.Entitlement is not null)
            {
                var prev = data.PreviousNextCheckAt;
                ApplyEntitlement(data.Entitlement, data.ServerTime);

                if (data.Advanced && prev is long p && data.Entitlement.NextCheckAt is long n)
                {
                    // 直观展示基准规则：提前校验基准不变，超期校验基准重置
                    Log($"  上次计划 : {Fmt(p)}");
                    Log($"  下次计划 : {Fmt(n)}");
                    Log(data.ServerTime <= p
                        ? "  本次属提前/准时校验 → 以原计划为基准"
                        : "  本次属超期校验 → 基准重置为本次时间");
                }
                LogEntitlement(data.Entitlement);
            }
            else
            {
                TimeGuard.Anchor(_stored, data.ServerTime);
                TicketStore.Save(_stored);
            }

            Log("✓ 校验通过");
            RefreshStatus();
        });
    }

    /// <summary>开关提前提醒。到校验期该强制还是强制，关的只是提前弹窗</summary>
    private void BtnMuteRemind_Click(object sender, RoutedEventArgs e)
    {
        if (_stored is null) { Warn("请先激活。"); return; }

        _stored.MuteRemind = !_stored.MuteRemind;
        TicketStore.Save(_stored);

        Log(_stored.MuteRemind
            ? "已关闭提前提醒（到校验期仍会强制要求校验）"
            : "已开启提前提醒");
        RefreshStatus();
    }

    /// <summary>把时间锚点往前挪 2 小时，模拟用户改慢了系统时间，验证回拨检测</summary>
    private void BtnSimulate_Click(object sender, RoutedEventArgs e)
    {
        if (_stored is null) { Warn("请先激活。"); return; }

        _stored.LastServerTime -= 7200;
        TicketStore.Save(_stored);

        Log("── 模拟：时间锚点往前挪 2 小时（等价于用户把系统时间调慢 2 小时）");
        Log("   此时系统时间会明显晚于推算值，观察下方检测结果…");
        RefreshStatus();
    }

    private void LogEntitlement(EntitlementInfo ent)
    {
        Log($"  授权期   : {Fmt(ent.ActivatedAt)} → {Fmt(ent.ExpiresAt)}（剩余 {ent.DaysLeft} 天）");
        Log($"  校验排期 : {(ent.HasSchedule ? $"每 {ent.CheckIntervalDays} 天一次" : "不做定期校验")}");

        if (ent.NextCheckAt is long n)
        {
            Log($"  下次校验 : {Fmt(n)}");
            Log($"  提醒开始 : {(ent.RemindAt is long r ? Fmt(r) : "不提醒")}");
        }
        Log($"  当前状态 : {StateLabel(ent.State)}");
    }

    private static string StateLabel(string state) => state switch
    {
        "active" => "正常",
        "due" => "进入提醒期（可跳过）",
        "overdue" => "已过校验期（应强制停用）",
        _ => state,
    };

    // ============ 解绑 ============

    private async void BtnUnbind_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        if (_stored is null)
        {
            Warn("本地没有票据，无法解绑。");
            return;
        }

        var confirm = MessageBox.Show(
            $"确定要解绑本设备吗？\n\n卡密：{_stored.LicenseKeyMasked}\n" +
            "解绑后本机授权立即失效，可在另一台设备上重新激活。",
            "确认解绑", MessageBoxButton.OKCancel, MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.OK) return;

        await RunBusy(async () =>
        {
            Sync();
            Log("── 发起解绑…");
            var resp = await _client.UnbindAsync(_stored!.LicenseKey, _fingerprint);

            if (resp.Code != 0)
            {
                Log($"✗ 解绑失败 [{resp.Code}] {resp.Msg}");
                SetStatus($"解绑失败：{resp.Msg}", isError: true);
                return;
            }

            Log($"✓ 解绑成功，已释放 {resp.Data?.Released.Count ?? 0} 个设备");
            if (resp.Data is not null)
            {
                Log($"解绑次数已用：{resp.Data.UnbindCount}/{resp.Data.MaxUnbinds}");
            }

            TicketStore.Clear();
            _stored = null;
            TxtLicenseKey.Clear();
            Log("本地票据已清除，可换设备重新激活。");
            RefreshStatus();
        });
    }

    // ============ 本地验签 ============

    private void BtnVerify_Click(object sender, RoutedEventArgs e)
    {
        if (_stored is null)
        {
            Warn("本地没有票据，请先激活。");
            return;
        }
        if (_publicKeyPem is null)
        {
            Warn("本地没有验签公钥，请先点「从服务端获取」。");
            return;
        }

        Log("── 离线验签（不联网）──");
        var result = TicketVerifier.Verify(_stored.Ticket, _publicKeyPem, _fingerprint);

        if (!result.Ok)
        {
            Log($"✗ {result.Reason}");
            SetStatus($"验签失败：{result.Reason}", isError: true);
            return;
        }

        var p = result.Payload!;
        Log("✓ 验签通过");
        Log($"   卡密ID   : {p.Lid}");
        Log($"   设备指纹 : {p.Fp[..16]}…");
        Log($"   签发时间 : {Fmt(p.Iat)}");
        Log($"   到期时间 : {Fmt(p.Exp)}");
        Log($"   剩余天数 : {TicketVerifier.DaysLeft(p.Exp)} 天");
        RefreshStatus();
    }

    // ============ 公钥 ============

    private async void BtnFetchKey_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        await RunBusy(async () =>
        {
            Sync();
            Log("── 从服务端获取验签公钥…");
            await EnsurePublicKeyAsync(force: true);
        });
    }

    private async Task<bool> EnsurePublicKeyAsync(bool force = false)
    {
        if (!force && _publicKeyPem is not null) return true;

        var resp = await _client.GetPublicKeyAsync();
        if (resp.Code != 0 || resp.Data is null || string.IsNullOrWhiteSpace(resp.Data.PublicKeyPem))
        {
            Log($"✗ 获取公钥失败：{resp.Msg}");
            return false;
        }

        _publicKeyPem = resp.Data.PublicKeyPem;
        TicketStore.SavePublicKey(_publicKeyPem);
        TxtKeyId.Text = resp.Data.KeyId;
        Log($"✓ 公钥已获取（key_id {resp.Data.KeyId}，{resp.Data.Algorithm}）");
        return true;
    }

    // ============ 其他操作 ============

    private void BtnClear_Click(object sender, RoutedEventArgs e)
    {
        TicketStore.Clear();
        _stored = null;
        TxtLicenseKey.Clear();
        Log("本地票据已清除（服务端绑定记录未变动，仍占用设备名额）。");
        RefreshStatus();
    }

    private void BtnCopyFp_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Clipboard.SetText(_fingerprint);
            Log("设备指纹已复制到剪贴板。");
        }
        catch (Exception ex)
        {
            Warn("复制失败：" + ex.Message);
        }
    }

    private void BtnDetail_Click(object sender, RoutedEventArgs e)
    {
        var detail = DeviceFingerprint.Describe();
        Log("── 指纹采集明细 ──");
        foreach (var line in detail.Split('\n'))
        {
            Log("   " + line.TrimEnd());
        }
        MessageBox.Show(
            detail + "\n\n任一来源变化都会导致指纹变化，此时需要解绑后重新激活。",
            "设备指纹采集明细", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void BtnClearLog_Click(object sender, RoutedEventArgs e) => TxtLog.Clear();

    // ============ 内部工具 ============

    private void Sync()
    {
        _client.BaseUrl = string.IsNullOrWhiteSpace(TxtServer.Text)
            ? "https://api-key.orkestr.run"
            : TxtServer.Text.Trim();
        _client.Product = string.IsNullOrWhiteSpace(TxtProduct.Text)
            ? "license-tester"
            : TxtProduct.Text.Trim();
    }

    private async Task RunBusy(Func<Task> action)
    {
        if (_busy) return;
        _busy = true;
        SetButtonsEnabled(false);
        try
        {
            await action();
        }
        catch (Exception ex)
        {
            Log("✗ 未捕获异常：" + ex.Message);
        }
        finally
        {
            _busy = false;
            SetButtonsEnabled(true);
        }
    }

    private void SetButtonsEnabled(bool enabled)
    {
        BtnActivate.IsEnabled = enabled;
        BtnCheck.IsEnabled = enabled;
        BtnHeartbeat.IsEnabled = enabled;
        BtnUnbind.IsEnabled = enabled;
        BtnVerify.IsEnabled = enabled;
        BtnFetchKey.IsEnabled = enabled;
        BtnMuteRemind.IsEnabled = enabled;
        BtnSimulate.IsEnabled = enabled;
    }

    private void RefreshStatus()
    {
        var muted = (System.Windows.Media.Brush)FindResource("Muted");
        var err = (System.Windows.Media.Brush)FindResource("ErrBrush");

        if (_stored is null)
        {
            SetStatus("未激活", isError: false);
            TxtEntitlement.Text = "—";
            TxtDaysLeft.Text = "—";
            TxtCheckPlan.Text = "—";
            TxtNextCheck.Text = "—";
            TxtTimeGuard.Text = "—";
            TxtTimeGuard.Foreground = muted;
            return;
        }

        var s = _stored;

        // ---- 时间可信度：用推算时间，不用系统时间 ----
        var tg = TimeGuard.Check(s);
        TxtTimeGuard.Text = (tg.Ok ? "✓ " : "✗ ") + tg.Reason;
        TxtTimeGuard.Foreground = tg.Ok ? muted : err;

        long now = tg.EstimatedNow;

        // ---- 票据验签 ----
        TicketVerifier.Result? v = null;
        if (_publicKeyPem is not null)
        {
            v = TicketVerifier.Verify(s.Ticket, _publicKeyPem, _fingerprint);
        }

        // ---- 授权期 ----
        long entExpires = s.EntitlementExpiresAt > 0
            ? s.EntitlementExpiresAt
            : (v?.Payload?.Eat ?? s.ExpiresAt);

        TxtEntitlement.Text = $"{Fmt(v?.Payload?.Aat ?? 0)} → {Fmt(entExpires)}";
        var days = (int)Math.Ceiling((entExpires - now) / 86400.0);
        TxtDaysLeft.Text = days > 0 ? $"{days} 天" : "已过期";

        // ---- 校验排期 ----
        if (s.NextCheckAt is long next && s.CheckIntervalDays > 0)
        {
            TxtCheckPlan.Text = $"每 {s.CheckIntervalDays} 天一次" +
                (s.CheckRemindPercent > 0 ? $"，提前 {s.CheckRemindPercent}% 提醒" : "，不提前提醒") +
                (s.MuteRemind ? "（提醒已关闭）" : "");
            TxtNextCheck.Text = Fmt(next);
        }
        else
        {
            TxtCheckPlan.Text = "不做定期校验（激活那一次即算完成）";
            TxtNextCheck.Text = "—";
        }

        // ---- 综合状态：按优先级依次判定 ----
        if (v is null)
        {
            SetStatus("已保存票据（未加载公钥，无法验签）", isError: false);
        }
        else if (!v.Ok)
        {
            SetStatus("✗ " + v.Reason, isError: true);
        }
        else if (!tg.Ok)
        {
            SetStatus("✗ " + tg.Reason, isError: true);
        }
        else if (now >= entExpires)
        {
            SetStatus("✗ 本设备授权已到期，请重新使用卡密激活", isError: true);
        }
        else if (s.NextCheckAt is long nc && now >= nc)
        {
            SetStatus("✗ 已过校验期，软件应强制停用，请立即执行校验", isError: true);
        }
        else if (s.RemindAt is long ra && now >= ra && !s.MuteRemind)
        {
            SetStatus("⚠ 已进入校验提醒期，可跳过或立即校验", isError: true);
        }
        else
        {
            SetStatus("✓ 授权有效（本地验签通过）", isError: false);
        }
    }

    /// <summary>把服务端返回的授权信息落盘，并校准时间锚点</summary>
    private void ApplyEntitlement(EntitlementInfo ent, long serverTime)
    {
        if (_stored is null) return;

        _stored.EntitlementExpiresAt = ent.ExpiresAt;
        _stored.LastCheckAt = ent.LastCheckAt;
        _stored.NextCheckAt = ent.NextCheckAt;
        _stored.RemindAt = ent.RemindAt;
        _stored.CheckIntervalDays = ent.CheckIntervalDays;
        _stored.CheckRemindPercent = ent.CheckRemindPercent;

        // 每次拿到服务端时间都重新锚定，回拨检测才有效
        TimeGuard.Anchor(_stored, serverTime);

        TicketStore.Save(_stored);
    }

    private void SetStatus(string text, bool isError)
    {
        TxtStatus.Text = text;
        TxtStatus.Foreground = isError
            ? (System.Windows.Media.Brush)FindResource("ErrBrush")
            : (System.Windows.Media.Brush)FindResource("OkBrush");
    }

    private static string Fmt(long unix) =>
        unix <= 0 ? "—" : DateTimeOffset.FromUnixTimeSeconds(unix).LocalDateTime.ToString("yyyy-MM-dd HH:mm:ss");

    private static string Mask(string key)
    {
        var s = key.Replace("-", "");
        if (s.Length < 15) return key;
        return $"{s[..5]}-·····-{s[^5..]}";
    }

    private void Log(string message)
    {
        TxtLog.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}{Environment.NewLine}");
        TxtLog.ScrollToEnd();
    }

    private void Warn(string message)
    {
        Log("⚠ " + message);
        MessageBox.Show(message, "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
    }
}
