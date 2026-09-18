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
            TicketStore.Save(_stored);

            if (data.License is not null)
            {
                var li = data.License;
                Log($"激活次数 : {li.ActivationCount}/{li.MaxActivations}");
                Log($"绑定设备 : {li.MaxDevices} 台上限");
                Log($"解绑次数 : {li.UnbindCount}/{li.MaxUnbinds}");
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
            TicketStore.Save(_stored);

            Log($"✓ 续期成功，新到期时间 {Fmt(data.ExpiresAt)}");
            RefreshStatus();
        });
    }

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
            ? "http://localhost:8080"
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
        BtnHeartbeat.IsEnabled = enabled;
        BtnUnbind.IsEnabled = enabled;
        BtnVerify.IsEnabled = enabled;
        BtnFetchKey.IsEnabled = enabled;
    }

    private void RefreshStatus()
    {
        if (_stored is null)
        {
            SetStatus("未激活", isError: false);
            TxtExpiry.Text = "—";
            TxtDaysLeft.Text = "—";
            return;
        }

        if (_publicKeyPem is null)
        {
            SetStatus("已保存票据（未加载公钥，无法验签）", isError: false);
        }
        else
        {
            var v = TicketVerifier.Verify(_stored.Ticket, _publicKeyPem, _fingerprint);
            if (v.Ok)
            {
                SetStatus("✓ 授权有效（本地验签通过）", isError: false);
            }
            else
            {
                SetStatus("✗ " + v.Reason, isError: true);
            }
        }

        TxtExpiry.Text = Fmt(_stored.ExpiresAt);
        var days = TicketVerifier.DaysLeft(_stored.ExpiresAt);
        TxtDaysLeft.Text = days > 0 ? $"{days} 天" : "已过期";
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
