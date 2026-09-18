using System.Text.Json;

namespace LicenseTester.License;

// ============ 服务端响应包装 ============

public sealed class ApiResponse<T>
{
    public int Code { get; set; }
    public string Msg { get; set; } = "";
    public T? Data { get; set; }
}

public sealed class ActivateData
{
    public string Ticket { get; set; } = "";
    public long ExpiresAt { get; set; }
    public long ServerTime { get; set; }
    public LicenseInfo? License { get; set; }
    public EntitlementInfo? Entitlement { get; set; }
}

public sealed class CheckData
{
    public string Ticket { get; set; } = "";
    public long ExpiresAt { get; set; }
    public long ServerTime { get; set; }
    public EntitlementInfo? Entitlement { get; set; }
    /// <summary>本次是否推进了校验周期</summary>
    public bool Advanced { get; set; }
    /// <summary>上次计划校验时间</summary>
    public long? PreviousNextCheckAt { get; set; }
}

/// <summary>本设备的授权与校验排期</summary>
public sealed class EntitlementInfo
{
    public long ActivatedAt { get; set; }
    public long ExpiresAt { get; set; }
    public int DaysLeft { get; set; }

    public string CheckMode { get; set; } = "";
    public int CheckFrequency { get; set; }
    public int CheckIntervalDays { get; set; }
    public int CheckRemindPercent { get; set; }

    public long LastCheckAt { get; set; }
    public long? NextCheckAt { get; set; }
    public long? RemindAt { get; set; }

    /// <summary>active | due | overdue</summary>
    public string State { get; set; } = "active";
    public bool MustCheck { get; set; }

    public bool HasSchedule => NextCheckAt.HasValue && CheckIntervalDays > 0;
}

public sealed class LicenseInfo
{
    public int ActivationDays { get; set; }
    public int MaxActivations { get; set; }
    public int ActivationCount { get; set; }
    public int MaxDevices { get; set; }
    public int MaxUnbinds { get; set; }
    public int UnbindCount { get; set; }
    public long? ExpiresAt { get; set; }
}

public sealed class TicketData
{
    public string Ticket { get; set; } = "";
    public long ExpiresAt { get; set; }
    public long ServerTime { get; set; }
}

public sealed class UnbindData
{
    public int UnbindCount { get; set; }
    public int MaxUnbinds { get; set; }
    public List<string> Released { get; set; } = new();
}

public sealed class PubKeyData
{
    public string Algorithm { get; set; } = "";
    public string KeyId { get; set; } = "";
    public string PublicKeyPem { get; set; } = "";
}

// ============ 票据载荷（与服务端 TicketPayload 对应） ============

public sealed class TicketPayload
{
    public int V { get; set; }
    public long Lid { get; set; }
    public string Fp { get; set; } = "";
    public long Iat { get; set; }
    public long Exp { get; set; }

    // ---- 授权与校验排期：客户端离线也能据此判断该不该弹校验窗口 ----

    /// <summary>首次激活时间（授权时间锚点）</summary>
    public long Aat { get; set; }
    /// <summary>本设备授权到期时间</summary>
    public long Eat { get; set; }
    /// <summary>计划下次校验时间；null = 不做定期校验</summary>
    public long? Nca { get; set; }
    /// <summary>提醒开始时间；null = 不提醒</summary>
    public long? Rat { get; set; }
}

// ============ 本地持久化结构 ============

public sealed class StoredLicense
{
    public string ServerUrl { get; set; } = "";
    public string Product { get; set; } = "";

    /// <summary>完整卡密 —— 自助解绑时要用，整体经 DPAPI 加密后落盘</summary>
    public string LicenseKey { get; set; } = "";

    /// <summary>展示用的脱敏卡密</summary>
    public string LicenseKeyMasked { get; set; } = "";

    public string Ticket { get; set; } = "";
    public long ExpiresAt { get; set; }
    public long LastHeartbeat { get; set; }

    // ---- 时间锚点：用于检测系统时间回拨 ----

    /// <summary>上次从服务端拿到的真实时间（Unix 秒）</summary>
    public long LastServerTime { get; set; }

    /// <summary>当时 Environment.TickCount64 的读数（毫秒）。不受系统时间影响</summary>
    public long LastTicks { get; set; }

    // ---- 授权快照（断网也能展示） ----

    public long EntitlementExpiresAt { get; set; }
    public long LastCheckAt { get; set; }
    public long? NextCheckAt { get; set; }
    public long? RemindAt { get; set; }
    public int CheckIntervalDays { get; set; }
    public int CheckRemindPercent { get; set; }

    // ---- 用户偏好 ----

    /// <summary>关闭「提前提醒」弹窗（用户可在设置里关掉）</summary>
    public bool MuteRemind { get; set; }

    /// <summary>「今天不再提示」的日期，格式 yyyyMMdd；0 = 未设置</summary>
    public int SnoozeDate { get; set; }
}

public static class Json
{
    /// <summary>服务端用 snake_case，这里统一映射</summary>
    public static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        PropertyNameCaseInsensitive = true,
        WriteIndented = true,
    };
}
