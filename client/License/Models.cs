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

// ============ 票据载荷（与证书服务端 TicketPayload 对应） ============

public sealed class TicketPayload
{
    public int V { get; set; }
    public long Lid { get; set; }
    public string Fp { get; set; } = "";
    public long Iat { get; set; }
    public long Exp { get; set; }
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
