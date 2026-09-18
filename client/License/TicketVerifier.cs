using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace LicenseTester.License;

/// <summary>
/// 票据离线验签
///
/// 这是整个客户端授权体系的信任根：只要公钥验签通过，就说明票据确实由
/// 服务端私钥签发过，客户端不需要联网也能确认授权有效。
///
/// ⚠️ 三个必须对齐的细节，错一个就验不过：
///   1. 签名对象是 payload 的 **base64url 字符串本身**（的 ASCII 字节），
///      不是解码后的 JSON —— 避免 JSON 序列化差异导致验签失败
///   2. 签名编码必须是 **IEEE P1363（r||s 定长）**，不是 DER
///      .NET 的 ECDsa.VerifyData 默认按 P1363 解析，服务端已相应配置
///   3. 哈希算法 SHA-256
/// </summary>
public static class TicketVerifier
{
    public sealed record Result(bool Ok, TicketPayload? Payload, string Reason);

    public static Result Verify(string ticket, string publicKeyPem, string expectedFingerprint)
    {
        if (string.IsNullOrWhiteSpace(ticket))
        {
            return new Result(false, null, "票据为空");
        }

        var parts = ticket.Split('.');
        if (parts.Length != 2)
        {
            return new Result(false, null, "票据格式错误（应为 body.signature）");
        }

        try
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(publicKeyPem);

            var signedData = Encoding.ASCII.GetBytes(parts[0]);
            var signature = Base64Url.DecodeFromChars(parts[1]);

            if (!ecdsa.VerifyData(signedData, signature, HashAlgorithmName.SHA256))
            {
                return new Result(false, null, "签名校验失败 —— 票据被篡改，或公钥与服务端不匹配");
            }

            var payloadJson = Base64Url.DecodeFromChars(parts[0]);
            var payload = JsonSerializer.Deserialize<TicketPayload>(payloadJson, Json.Options);

            if (payload is null)
            {
                return new Result(false, null, "票据内容解析失败");
            }

            if (payload.V != 1)
            {
                return new Result(false, payload, $"票据协议版本不支持（v={payload.V}）");
            }

            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (payload.Exp <= now)
            {
                var exp = DateTimeOffset.FromUnixTimeSeconds(payload.Exp).LocalDateTime;
                return new Result(false, payload, $"票据已过期（{exp:yyyy-MM-dd HH:mm:ss}）");
            }

            if (!string.Equals(payload.Fp, expectedFingerprint, StringComparison.OrdinalIgnoreCase))
            {
                return new Result(false, payload, "票据绑定的设备与本机不符 —— 票据是从别的机器复制过来的");
            }

            return new Result(true, payload, "验签通过");
        }
        catch (Exception ex)
        {
            return new Result(false, null, "验签异常：" + ex.Message);
        }
    }

    /// <summary>剩余天数（向上取整），用于展示</summary>
    public static int DaysLeft(long expiresAt)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var diff = expiresAt - now;
        if (diff <= 0) return 0;
        return (int)Math.Ceiling(diff / 86400.0);
    }
}
