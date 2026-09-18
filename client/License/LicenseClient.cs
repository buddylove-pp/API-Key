using System.Net.Http;
using System.Text;
using System.Text.Json;

namespace LicenseTester.License;

/// <summary>
/// 授权服务 HTTP 客户端
///
/// 只用 HttpClient + System.Text.Json，无任何第三方依赖。
/// </summary>
public sealed class LicenseClient
{
    private static readonly HttpClient Http = new()
    {
        Timeout = TimeSpan.FromSeconds(20),
    };

    public string BaseUrl { get; set; } = "http://localhost:8080";
    public string Product { get; set; } = "license-tester";

    // ---------- 公共接口 ----------

    public Task<ApiResponse<ActivateData>> ActivateAsync(string licenseKey, string deviceFp, string deviceName)
        => PostAsync<ActivateData>("/api/v1/activate", new
        {
            license_key = licenseKey,
            device_fp = deviceFp,
            device_name = deviceName,
            product = Product,
            app_version = "1.0.0",
        });

    public Task<ApiResponse<TicketData>> HeartbeatAsync(string ticket, string deviceFp)
        => PostAsync<TicketData>("/api/v1/heartbeat", new
        {
            ticket,
            device_fp = deviceFp,
            app_version = "1.0.0",
        });

    public Task<ApiResponse<UnbindData>> UnbindAsync(string licenseKey, string deviceFp)
        => PostAsync<UnbindData>("/api/v1/unbind", new
        {
            license_key = licenseKey,
            device_fp = deviceFp,
        });

    public async Task<ApiResponse<PubKeyData>> GetPublicKeyAsync()
    {
        try
        {
            var url = BaseUrl.TrimEnd('/') + "/api/v1/pubkey";
            var text = await Http.GetStringAsync(url).ConfigureAwait(false);
            return JsonSerializer.Deserialize<ApiResponse<PubKeyData>>(text, Json.Options)
                   ?? Fail<PubKeyData>("服务端返回无法解析");
        }
        catch (Exception ex)
        {
            return Fail<PubKeyData>(Describe(ex));
        }
    }

    // ---------- 内部 ----------

    private async Task<ApiResponse<T>> PostAsync<T>(string path, object body)
    {
        try
        {
            var url = BaseUrl.TrimEnd('/') + path;
            var payload = JsonSerializer.Serialize(body, Json.Options);

            using var content = new StringContent(payload, Encoding.UTF8, "application/json");
            using var resp = await Http.PostAsync(url, content).ConfigureAwait(false);
            var text = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);

            if (string.IsNullOrWhiteSpace(text))
            {
                return Fail<T>($"服务端返回空响应（HTTP {(int)resp.StatusCode}）");
            }

            var parsed = JsonSerializer.Deserialize<ApiResponse<T>>(text, Json.Options);
            return parsed ?? Fail<T>("服务端返回无法解析：" + Truncate(text));
        }
        catch (TaskCanceledException)
        {
            return Fail<T>("请求超时 —— 服务端无响应或网络不通");
        }
        catch (Exception ex)
        {
            return Fail<T>(Describe(ex));
        }
    }

    private static ApiResponse<T> Fail<T>(string msg) => new() { Code = -1, Msg = msg, Data = default };

    private static string Describe(Exception ex) =>
        ex switch
        {
            HttpRequestException hre => "无法连接服务端：" + hre.Message,
            _ => ex.GetType().Name + "：" + ex.Message,
        };

    private static string Truncate(string s) => s.Length <= 200 ? s : s[..200] + "…";
}
