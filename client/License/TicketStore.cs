using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace LicenseTester.License;

/// <summary>
/// 本地票据存储
///
/// 用 Windows DPAPI（CryptProtectData）加密，密钥绑定当前用户 ——
/// 别人拷走这个文件在他机器上也解不开。
///
/// ⚠️ DPAPI 只是提高门槛，不是真正的防线。
///    真正的防线是：票据里绑定了设备指纹，且由服务端私钥签名。
///    即使有人解开本地文件，票据也只能在本机使用。
/// </summary>
public static class TicketStore
{
    private static string Dir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "LicenseTester");

    private static string LicensePath => Path.Combine(Dir, "license.bin");
    private static string PubKeyPath => Path.Combine(Dir, "server-pubkey.pem");

    public static string StorageLocation => LicensePath;

    // ---------- 票据 ----------

    public static void Save(StoredLicense license)
    {
        Directory.CreateDirectory(Dir);
        var json = JsonSerializer.SerializeToUtf8Bytes(license, Json.Options);
        var encrypted = Protect(json);
        File.WriteAllBytes(LicensePath, encrypted);
    }

    public static StoredLicense? Load()
    {
        try
        {
            if (!File.Exists(LicensePath)) return null;
            var encrypted = File.ReadAllBytes(LicensePath);
            var json = Unprotect(encrypted);
            return JsonSerializer.Deserialize<StoredLicense>(json, Json.Options);
        }
        catch
        {
            // 文件损坏或被别的用户加密过 —— 当作没有授权处理
            return null;
        }
    }

    public static void Clear()
    {
        try
        {
            if (File.Exists(LicensePath)) File.Delete(LicensePath);
        }
        catch
        {
            /* 删不掉就算了，下次覆盖 */
        }
    }

    // ---------- 服务端公钥缓存 ----------

    public static void SavePublicKey(string pem)
    {
        Directory.CreateDirectory(Dir);
        File.WriteAllText(PubKeyPath, pem, Encoding.UTF8);
    }

    public static string? LoadPublicKey()
    {
        try
        {
            return File.Exists(PubKeyPath) ? File.ReadAllText(PubKeyPath, Encoding.UTF8) : null;
        }
        catch
        {
            return null;
        }
    }

    // ---------- DPAPI ----------

    [StructLayout(LayoutKind.Sequential)]
    private struct DataBlob
    {
        public int CbData;
        public IntPtr PbData;
    }

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptProtectData(
        ref DataBlob pDataIn,
        string? szDataDescr,
        IntPtr pOptionalEntropy,
        IntPtr pvReserved,
        IntPtr pPromptStruct,
        int dwFlags,
        out DataBlob pDataOut);

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptUnprotectData(
        ref DataBlob pDataIn,
        IntPtr ppszDataDescr,
        IntPtr pOptionalEntropy,
        IntPtr pvReserved,
        IntPtr pPromptStruct,
        int dwFlags,
        out DataBlob pDataOut);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr hMem);

    private const int CryptprotectUiForbidden = 0x1;

    private static byte[] Protect(byte[] data) => Transform(data, protect: true);

    private static byte[] Unprotect(byte[] data) => Transform(data, protect: false);

    private static byte[] Transform(byte[] data, bool protect)
    {
        var input = new DataBlob
        {
            CbData = data.Length,
            PbData = Marshal.AllocHGlobal(data.Length),
        };

        try
        {
            Marshal.Copy(data, 0, input.PbData, data.Length);

            bool ok = protect
                ? CryptProtectData(ref input, "LicenseTester", IntPtr.Zero, IntPtr.Zero,
                    IntPtr.Zero, CryptprotectUiForbidden, out var output)
                : CryptUnprotectData(ref input, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                    IntPtr.Zero, CryptprotectUiForbidden, out output);

            if (!ok)
            {
                throw new InvalidOperationException(
                    (protect ? "CryptProtectData" : "CryptUnprotectData") +
                    " 失败，Win32 错误码 " + Marshal.GetLastWin32Error());
            }

            try
            {
                var result = new byte[output.CbData];
                Marshal.Copy(output.PbData, result, 0, output.CbData);
                return result;
            }
            finally
            {
                LocalFree(output.PbData);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(input.PbData);
        }
    }
}
