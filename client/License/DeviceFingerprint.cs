using System.IO;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;

namespace LicenseTester.License;

/// <summary>
/// 设备指纹
///
/// 多源采集 + 容错：任何一项取不到就跳过，不让整个指纹生成失败。
/// 最终只上传 SHA-256 哈希，**不上传任何原始硬件信息**。
///
/// 采集来源：
///   1. 注册表 MachineGuid        —— 最稳定，重装系统才会变
///   2. 系统盘卷序列号            —— 格式化才会变
///   3. 首张物理网卡 MAC          —— 换网卡会变
///
/// ⚠️ 任一来源变化都会导致指纹变化，用户需要解绑后重新激活。
///    这正是 max_unbinds 存在的意义。
/// </summary>
public static class DeviceFingerprint
{
    private const string Salt = "zhuoyan-license-v1:";

    public static string Compute()
    {
        var parts = new List<string>();

        Add(parts, "guid", ReadMachineGuid());
        Add(parts, "vol", ReadSystemVolumeSerial());
        Add(parts, "mac", ReadPrimaryMac());

        // 兜底：所有来源都拿不到时，至少保证能生成一个稳定值
        if (parts.Count == 0)
        {
            parts.Add("name:" + Environment.MachineName);
        }

        var raw = Salt + string.Join("|", parts);
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// <summary>给用户看的指纹短形式</summary>
    public static string Short(string fp) =>
        fp.Length <= 16 ? fp : $"{fp[..8]}…{fp[^8..]}";

    /// <summary>采集明细，用于排查「为什么指纹变了」</summary>
    public static string Describe()
    {
        var sb = new StringBuilder();
        sb.AppendLine($"MachineGuid : {ReadMachineGuid() ?? "<读取失败>"}");
        sb.AppendLine($"系统盘序列号: {ReadSystemVolumeSerial() ?? "<读取失败>"}");
        sb.AppendLine($"主网卡 MAC  : {ReadPrimaryMac() ?? "<读取失败>"}");
        return sb.ToString().TrimEnd();
    }

    private static void Add(List<string> parts, string tag, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            parts.Add($"{tag}:{value}");
        }
    }

    // ---------- 来源 1：MachineGuid ----------

    private static string? ReadMachineGuid()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography");
            return key?.GetValue("MachineGuid") as string;
        }
        catch
        {
            return null;
        }
    }

    // ---------- 来源 2：系统盘卷序列号 ----------

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumeInformation(
        string lpRootPathName,
        StringBuilder? lpVolumeNameBuffer,
        int nVolumeNameSize,
        out uint lpVolumeSerialNumber,
        out uint lpMaximumComponentLength,
        out uint lpFileSystemFlags,
        StringBuilder? lpFileSystemNameBuffer,
        int nFileSystemNameSize);

    private static string? ReadSystemVolumeSerial()
    {
        try
        {
            var root = Path.GetPathRoot(Environment.SystemDirectory);
            if (string.IsNullOrEmpty(root)) return null;

            if (GetVolumeInformation(root, null, 0, out uint serial, out _, out _, null, 0))
            {
                return serial.ToString("X8");
            }
            return null;
        }
        catch
        {
            return null;
        }
    }

    // ---------- 来源 3：物理网卡 MAC ----------

    private static string? ReadPrimaryMac()
    {
        try
        {
            var macs = new List<string>();
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.NetworkInterfaceType is not (NetworkInterfaceType.Ethernet
                    or NetworkInterfaceType.Wireless80211))
                {
                    continue;
                }

                var bytes = ni.GetPhysicalAddress().GetAddressBytes();
                if (bytes.Length == 6)
                {
                    macs.Add(Convert.ToHexString(bytes));
                }
            }

            if (macs.Count == 0) return null;

            // 排序后取第一个：避免网卡枚举顺序变化导致指纹漂移
            macs.Sort(StringComparer.Ordinal);
            return macs[0];
        }
        catch
        {
            return null;
        }
    }
}
