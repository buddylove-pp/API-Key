using System;

namespace LicenseTester.License;

/// <summary>
/// 时间回拨检测
///
/// 用户改一下系统时间，就能绕过所有基于本地时间的判断
/// （票据过期、校验到期、授权到期）。所以**绝不能信任**
/// DateTime.Now / DateTime.UtcNow。
///
/// 做法：以「上次从服务端拿到的真实时间」为锚点，用**单调时钟**
/// （Environment.TickCount64，从系统启动算起的毫秒数，不受系统时间影响）
/// 推算到现在过了多久，得到"现在大概几点"。若系统时间明显早于推算值，
/// 就是被回拨了。
///
/// ⚠️ 局限：单调时钟在重启后归零。检测到倒退说明重启过，
///    此时无法推算，只能标记为「需要联网校验」由服务端裁决。
/// </summary>
public static class TimeGuard
{
    /// <summary>
    /// 允许的误差（秒）。系统时间自动校准、休眠唤醒、跨时区调整
    /// 都会造成小幅偏差，不能因为几秒钟就判定作弊。
    /// </summary>
    private const long ToleranceSeconds = 300;

    public sealed record Result(
        bool Ok,
        long EstimatedNow,
        string Reason,
        /// <summary>是否需要联网校验来重新对时</summary>
        bool NeedsOnlineCheck
    );

    /// <summary>用一次服务端响应校准锚点。每次激活 / 校验 / 心跳成功后都应调用</summary>
    public static void Anchor(StoredLicense lic, long serverTime)
    {
        if (serverTime <= 0) return;
        lic.LastServerTime = serverTime;
        lic.LastTicks = Environment.TickCount64;
    }

    /// <summary>检查当前系统时间是否可信</summary>
    public static Result Check(StoredLicense lic)
    {
        long systemNow = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        long ticks = Environment.TickCount64;

        // 没有锚点：首次运行，或者老版本数据。无法判断，放行但要求联网
        if (lic.LastServerTime <= 0 || lic.LastTicks <= 0)
        {
            return new Result(true, systemNow, "尚无时间锚点，本次不判定", true);
        }

        // 单调时钟倒退 = 系统重启过，无法推算真实时间
        if (ticks < lic.LastTicks)
        {
            return new Result(true, systemNow, "检测到系统重启，需要联网校验", true);
        }

        long elapsed = (ticks - lic.LastTicks) / 1000;
        long estimated = lic.LastServerTime + elapsed;

        // 系统时间早于推算值超过容差 → 判定回拨
        if (systemNow < estimated - ToleranceSeconds)
        {
            long diff = estimated - systemNow;
            return new Result(
                false,
                estimated,
                $"检测到系统时间被回拨约 {FormatDuration(diff)}，请恢复正确时间后联网校验",
                true);
        }

        return new Result(true, Math.Max(systemNow, estimated), "时间正常", false);
    }

    /// <summary>距锚点已经流逝的秒数（单调时钟口径，不受系统时间影响）</summary>
    public static long ElapsedSinceAnchor(StoredLicense lic)
    {
        if (lic.LastTicks <= 0) return 0;
        long ticks = Environment.TickCount64;
        return ticks < lic.LastTicks ? 0 : (ticks - lic.LastTicks) / 1000;
    }

    private static string FormatDuration(long seconds)
    {
        if (seconds >= 86400) return $"{seconds / 86400} 天";
        if (seconds >= 3600) return $"{seconds / 3600} 小时";
        if (seconds >= 60) return $"{seconds / 60} 分钟";
        return $"{seconds} 秒";
    }
}
