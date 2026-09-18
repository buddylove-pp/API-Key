/**
 * 定期校验排期计算
 *
 * 两条核心规则（来自产品要求，别改）：
 *
 *   提前校验 → 基准不变：next = 原计划时间 + 周期
 *     例：周期 10 天，计划第 10 天；用户第 8 天校验 → 下次仍是第 20 天，不是第 18 天
 *
 *   超期校验 → 基准重置：next = 实际校验时间 + 周期
 *     例：计划第 10 天；用户第 15 天才校验 → 下次 = 第 25 天
 *
 * 时间锚点用「首次激活时间」，与用户是否使用软件、是否处于未校验期无关，
 * 所以授权期永远按真实流逝时间计算。
 */

export const SECONDS_PER_DAY = 86_400;

export type CheckMode = "frequency" | "interval";

export interface CheckPlan {
  /** 有效周期（天）。0 = 不做定期校验 */
  intervalDays: number;
  /** 计划下次校验时间；null = 不校验 */
  nextCheckAt: number | null;
  /** 提醒开始时间；null = 不提醒 */
  remindAt: number | null;
}

/**
 * 解析有效校验周期（天）。返回 0 表示不做定期校验。
 *
 * frequency 模式：把 activation_days 等分成 N 段 → 周期 = activation_days / N
 *   N <= 1 视为不校验（因为激活那一刻已经算第一次）
 * interval  模式：直接用指定天数，与总时长无关
 */
export function resolveIntervalDays(
  mode: CheckMode,
  activationDays: number,
  frequency: number,
  intervalDays: number,
): number {
  if (mode === "interval") {
    const d = Math.floor(intervalDays);
    return Number.isFinite(d) && d > 0 ? d : 0;
  }

  const n = Math.floor(frequency);
  if (!Number.isFinite(n) || n <= 1) return 0;

  const d = Math.floor(activationDays / n);
  return d >= 1 ? d : 0;
}

/** 提醒开始时间 = 计划校验时间 − 周期 × 提醒比例 */
export function computeRemindAt(
  nextCheckAt: number,
  intervalDays: number,
  remindPercent: number,
): number | null {
  if (intervalDays <= 0 || remindPercent <= 0) return null;
  const ratio = Math.min(90, Math.max(0, remindPercent)) / 100;
  return Math.round(nextCheckAt - intervalDays * SECONDS_PER_DAY * ratio);
}

/** 激活时确定首个校验计划 */
export function initialPlan(
  activatedAt: number,
  intervalDays: number,
  remindPercent: number,
): CheckPlan {
  if (intervalDays <= 0) {
    return { intervalDays: 0, nextCheckAt: null, remindAt: null };
  }
  const nextCheckAt = activatedAt + intervalDays * SECONDS_PER_DAY;
  return {
    intervalDays,
    nextCheckAt,
    remindAt: computeRemindAt(nextCheckAt, intervalDays, remindPercent),
  };
}

/**
 * 推进到下一次校验计划。
 * 提前或准时 → 以原计划时间为基准；超期 → 以实际校验时间为基准。
 */
export function advanceNextCheck(
  plannedAt: number,
  actualCheckAt: number,
  intervalDays: number,
): number {
  const base = actualCheckAt <= plannedAt ? plannedAt : actualCheckAt;
  return base + intervalDays * SECONDS_PER_DAY;
}

/** 依据当前时间判定校验状态 */
export function deriveState(
  now: number,
  nextCheckAt: number | null,
  remindAt: number | null,
  entitlementExpiresAt: number | null,
): "active" | "due" | "overdue" {
  if (nextCheckAt !== null && now >= nextCheckAt) return "overdue";
  if (remindAt !== null && now >= remindAt) return "due";
  // 授权本身到期也算超期停用
  if (entitlementExpiresAt !== null && now >= entitlementExpiresAt) return "overdue";
  return "active";
}
