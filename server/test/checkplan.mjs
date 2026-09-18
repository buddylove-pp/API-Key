#!/usr/bin/env node
/**
 * 校验排期计算的单元测试
 *
 * 这几条规则是产品明确要求的，算错会导致用户要么被误停用、要么绕过校验，
 * 所以单独锁死。跑之前需要先 npm run build（测的是编译产物）。
 *
 * 用法：npm run build && node test/checkplan.mjs
 */

import {
  SECONDS_PER_DAY,
  advanceNextCheck,
  computeRemindAt,
  deriveState,
  initialPlan,
  resolveIntervalDays,
} from "../dist/checkplan.js";

let passed = 0;
let failed = 0;
const failures = [];

function eq(name, actual, expected) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (ok) {
    passed++;
    console.log(`  ✓ ${name}`);
  } else {
    failed++;
    failures.push(name);
    console.log(`  ✗ ${name}\n      期望 ${JSON.stringify(expected)}\n      实际 ${JSON.stringify(actual)}`);
  }
}

function section(t) {
  console.log(`\n${t}`);
}

const D = SECONDS_PER_DAY;
const day = (n) => n * D;

// ============ 1. 有效周期解析 ============

section("1. 定频率模式：把总时长等分成 N 段");
{
  eq("100 天 ÷ 10 → 每 10 天", resolveIntervalDays("frequency", 100, 10, 0), 10);
  eq("100 天 ÷ 3 → 每 33 天（向下取整）", resolveIntervalDays("frequency", 100, 3, 0), 33);
  eq("★ 频率 1 → 不做定期校验", resolveIntervalDays("frequency", 100, 1, 0), 0);
  eq("频率 0 → 不做定期校验", resolveIntervalDays("frequency", 100, 0, 0), 0);
  eq("总时长小于频率 → 不做校验（除不尽到 0）", resolveIntervalDays("frequency", 5, 10, 0), 0);
}

section("2. 定时间模式：直接指定天数，与总时长无关");
{
  eq("直接指定 10 天", resolveIntervalDays("interval", 100, 1, 10), 10);
  eq("★ 总时长 30 天也能设 10 天周期", resolveIntervalDays("interval", 30, 999, 10), 10);
  eq("指定 0 天 → 不校验", resolveIntervalDays("interval", 100, 10, 0), 0);
  eq("负数 → 不校验", resolveIntervalDays("interval", 100, 10, -5), 0);
  eq("忽略频率参数", resolveIntervalDays("interval", 100, 50, 7), 7);
}

// ============ 3. 下次校验时间推进（核心规则） ============

section("3. 下次校验时间推进 —— 提前不推、超期重置");
{
  eq("★ 提前校验：计划第10天、第8天校验 → 下次第20天（不是第18天）",
    advanceNextCheck(day(10), day(8), 10), day(20));

  eq("准时校验：第10天校验 → 下次第20天",
    advanceNextCheck(day(10), day(10), 10), day(20));

  eq("★ 超期校验：计划第10天、第15天校验 → 下次第25天（以实际为准）",
    advanceNextCheck(day(10), day(15), 10), day(25));

  eq("大幅超期：计划第10天、第100天校验 → 下次第110天",
    advanceNextCheck(day(10), day(100), 10), day(110));

  eq("提前一整个周期：计划第20天、第10天校验 → 下次第30天",
    advanceNextCheck(day(20), day(10), 10), day(30));
}

// ============ 4. 提前提醒时间 ============

section("4. 提前提醒时间");
{
  eq("★ 计划第10天、周期10天、提前20% → 第8天开始提醒",
    computeRemindAt(day(10), 10, 20), day(8));

  eq("提前 50% → 第5天", computeRemindAt(day(10), 10, 50), day(5));
  eq("比例 0 → 不提醒", computeRemindAt(day(10), 10, 0), null);
  eq("周期 0 → 不提醒", computeRemindAt(day(10), 0, 20), null);
  eq("比例超过 90 被夹到 90%", computeRemindAt(day(10), 10, 999), day(10) - Math.round(9 * D));
}

// ============ 5. 激活时的首次排期 ============

section("5. 激活时确定首次排期");
{
  const p = initialPlan(day(0), 10, 20);
  eq("首次计划在第 10 天", p.nextCheckAt, day(10));
  eq("首次提醒在第 8 天", p.remindAt, day(8));
  eq("周期记录为 10", p.intervalDays, 10);

  const none = initialPlan(day(0), 0, 20);
  eq("周期 0 → 无计划", none.nextCheckAt, null);
  eq("周期 0 → 无提醒", none.remindAt, null);
}

// ============ 6. 状态判定 ============

section("6. 状态判定");
{
  const next = day(10);
  const remind = day(8);
  const entExpires = day(100);

  eq("第5天 → active", deriveState(day(5), next, remind, entExpires), "active");
  eq("第7.9天 → active", deriveState(day(8) - 1, next, remind, entExpires), "active");
  eq("★ 第8天（进入提醒期）→ due", deriveState(day(8), next, remind, entExpires), "due");
  eq("第9天 → due", deriveState(day(9), next, remind, entExpires), "due");
  eq("★ 第10天（到校验期）→ overdue", deriveState(day(10), next, remind, entExpires), "overdue");
  eq("第30天 → overdue", deriveState(day(30), next, remind, entExpires), "overdue");

  eq("无计划 + 授权未到期 → active", deriveState(day(50), null, null, entExpires), "active");
  eq("★ 无计划但授权到期 → overdue", deriveState(day(100), null, null, entExpires), "overdue");

  eq("提醒关闭（remind=null）第9天 → active", deriveState(day(9), next, null, entExpires), "active");
}

// ============ 汇总 ============

console.log("\n" + "─".repeat(50));
console.log(`  通过 ${passed} 项，失败 ${failed} 项`);
if (failed > 0) {
  console.log("  失败项：");
  for (const f of failures) console.log(`    - ${f}`);
}
console.log("─".repeat(50));

process.exit(failed === 0 ? 0 : 1);
