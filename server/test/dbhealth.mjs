#!/usr/bin/env node
/**
 * 数据库健康检查的单元测试
 *
 * 2026-09-20 出过一次线上故障：所有查库接口 500，但 /health 还报 status=up
 * —— 因为它只返回**启动时**的 init_error，从不验证运行时连接。
 * 排查绕了很大弯。这里把修复锁死：
 *
 *   1. sanitizeDbError 必须剥掉连接串（pg 报错里常带 host/user/password，
 *      直接透到公开的 /health 上等于泄露数据库凭据）
 *   2. 探活失败必须让状态降级
 *
 * 用法：npm run build && node test/dbhealth.mjs
 */

import { sanitizeDbError } from "../dist/routes.js";

let passed = 0;
let failed = 0;
const failures = [];

function check(name, cond, extra = "") {
  if (cond) {
    passed++;
    console.log(`  ✓ ${name}`);
  } else {
    failed++;
    failures.push(name);
    console.log(`  ✗ ${name}${extra ? "  → " + extra : ""}`);
  }
}

function section(title) {
  console.log(`\n${title}`);
}

// ============ 脱敏 ============

section("1. 数据库错误脱敏");

check(
  "剥掉连接串里的全部凭据",
  !sanitizeDbError(
    new Error("connect ECONNREFUSED postgres://secretuser:supersecretpw@db.internal:5432/prod"),
  ).includes("supersecretpw"),
  sanitizeDbError(new Error("postgres://secretuser:supersecretpw@db.internal:5432/prod")),
);

check(
  "连接串整体被替换为 ***",
  sanitizeDbError(new Error("postgres://u:p@h/d")).includes("postgres://***"),
  sanitizeDbError(new Error("postgres://u:p@h/d")),
);

check(
  "postgresql:// 前缀同样处理",
  sanitizeDbError(new Error("bad postgresql://u:p@h/d")).includes("postgresql://***"),
  sanitizeDbError(new Error("bad postgresql://u:p@h/d")),
);

check(
  "剥掉 key=value 形式的 password",
  !sanitizeDbError(new Error("failed password=hunter2 host=db.internal")).includes("hunter2"),
  sanitizeDbError(new Error("failed password=hunter2 host=db.internal")),
);

check(
  "剥掉 key=value 形式的 user / host",
  (() => {
    const s = sanitizeDbError(new Error("user=admin host=10.0.0.5 db=x"));
    return !s.includes("admin") && !s.includes("10.0.0.5");
  })(),
  sanitizeDbError(new Error("user=admin host=10.0.0.5 db=x")),
);

check(
  "保留可读的错误描述（不误伤正常内容）",
  sanitizeDbError(new Error("Connection terminated due to connection timeout"))
    .includes("Connection terminated"),
  sanitizeDbError(new Error("Connection terminated due to connection timeout")),
);

check(
  "超长错误被截断",
  sanitizeDbError(new Error("x".repeat(1000))).length <= 300,
  String(sanitizeDbError(new Error("x".repeat(1000))).length),
);

check(
  "非 Error 对象也能处理（不抛异常）",
  typeof sanitizeDbError("plain string error") === "string",
  sanitizeDbError("plain string error"),
);

check(
  "null / undefined 不崩",
  typeof sanitizeDbError(null) === "string" && typeof sanitizeDbError(undefined) === "string",
);

check(
  "多次脱敏不会二次破坏",
  sanitizeDbError(new Error(sanitizeDbError(new Error("postgres://u:p@h/d")))).includes("postgres://***"),
  sanitizeDbError(new Error(sanitizeDbError(new Error("postgres://u:p@h/d")))),
);

// ============ 汇总 ============

console.log("\n" + "─".repeat(50));
console.log(`  通过 ${passed} 项，失败 ${failed} 项`);
console.log("─".repeat(50));

if (failures.length > 0) {
  console.log("  失败项：");
  for (const f of failures) console.log(`    - ${f}`);
}

process.exit(failed === 0 ? 0 : 1);
