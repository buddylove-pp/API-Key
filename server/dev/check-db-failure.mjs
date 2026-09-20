/**
 * 看门狗「失败检测」验证（一次性排查用）
 *
 * 用一个连不上的数据库启动，确认：
 *   1. /health 如实报告 db_reachable=false 并给出 db_error
 *   2. 看门狗检测到连续失败并尝试重建连接池
 *   3. 错误信息已脱敏（不含密码 / 主机名）
 */
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const privateKeyPem = readFileSync(join(process.cwd(), "keys", "private.oneline.txt"), "utf8").trim();

const child = spawn(process.execPath, ["dist/index.js"], {
  cwd: process.cwd(),
  env: {
    ...process.env,
    DB_DRIVER: "pg",
    // 故意指向一个连不上的地址，并塞入明显的敏感串用于验证脱敏
    DATABASE_URL: "postgres://secretuser:supersecretpw@10.255.255.1:5432/nodb?sslmode=disable",
    PORT: "18092",
    ADMIN_TOKEN: "wd_test_token_0123456789abcdefghijkl",
    TICKET_PRIVATE_KEY_PEM: privateKeyPem,
    DB_WATCHDOG_SEC: "2",
    // 建表总超时压到 5 秒，否则要等几十条语句各超时一次
    DB_INIT_TIMEOUT_SEC: "5",
  },
  stdio: ["ignore", "pipe", "pipe"],
});

let out = "";
child.stdout.on("data", (d) => { out += String(d); });
child.stderr.on("data", (d) => { out += String(d); });

// ── 关键测量：数据库不可达时，服务多久能被访问到 ──
// 修复前：逐条执行 schema 每条各等一次连接超时，几分钟都起不来。
// 修复后：受 DB_INIT_TIMEOUT_SEC 约束，超时就降级启动。
const spawnAt = Date.now();
let readyMs = -1;
for (let i = 0; i < 80; i++) {
  await new Promise((r) => setTimeout(r, 500));
  const ok = await fetch("http://127.0.0.1:18092/health")
    .then((x) => x.ok)
    .catch(() => false);
  if (ok) {
    readyMs = Date.now() - spawnAt;
    break;
  }
}
console.log(`  数据库不可达时，服务在 ${readyMs} ms 后即可访问（上限 ${5_000}ms + 余量）`);
console.log();

// 等够两轮看门狗周期。
// 注意：数据库不可达时每次 ping 自己要等 10 秒连接超时，
// 所以「连续两次失败」实际需要 ~20 秒，不是 2×2 秒。
await new Promise((r) => setTimeout(r, 26_000));

const probe = await fetch("http://127.0.0.1:18092/health")
  .then(async (x) => ({ status: x.status, json: await x.json() }))
  .catch((e) => ({ status: 0, json: null, err: String(e) }));

child.kill("SIGTERM");
await new Promise((r) => setTimeout(r, 500));

if (probe.status !== 200 || !probe.json) {
  console.log(`  ✗ 服务未响应（HTTP ${probe.status}）`);
  console.log(out.split("\n").slice(-20).join("\n"));
  process.exit(1);
}

const d = probe.json.data ?? {};
const dbError = String(d.db_error ?? "");

console.log(`  status         : ${d.status}`);
console.log(`  db_reachable   : ${d.db_reachable}`);
console.log(`  db_error       : ${dbError.slice(0, 120)}`);

const detectedFail = (out.match(/探活失败/g) || []).length;
const triedReconnect = (out.match(/重建连接池/g) || []).length;

console.log(`  看门狗检测到失败: ${detectedFail} 次`);
console.log(`  尝试重建连接池  : ${triedReconnect} 次`);
console.log();

const checks = [
  ["状态降级为 degraded", d.status === "degraded"],
  ["db_reachable 为 false", d.db_reachable === false],
  ["给出了 db_error", dbError.length > 0],
  ["★ 错误已脱敏（不含密码）", !dbError.includes("supersecretpw")],
  ["★ 错误已脱敏（不含用户名）", !dbError.includes("secretuser")],
  ["★ 错误已脱敏（不含主机名）", !dbError.includes("10.255.255.1")],
  ["看门狗检测到失败", detectedFail > 0],
  ["看门狗尝试重建连接池", triedReconnect > 0],
];

let bad = 0;
for (const [name, pass] of checks) {
  console.log(`  ${pass ? "✓" : "✗"} ${name}`);
  if (!pass) bad++;
}

process.exit(bad === 0 ? 0 : 1);
