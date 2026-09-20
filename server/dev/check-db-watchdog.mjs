/**
 * 数据库看门狗验证脚本（一次性排查用，不属于回归测试）
 *
 * 用 1 秒间隔启动看门狗，观察它会不会误判、会不会把连接池搞坏。
 * 内存驱动下探活永远成功，所以"重建连接池"次数应恒为 0。
 */
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";

// 私钥从本地 keys/ 读，不写死在脚本里
const privateKeyPem = readFileSync(join(process.cwd(), "keys", "private.oneline.txt"), "utf8").trim();

const child = spawn(process.execPath, ["dist/index.js"], {
  cwd: process.cwd(),
  env: {
    ...process.env,
    DB_DRIVER: "memory",
    PORT: "18091",
    ADMIN_TOKEN: "wd_test_token_0123456789abcdefghijkl",
    TICKET_PRIVATE_KEY_PEM: privateKeyPem,
    DB_WATCHDOG_SEC: "1",
  },
  stdio: ["ignore", "pipe", "pipe"],
});

let out = "";
child.stdout.on("data", (d) => { out += String(d); });
child.stderr.on("data", (d) => { out += String(d); });

await new Promise((r) => setTimeout(r, 2500));

// 先看一眼服务到底起没起来
const probe = await fetch("http://127.0.0.1:18091/health")
  .then(async (x) => ({ status: x.status, body: await x.text() }))
  .catch((e) => ({ status: 0, body: String(e) }));
if (probe.status !== 200) {
  console.log(`  服务未就绪（HTTP ${probe.status}）：${probe.body.slice(0, 200)}`);
  console.log("  ── 服务输出 ──");
  console.log(out.split("\n").slice(-25).join("\n"));
  child.kill("SIGTERM");
  process.exit(1);
}

let ok = 0;
let bad = 0;
for (let i = 0; i < 5; i++) {
  const r = await fetch("http://127.0.0.1:18091/health")
    .then((x) => x.json())
    .catch(() => null);
  if (r?.data?.db_reachable === true) ok++;
  else bad++;
  await new Promise((r2) => setTimeout(r2, 800));
}

child.kill("SIGTERM");
await new Promise((r) => setTimeout(r, 600));

const reconnects = (out.match(/重建连接池/g) || []).length;
const falseAlarms = (out.match(/探活失败/g) || []).length;

console.log(`  探活成功 ${ok} 次，失败 ${bad} 次`);
console.log(`  误报（探活失败日志）: ${falseAlarms} 次`);
console.log(`  重建连接池: ${reconnects} 次   ← 内存驱动下应恒为 0`);
console.log(
  ok === 5 && bad === 0 && reconnects === 0 && falseAlarms === 0
    ? "  ✓ 看门狗正常，无误判"
    : "  ✗ 有问题",
);

process.exit(ok === 5 && reconnects === 0 ? 0 : 1);
