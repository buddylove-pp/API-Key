#!/usr/bin/env node
/**
 * 冒烟测试：对「已在运行」的服务做一次完整链路验证
 *
 * 与 test/e2e.mjs 的区别：e2e 会自己拉起服务、用内存库、跑 59 项断言；
 * 本脚本面向真实运行中的实例（含 PostgreSQL），只做关键路径确认。
 *
 * 用法：
 *   node --env-file=.env scripts/smoke.mjs
 *   node --env-file=.env scripts/smoke.mjs https://your-app.orkestr.run
 */

import { readFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");

const BASE = (process.argv[2] ?? "http://127.0.0.1:8787").replace(/\/$/, "");

function loadEnv() {
  const p = join(root, ".env");
  if (!existsSync(p)) return {};
  const out = {};
  for (const line of readFileSync(p, "utf8").split("\n")) {
    if (!line.includes("=") || line.startsWith("#")) continue;
    const i = line.indexOf("=");
    out[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  }
  return out;
}

const env = { ...loadEnv(), ...process.env };
const token = env.ADMIN_TOKEN;

if (!token) {
  console.error("缺少 ADMIN_TOKEN（请用 node --env-file=.env 运行）");
  process.exit(1);
}

let pass = 0;
let fail = 0;

function check(name, cond, extra = "") {
  if (cond) {
    pass++;
    console.log(`  ✓ ${name}`);
  } else {
    fail++;
    console.log(`  ✗ ${name}${extra ? "  → " + extra : ""}`);
  }
}

async function getJson(path, headers) {
  const res = await fetch(BASE + path, { headers: headers ?? {} });
  const text = await res.text();
  try {
    return { status: res.status, json: JSON.parse(text) };
  } catch {
    return { status: res.status, json: null, text };
  }
}

async function postJson(path, body, headers) {
  const res = await fetch(BASE + path, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...(headers ?? {}) },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  try {
    return { status: res.status, json: JSON.parse(text) };
  } catch {
    return { status: res.status, json: null, text };
  }
}

console.log(`目标服务: ${BASE}\n`);

// ---- 1. 基础 ----
console.log("1. 基础可用性");
{
  const h = await getJson("/health");
  check("健康检查通过", h.json?.code === 0, `HTTP ${h.status}`);

  const res = await fetch(BASE + "/admin");
  const html = await res.text();
  check("管理后台页面可访问", res.status === 200 && html.includes("卡密管理后台"), `HTTP ${res.status}`);
}

// ---- 2. 管理鉴权 ----
console.log("\n2. 管理接口鉴权");
{
  const r = await postJson("/admin/v1/licenses/generate", { count: 1 });
  check("无令牌被拒", r.status === 401, `HTTP ${r.status}`);
}

// ---- 3. 生成卡密 ----
console.log("\n3. 生成卡密");
const auth = { Authorization: "Bearer " + token };
let key = null;
{
  const g = await postJson(
    "/admin/v1/licenses/generate",
    {
      product: "license-tester",
      count: 3,
      max_devices: 1,
      max_activations: 1,
      activation_days: 365,
      max_unbinds: 3,
      refund_on_unbind: true,
      note: "smoke-test",
    },
    auth,
  );

  check("生成 3 张卡密", g.json?.code === 0 && g.json?.data?.count === 3, JSON.stringify(g.json));

  const keys = g.json?.data?.keys ?? [];
  for (const k of keys) console.log(`      ${k}`);
  key = keys[0];
}

// ---- 4. 激活 ----
console.log("\n4. 激活与票据");
const fp = "f".repeat(40);
let ticket = null;
{
  const a = await postJson("/api/v1/activate", {
    license_key: key,
    device_fp: fp,
    device_name: "SMOKE-TEST",
    product: "license-tester",
  });

  check("激活成功", a.json?.code === 0, JSON.stringify(a.json));
  ticket = a.json?.data?.ticket;

  if (ticket) {
    const [body, sig] = ticket.split(".");
    check("票据为 body.signature 两段式", Boolean(body && sig));
    check("签名长度为 P1363 定长 64 字节", Buffer.from(sig, "base64url").length === 64,
      `${Buffer.from(sig, "base64url").length} 字节`);

    const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    check("票据绑定了本设备指纹", payload.fp === fp);
    const days = Math.round((payload.exp - payload.iat) / 86400);
    check("票据有效期 365 天", days === 365, `${days} 天`);
  }
}

// ---- 5. 软件维度 ----
console.log("\n5. 软件维度隔离");
{
  const wrong = await postJson("/api/v1/activate", {
    license_key: key,
    device_fp: fp,
    product: "another-app",
  });
  check("跨软件激活被拒（1006）", wrong.json?.code === 1006, JSON.stringify(wrong.json));
}

// ---- 6. 心跳 ----
console.log("\n6. 心跳续期");
{
  const hb = await postJson("/api/v1/heartbeat", { ticket, device_fp: fp });
  check("心跳成功", hb.json?.code === 0, JSON.stringify(hb.json));
}

// ---- 7. 管理查询 ----
console.log("\n7. 管理查询");
{
  const prefix = key.replace(/-/g, "").slice(0, 8);
  const d = await getJson(`/admin/v1/licenses/${prefix}`, auth);
  check("按前缀查到卡密", d.json?.code === 0, JSON.stringify(d.json));
  check("返回绑定记录", Array.isArray(d.json?.data?.bindings) && d.json.data.bindings.length === 1);
  check("返回审计日志", Array.isArray(d.json?.data?.audit) && d.json.data.audit.length > 0);

  const l = await getJson("/admin/v1/licenses?page=1&page_size=10", auth);
  check("列表可查", l.json?.code === 0 && typeof l.json?.data?.total === "number");
}

console.log("\n" + "─".repeat(50));
console.log(`  通过 ${pass} 项，失败 ${fail} 项`);
console.log("─".repeat(50));

process.exit(fail === 0 ? 0 : 1);
