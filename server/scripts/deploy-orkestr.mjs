#!/usr/bin/env node
/**
 * orkestr 部署脚本
 *
 * 做三件事：
 *   1. 把本地 .env 里的密钥写进 orkestr 环境变量（加密存储）
 *   2. 触发一次部署
 *   3. 轮询部署状态直到成功或失败
 *
 * 用法：
 *   ORKESTR_API_KEY=ork_xxx ORKESTR_PROJECT_ID=<uuid> node scripts/deploy-orkestr.mjs
 *
 * 可选环境变量：
 *   ORKESTR_API_BASE  默认 https://api.orkestr.eu/api
 *   ORKESTR_ENV_ID    默认自动取第一个 environment
 *   SKIP_ENV=1        只部署，不改环境变量
 */

import { readFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");

const API_KEY = process.env.ORKESTR_API_KEY;
const PROJECT_ID = process.env.ORKESTR_PROJECT_ID;
const BASE = (process.env.ORKESTR_API_BASE ?? "https://api.orkestr.eu/api").replace(/\/$/, "");

if (!API_KEY || !PROJECT_ID) {
  console.error("缺少 ORKESTR_API_KEY 或 ORKESTR_PROJECT_ID");
  process.exit(1);
}

// ---------- 工具 ----------

async function api(path, options = {}) {
  const res = await fetch(BASE + path, {
    method: options.method ?? "GET",
    headers: {
      Authorization: "Bearer " + API_KEY,
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    /* 非 JSON */
  }
  return { status: res.status, json, text };
}

function loadEnvFile() {
  const p = join(root, ".env");
  if (!existsSync(p)) {
    console.error("找不到 .env，请先运行 node scripts/dev-setup.mjs");
    process.exit(1);
  }
  const out = {};
  for (const line of readFileSync(p, "utf8").split("\n")) {
    if (!line.includes("=") || line.startsWith("#")) continue;
    const i = line.indexOf("=");
    out[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  }
  return out;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------- 主流程 ----------

const local = loadEnvFile();

if (!local.ADMIN_TOKEN || !local.TICKET_PRIVATE_KEY_PEM) {
  console.error(".env 里缺少 ADMIN_TOKEN 或 TICKET_PRIVATE_KEY_PEM");
  process.exit(1);
}

// 1. 找环境 ID
let envId = process.env.ORKESTR_ENV_ID;
if (!envId) {
  const r = await api(`/projects/${PROJECT_ID}/environments`);
  const envs = Array.isArray(r.json) ? r.json : (r.json?.environments ?? []);
  const prod = envs.find((e) => e.is_production) ?? envs[0];
  if (!prod) {
    console.error("找不到任何环境:", r.text.slice(0, 300));
    process.exit(1);
  }
  envId = prod.id;
  console.log(`环境: ${prod.name} (${envId})`);
}

// 2. 写环境变量
if (process.env.SKIP_ENV !== "1") {
  // 只设置不依赖平台的变量；PORT 与 DATABASE_URL 由 orkestr 注入
  const vars = {
    DB_DRIVER: "pg",
    ADMIN_TOKEN: local.ADMIN_TOKEN,
    TICKET_PRIVATE_KEY_PEM: local.TICKET_PRIVATE_KEY_PEM,
    AUTO_MIGRATE: "true",
    RATE_LIMIT_MAX: local.RATE_LIMIT_MAX || "60",
    RATE_LIMIT_WINDOW_SEC: local.RATE_LIMIT_WINDOW_SEC || "60",
  };

  console.log("写入环境变量:", Object.keys(vars).join(", "));

  const r = await api(`/projects/${PROJECT_ID}/environments/${envId}`, {
    method: "PATCH",
    body: { env_vars: vars },
  });

  if (r.status >= 400) {
    console.error(`✗ 写入失败 HTTP ${r.status}:`, r.text.slice(0, 400));
    process.exit(1);
  }
  console.log("✓ 环境变量已写入（平台侧加密存储）");
}

// 3. 触发部署
console.log("\n触发部署…");
const dep = await api(`/projects/${PROJECT_ID}/environments/${envId}/deploy`, {
  method: "POST",
  body: {},
});

if (dep.status >= 400) {
  console.error(`✗ 部署触发失败 HTTP ${dep.status}:`, dep.text.slice(0, 400));
  process.exit(1);
}

const deployId = dep.json?.id ?? dep.json?.deployment_id;
console.log(`部署已排队: ${deployId ?? "(未返回 id)"}`);

// 4. 轮询状态
if (!deployId) process.exit(0);

let last = "";
for (let i = 0; i < 120; i++) {
  await sleep(5000);

  const r = await api(`/projects/${PROJECT_ID}/deployments`);
  const list = r.json?.deployments ?? [];
  const d = list.find((x) => x.id === deployId) ?? list[0];
  if (!d) continue;

  if (d.status !== last) {
    console.log(`  [${i * 5}s] ${d.status}`);
    last = d.status;
  }

  if (d.status === "running" || d.status === "success" || d.status === "live") {
    console.log("\n══════════════════════════════════════");
    console.log("  ✓ 部署成功");
    console.log("══════════════════════════════════════");
    process.exit(0);
  }

  if (d.status === "failed" || d.status === "error") {
    console.error("\n══════════════════════════════════════");
    console.error("  ✗ 部署失败");
    console.error("══════════════════════════════════════");
    console.error(d.error_message ?? "(无错误信息)");
    process.exit(1);
  }
}

console.error("\n轮询超时，请到 orkestr 控制台查看部署状态");
process.exit(1);
