#!/usr/bin/env node
/**
 * 本地开发环境初始化
 *
 * 做三件事：
 *   1. 密钥对不存在就生成（复用 gen-keys）
 *   2. 生成一个随机 ADMIN_TOKEN
 *   3. 写出 .env（该文件已被 .gitignore 忽略）
 *
 * 用法：node scripts/dev-setup.mjs
 * 之后：node --env-file=.env dist/index.js
 */

import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const keysDir = join(root, "keys");
const envPath = join(root, ".env");

// 1. 密钥对
if (!existsSync(join(keysDir, "private.pem"))) {
  console.log("未找到密钥对，正在生成…\n");
  execFileSync(process.execPath, [join(here, "gen-keys.mjs")], { stdio: "inherit" });
}

const privateOneLine = readFileSync(join(keysDir, "private.oneline.txt"), "utf8").trim();

// 2. ADMIN_TOKEN —— 已存在则复用，避免每次重启后令牌变化
let adminToken = "";
if (existsSync(envPath)) {
  const existing = readFileSync(envPath, "utf8");
  const m = existing.match(/^ADMIN_TOKEN=(.+)$/m);
  if (m) adminToken = m[1].trim();
}
if (!adminToken) {
  adminToken = randomBytes(32).toString("hex");
}

// 3. 写 .env
const env = [
  "# 由 scripts/dev-setup.mjs 生成 —— 本地开发用，不要提交到 Git",
  "# 注意：本机 8080 端口被沙箱代理占用，本地开发固定用 8787",
  "PORT=8787",
  "DB_DRIVER=memory",
  "# 生产环境改成 pg 并填 DATABASE_URL",
  "DATABASE_URL=",
  `ADMIN_TOKEN=${adminToken}`,
  `TICKET_PRIVATE_KEY_PEM=${privateOneLine}`,
  "PUBLIC_BASE_URL=http://localhost:8080",
  "AUTO_MIGRATE=true",
  "RATE_LIMIT_MAX=600",
  "RATE_LIMIT_WINDOW_SEC=60",
  "",
].join("\n");

writeFileSync(envPath, env, { mode: 0o600 });

console.log("\n══════════════════════════════════════════════");
console.log("  本地环境已就绪");
console.log("══════════════════════════════════════════════");
console.log(`  .env 已写入 : ${envPath}`);
console.log(`  ADMIN_TOKEN : ${adminToken}`);
console.log("");
console.log("  启动服务：");
console.log("    node --env-file=.env dist/index.js");
console.log("");
console.log("  然后浏览器打开：");
console.log("    http://localhost:8787/admin");
console.log("══════════════════════════════════════════════");
