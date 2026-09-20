/**
 * 本地起服务用于验证界面改动（一次性，不属于回归测试）
 * 用内存驱动，数据不落盘。
 */
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const env = {
  ...process.env,
  DB_DRIVER: "memory",
  PORT: "18094",
  ADMIN_TOKEN: "sticky_test_token_0123456789abcdefghij",
  ADMIN_USERNAME: "stickytest",
  ADMIN_PASSWORD: "sticky-test-pass-123",
  TICKET_PRIVATE_KEY_PEM: readFileSync(
    join(process.cwd(), "keys", "private.oneline.txt"), "utf8",
  ).trim(),
};

const child = spawn(process.execPath, ["dist/index.js"], {
  cwd: process.cwd(),
  env,
  stdio: "inherit",
});

process.on("SIGTERM", () => child.kill("SIGTERM"));
process.on("SIGINT", () => child.kill("SIGINT"));
