/**
 * 卡密授权验证服务 · 入口
 *
 * 启动流程：校验配置 → 加载密钥 → 连接数据库 → 建表 → 挂载路由 → 监听
 * 任何一步失败都直接退出，不允许带着坏配置跑起来。
 */

import express, { type NextFunction, type Request, type Response } from "express";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { config, validateConfig } from "./config.js";
import { derivePublicKey, keyFingerprint, loadPrivateKey } from "./crypto.js";
import { createRepo } from "./repo.js";
import { LicenseService } from "./service.js";
import { buildRouter, MAX_BODY } from "./routes.js";

async function main(): Promise<void> {
  validateConfig();

  const privateKey = loadPrivateKey(config.ticketPrivateKeyPem);
  const publicKey = derivePublicKey(privateKey);

  const repo = createRepo(config.dbDriver, config.databaseUrl);
  if (config.autoMigrate) {
    await repo.init();
  }

  const service = new LicenseService(repo, privateKey, publicKey);

  const app = express();
  app.disable("x-powered-by");
  // orkestr 在容器前面有反向代理，需要信任 X-Forwarded-For 才能拿到真实 IP
  app.set("trust proxy", true);

  app.use(express.json({ limit: MAX_BODY }));
  // 请求体不是合法 JSON 时给出 400，而不是掉进 500
  app.use((err: unknown, _req: Request, res: Response, next: NextFunction) => {
    if (err instanceof SyntaxError) {
      res.status(400).json({ code: 4001, msg: "请求体不是合法 JSON", data: null });
      return;
    }
    next(err);
  });

  // 管理后台页面：静态 HTML，由本服务直接托管
  const here = dirname(fileURLToPath(import.meta.url));
  const publicDir = join(here, "..", "public");
  app.get("/admin", (_req: Request, res: Response) => {
    res.sendFile(join(publicDir, "admin.html"));
  });
  app.get("/", (_req: Request, res: Response) => {
    res.redirect("/admin");
  });

  app.use(buildRouter({
    service,
    publicKey,
    adminToken: config.adminToken,
    rateLimitMax: config.rateLimitMax,
    rateLimitWindowSec: config.rateLimitWindowSec,
  }));

  const server = app.listen(config.port, () => {
    console.log("──────────────────────────────────────────────");
    console.log("  卡密授权服务已启动");
    console.log(`  监听端口   : ${config.port}`);
    console.log(`  数据库驱动 : ${config.dbDriver}`);
    console.log(`  公钥指纹   : ${keyFingerprint(publicKey)}`);
    console.log(`  自动建表   : ${config.autoMigrate ? "开" : "关"}`);
    console.log(`  限流       : ${config.rateLimitMax} 次 / ${config.rateLimitWindowSec} 秒 / IP`);
    console.log(`  管理后台   : http://<你的域名>/admin`);
    console.log("──────────────────────────────────────────────");
  });

  let shuttingDown = false;
  const shutdown = async (signal: string): Promise<void> => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`\n收到 ${signal}，正在优雅关闭…`);

    server.close();
    try {
      await repo.close();
    } catch (e) {
      console.error("关闭数据库连接失败:", e);
    }
    process.exit(0);
  };

  process.on("SIGTERM", () => void shutdown("SIGTERM"));
  process.on("SIGINT", () => void shutdown("SIGINT"));
}

main().catch((err: unknown) => {
  console.error("启动失败:", err instanceof Error ? err.message : err);
  process.exit(1);
});
