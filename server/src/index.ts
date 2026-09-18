/**
 * 卡密授权验证服务 · 入口
 *
 * 启动流程：校验配置 → 加载密钥 → 连接数据库 → 建表 → 挂载路由 → 监听
 * 任何一步失败都直接退出，不允许带着坏配置跑起来。
 */

import express, { type NextFunction, type Request, type Response } from "express";
import { timingSafeEqual } from "node:crypto";
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

  // 建表/连库失败不直接退出：让进程活着，/health 会报出真实原因。
  // 否则容器一崩，平台只会给一句 "App check failed"，根因完全看不到。
  let initError: string | null = null;
  if (config.autoMigrate) {
    try {
      await repo.init();
      console.log("[db] 建表完成");
    } catch (e) {
      initError = e instanceof Error ? e.message : String(e);
      console.error("[db] 建表失败:", initError);
    }
  }

  const service = new LicenseService(repo, privateKey, publicKey, config.ticketMaxTtlDays);

  // 首次启动时种下 root 账户（已有账户则跳过，不会覆盖密码）
  if (config.adminUsername !== "" && config.adminPassword !== "") {
    try {
      const created = await service.ensureRootUser(config.adminUsername, config.adminPassword);
      if (created) {
        console.log(`[auth] 已创建 root 账户「${config.adminUsername}」`);
      }
    } catch (e) {
      console.error("[auth] 创建 root 账户失败:", e instanceof Error ? e.message : e);
    }
  } else if (config.dbDriver === "pg") {
    console.warn("[auth] 未设置 ADMIN_USERNAME / ADMIN_PASSWORD，跳过 root 账户初始化");
  }

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

  // HTTP Basic Auth 登录门（可选）。设在 /admin 之前，
  // 这样页面本身和管理接口 /admin/v1/* 都受保护 —— 未登录连界面都看不到。
  if (config.adminBasicAuth !== "") {
    const expected = Buffer.from(config.adminBasicAuth, "utf8");
    app.use("/admin", (req: Request, res: Response, next: NextFunction) => {
      const header = req.headers.authorization ?? "";
      if (header.startsWith("Basic ")) {
        const given = Buffer.from(header.slice(6), "base64").toString("utf8");
        const givenBuf = Buffer.from(given, "utf8");
        if (givenBuf.length === expected.length && timingSafeEqual(givenBuf, expected)) {
          next();
          return;
        }
      }
      res.setHeader("WWW-Authenticate", 'Basic realm="License Admin", charset="UTF-8"');
      res.status(401).send("需要登录");
    });
  }

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
    health: () => ({
      db_driver: config.dbDriver,
      database_url_set: config.databaseUrl !== "",
      auto_migrate: config.autoMigrate,
      init_error: initError,
    }),
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
