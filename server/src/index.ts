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

/**
 * 给 Promise 加超时。超时返回 null，**原 Promise 继续在后台跑**。
 *
 * 用在这里是为了让「建表」不会无限拖住启动 ——
 * 数据库不可达时逐条执行 schema 每条各等一次连接超时，几分钟就过去了。
 */
function withTimeout<T>(p: Promise<T>, ms: number): Promise<T | null> {
  let timer: NodeJS.Timeout | undefined;

  const timeout = new Promise<null>((resolve) => {
    timer = setTimeout(() => resolve(null), ms);
    // 不要因为这个定时器把进程钉住不退出
    timer.unref?.();
  });

  return Promise.race([p, timeout]).finally(() => {
    if (timer) clearTimeout(timer);
  });
}

async function main(): Promise<void> {
  validateConfig();

  const privateKey = loadPrivateKey(config.ticketPrivateKeyPem);
  const publicKey = derivePublicKey(privateKey);

  const repo = createRepo(config.dbDriver, config.databaseUrl);

  // 建表/连库失败不直接退出：让进程活着，/health 会报出真实原因。
  // 否则容器一崩，平台只会给一句 "App check failed"，根因完全看不到。
  let initError: string | null = null;
  /** 建表是否真的成功了。看门狗靠它判断要不要补建 */
  let schemaReady = false;

  if (config.autoMigrate) {
    const startedAt = Date.now();

    // ⚠️ 必须有总超时：数据库不可达时逐条执行 schema 会每条各等一次
    //    连接超时，几十条语句就是好几分钟 —— 容器会启动超时、部署直接失败。
    const ok = await withTimeout(
      (async (): Promise<boolean> => {
        try {
          await repo.init();
          // 即使外层已经超时返回，这里也要置位 ——
          // 建表在后台跑完了就该认，否则看门狗会白补一次
          schemaReady = true;
          initError = null;
          return true;
        } catch (e) {
          initError = e instanceof Error ? e.message : String(e);
          return false;
        }
      })(),
      config.dbInitTimeoutSec * 1000,
    );

    if (ok === true) {
      console.log(`[db] 建表完成（${Date.now() - startedAt} ms）`);
    } else if (ok === false) {
      console.error("[db] 建表失败:", initError);
      console.error("[db] 已降级启动，看门狗会在数据库恢复后自动补建表");
    } else {
      initError = `建表超时（超过 ${config.dbInitTimeoutSec} 秒），已降级启动`;
      console.error("[db]", initError);
      console.error("[db] 看门狗会在数据库恢复后自动补建表，无需重启容器");
    }
  }

  const service = new LicenseService(repo, privateKey, publicKey, config.ticketMaxTtlDays);

  // 首次启动时种下 root 账户（已有账户则跳过，不会覆盖密码）
  if (config.adminUsername !== "" && config.adminPassword !== "") {
    try {
      // 同样要加超时：数据库不可达时这里也会等满连接超时，
      // 把启动又拖长 10 秒 —— 光给建表加超时是不够的。
      const created = await withTimeout(
        service.ensureRootUser(config.adminUsername, config.adminPassword),
        config.dbInitTimeoutSec * 1000,
      );

      if (created === true) {
        console.log(`[auth] 已创建 root 账户「${config.adminUsername}」`);
      } else if (created === null) {
        console.warn("[auth] 初始化 root 账户超时，跳过（不影响启动，可稍后手动处理）");
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

  /**
   * 数据库看门狗。
   *
   * 为什么需要：连接可能被数据库、负载均衡或防火墙**静默断开**，
   * 而进程自己不知道 —— 表现就是所有接口 500（2026-09-20 真实发生过一次，
   * 当时 /health 还在报 up，排查绕了很大弯）。
   *
   * 为什么放后台而不是挂在请求的重试逻辑上：
   *   连接可能在语句执行到一半时断掉，盲目重放 INSERT 会写重复数据。
   *   后台探活不涉及任何业务语句，重建连接池是安全的。
   */
  function startDbWatchdog(): NodeJS.Timeout | null {
    if (config.dbWatchdogSec <= 0) return null;

    let fails = 0;

    return setInterval(() => {
      void (async () => {
        try {
          await service.ping();

          // 数据库回来了，但建表可能还没成功（启动时超时降级了）。
          // schema 是 CREATE TABLE IF NOT EXISTS，重复执行安全。
          if (!schemaReady && config.autoMigrate) {
            console.log("[db] 数据库已恢复，补建表…");
            try {
              await repo.init();
              schemaReady = true;
              initError = null;
              console.log("[db] 建表完成，服务已恢复");
            } catch (e) {
              console.warn("[db] 补建表失败，下轮再试:", e instanceof Error ? e.message : e);
            }
          }

          if (fails > 0) {
            console.log(`[db] 探活恢复正常（此前连续失败 ${fails} 次）`);
            fails = 0;
          }
        } catch (e) {
          fails++;
          const msg = e instanceof Error ? e.message : String(e);
          console.warn(`[db] 探活失败第 ${fails} 次：${msg}`);

          // 连续两次才重建 —— 单次抖动不值得动池
          if (fails >= 2) {
            console.warn("[db] 连续探活失败，重建连接池…");
            try {
              await service.reconnect();
              console.log("[db] 连接池已重建");
            } catch (re) {
              console.error("[db] 重建连接池失败：", re);
            }
            fails = 0;
          }
        }
      })();
    }, config.dbWatchdogSec * 1000).unref();
  }

  const watchdog = startDbWatchdog();

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

    if (watchdog) clearInterval(watchdog);
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
