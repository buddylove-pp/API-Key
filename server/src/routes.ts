/**
 * HTTP 路由层
 *
 * 只做三件事：解析请求 → 调用 service → 包装响应。
 * 所有业务判断都在 service.ts 里，路由层不做业务决策。
 */

import { timingSafeEqual } from "node:crypto";
import { Router, type NextFunction, type Request, type Response } from "express";
import { keyFingerprint, publicKeyToPem, isValidDeviceFp } from "./crypto.js";
import type { KeyObject } from "node:crypto";
import {
  MAX_TOKEN_TTL_SECONDS,
  ROLE_DESC,
  ROLE_LABEL,
  isAdminRole,
  roleAtLeast,
  type AdminIdentity,
  type AdminRole,
} from "./adminauth.js";
import { ErrCode, ServiceError, type CallContext, type LicenseService } from "./service.js";
import { RateLimiter } from "./ratelimit.js";

const MAX_BODY = "16kb";

/** 带身份信息的请求 */
interface AuthedRequest extends Request {
  admin?: AdminIdentity;
}

function ok(res: Response, data: unknown): void {
  res.json({ code: 0, msg: "ok", data });
}

function fail(res: Response, code: number, msg: string, httpStatus: number): void {
  res.status(httpStatus).json({ code, msg, data: null });
}

/** Express 4 不会自动捕获 async 异常，这里统一兜住 */
function wrap(fn: (req: Request, res: Response) => Promise<void>) {
  return (req: Request, res: Response, next: NextFunction) => {
    fn(req, res).catch(next);
  };
}

function clientIp(req: Request): string | null {
  const xff = req.headers["x-forwarded-for"];
  if (typeof xff === "string" && xff.length > 0) return xff.split(",")[0]!.trim();
  return req.ip ?? null;
}

function str(v: unknown): string | null {
  return typeof v === "string" && v.trim() !== "" ? v.trim() : null;
}

/**
 * 把数据库错误压成一句可对外公开的说明。
 *
 * 必须剥掉连接串 —— pg 的报错里经常带着 host / user / password，
 * 直接透到 /health 上等于把数据库凭据公开了。
 *
 * 导出是为了能单测：这是有安全影响的纯函数，不该只靠人工检查。
 */
export function sanitizeDbError(e: unknown): string {
  const raw = e instanceof Error ? e.message : String(e);
  return raw
    .replace(/(postgres(?:ql)?:\/\/)[^\s]+/gi, "$1***")
    .replace(/(password|passwd|pwd)\s*=\s*[^\s;]+/gi, "$1=***")
    .replace(/(user|username)\s*=\s*[^\s;]+/gi, "$1=***")
    .replace(/(host|hostname)\s*=\s*[^\s;]+/gi, "$1=***")
    .slice(0, 300);
}

function ctxOf(req: Request, body: Record<string, unknown>): CallContext {
  return { ip: clientIp(req), appVersion: str(body["app_version"]) };
}

export interface RouterDeps {
  service: LicenseService;
  publicKey: KeyObject;
  adminToken: string;
  rateLimitMax: number;
  rateLimitWindowSec: number;
  /** 启动期诊断信息，供 /health 暴露，便于排查容器启动失败 */
  health?: () => Record<string, unknown>;
}

export function buildRouter(deps: RouterDeps): Router {
  const { service, publicKey, adminToken } = deps;
  const router = Router();
  const limiter = new RateLimiter(deps.rateLimitMax, deps.rateLimitWindowSec);

  setInterval(() => limiter.sweep(), 60_000).unref();

  const publicLimiter = (req: Request, res: Response, next: NextFunction): void => {
    if (!limiter.allow(clientIp(req) ?? "unknown")) {
      fail(res, 4290, "请求过于频繁，请稍后重试", 429);
      return;
    }
    next();
  };

  // ============ 基础 ============

  router.get("/health", async (_req, res) => {
    const extra = deps.health?.() ?? {};
    const initError = extra["init_error"];
    const startupDegraded = typeof initError === "string" && initError !== "";

    // 真实探活。init() 只在启动时跑一次，之后连接可能被数据库、
    // 负载均衡或防火墙悄悄断开，而进程自己不知道 ——
    // 表现出来就是所有接口 500、但 /health 还报 "up"（曾经真实发生过）。
    let dbUp = true;
    let dbError: string | null = null;
    try {
      await deps.service.ping();
    } catch (e) {
      dbUp = false;
      dbError = sanitizeDbError(e);
    }

    const degraded = startupDegraded || !dbUp;

    // 即使数据库不可用也返回 200：让平台的应用检查通过，
    // 这样才有机会从 /health 读到真实故障原因，而不是只拿到一句 "App check failed"
    ok(res, {
      status: degraded ? "degraded" : "up",
      server_time: Math.floor(Date.now() / 1000),
      ...extra,
      db_reachable: dbUp,
      db_error: dbError,
    });
  });

  /**
   * 客户端拉取验签公钥。
   * 生产环境建议把公钥硬编码进客户端，这个接口只用于首次对接与排错。
   */
  router.get("/api/v1/pubkey", (_req, res) => {
    ok(res, {
      algorithm: "ES256",
      curve: "P-256",
      signature_format: "ieee-p1363",
      signed_payload: "base64url 段本身（非解码后的 JSON）",
      key_id: keyFingerprint(publicKey),
      public_key_pem: publicKeyToPem(publicKey),
    });
  });

  // ============ 激活 ============

  router.post("/api/v1/activate", publicLimiter, wrap(async (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const licenseKey = str(body["license_key"]);
    const deviceFp = body["device_fp"];
    const product = str(body["product"]);

    if (!licenseKey) throw new ServiceError(ErrCode.INVALID_PARAM);
    if (!isValidDeviceFp(deviceFp)) throw new ServiceError(ErrCode.INVALID_PARAM);
    // 软件维度必填：客户端必须声明自己是哪个软件
    if (!product) throw new ServiceError(ErrCode.INVALID_PARAM);

    const result = await service.activate(
      licenseKey,
      deviceFp,
      str(body["device_name"]),
      product,
      ctxOf(req, body),
    );
    ok(res, result);
  }));

  // ============ 心跳续期 ============

  router.post("/api/v1/heartbeat", publicLimiter, wrap(async (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const ticket = str(body["ticket"]);
    const deviceFp = body["device_fp"];

    if (!ticket) throw new ServiceError(ErrCode.INVALID_PARAM);
    if (!isValidDeviceFp(deviceFp)) throw new ServiceError(ErrCode.INVALID_PARAM);

    const result = await service.heartbeat(ticket, deviceFp, ctxOf(req, body));
    ok(res, result);
  }));

  // ============ 定期校验 ============

  /**
   * 执行一次校验，推进校验周期。
   * 与心跳的区别：心跳只续票据，校验会推进排期。
   * 校验不消耗卡密的激活次数。
   */
  router.post("/api/v1/check", publicLimiter, wrap(async (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const ticket = str(body["ticket"]);
    const deviceFp = body["device_fp"];

    if (!ticket) throw new ServiceError(ErrCode.INVALID_PARAM);
    if (!isValidDeviceFp(deviceFp)) throw new ServiceError(ErrCode.INVALID_PARAM);

    const result = await service.check(ticket, deviceFp, ctxOf(req, body));
    ok(res, result);
  }));

  /** 只读查询授权状态（不推进排期），客户端用来判断该不该弹校验窗口 */
  router.post("/api/v1/entitlement", publicLimiter, wrap(async (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const ticket = str(body["ticket"]);
    const deviceFp = body["device_fp"];

    if (!ticket) throw new ServiceError(ErrCode.INVALID_PARAM);
    if (!isValidDeviceFp(deviceFp)) throw new ServiceError(ErrCode.INVALID_PARAM);

    ok(res, await service.getEntitlement(ticket, deviceFp));
  }));

  // ============ 自助解绑 ============

  router.post("/api/v1/unbind", publicLimiter, wrap(async (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const licenseKey = str(body["license_key"]);
    const deviceFp = body["device_fp"];

    if (!licenseKey) throw new ServiceError(ErrCode.INVALID_PARAM);
    if (deviceFp !== undefined && deviceFp !== null && !isValidDeviceFp(deviceFp)) {
      throw new ServiceError(ErrCode.INVALID_PARAM);
    }

    const result = await service.unbind(
      licenseKey,
      typeof deviceFp === "string" ? deviceFp : null,
      ctxOf(req, body),
      false,
    );
    ok(res, result);
  }));

  // ============ 管理端 ============

  // ---------- 身份解析与角色守卫 ----------

  const staticTokenBuf = Buffer.from(adminToken, "utf8");

  /**
   * 两种令牌都走 `Authorization: Bearer`，靠前缀和查库区分：
   *   1) 环境变量静态令牌 —— 不落库、永不过期，始终 root（兼容既有接入）
   *   2) 动态令牌 —— 账户登录签发的会话，或后台签发的下级令牌
   */
  async function resolveIdentity(req: Request): Promise<AdminIdentity | null> {
    const header = req.headers.authorization ?? "";
    if (!header.startsWith("Bearer ")) return null;

    const raw = header.slice(7).trim();
    if (raw === "") return null;

    const givenBuf = Buffer.from(raw, "utf8");
    if (givenBuf.length === staticTokenBuf.length && timingSafeEqual(givenBuf, staticTokenBuf)) {
      return { name: "静态管理令牌", role: "root", source: "static" };
    }
    return service.resolveToken(raw);
  }

  const requireAuth = (minRole: AdminRole) =>
    (req: Request, res: Response, next: NextFunction): void => {
      resolveIdentity(req)
        .then((id) => {
          if (!id) {
            fail(res, ErrCode.AUTH_REQUIRED, "未登录或登录已失效，请重新登录", 401);
            return;
          }
          if (!roleAtLeast(id.role, minRole)) {
            fail(res, ErrCode.AUTH_FORBIDDEN, "当前身份无权执行此操作", 403);
            return;
          }
          (req as AuthedRequest).admin = id;
          next();
        })
        .catch(next);
    };

  /**
   * 只允许「账户密码登录」通过。
   *
   * 令牌管理必须用这个，不能用 requireAuth("root") ——
   * 否则 root 令牌可以再签发 root 令牌，等于权限能无限自我复制：
   * 一次泄露就能不断造新令牌，撤销旧的也没用。
   *
   * 静态 ADMIN_TOKEN 同样被挡在外面：它是长期不变的应急凭证，
   * 一旦泄露就成了永久提权入口。
   */
  const requireAccount =
    (req: Request, res: Response, next: NextFunction): void => {
      resolveIdentity(req)
        .then((id) => {
          if (!id) {
            fail(res, ErrCode.AUTH_REQUIRED, "未登录或登录已失效，请重新登录", 401);
            return;
          }
          if (id.source !== "account") {
            fail(
              res, ErrCode.AUTH_FORBIDDEN,
              "签发令牌需要账户密码登录，令牌不能派生令牌", 403,
            );
            return;
          }
          (req as AuthedRequest).admin = id;
          next();
        })
        .catch(next);
    };

  // ============ 登录（公开，但限流） ============

  router.post("/api/v1/admin/login", publicLimiter, wrap(async (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const username = str(body["username"]);
    const password = typeof body["password"] === "string" ? body["password"] : "";
    if (!username || !password) throw new ServiceError(ErrCode.INVALID_PARAM);

    const result = await service.login(username, password, {
      ip: clientIp(req), appVersion: null,
    });
    ok(res, result);
  }));

  /** 退出登录：撤销当前会话令牌，避免有效凭据在服务端堆积 */
  router.post("/api/v1/admin/logout", publicLimiter, wrap(async (req, res) => {
    const header = req.headers.authorization ?? "";
    const raw = header.startsWith("Bearer ") ? header.slice(7).trim() : "";

    if (raw !== "") {
      await service.logout(raw, { ip: clientIp(req), appVersion: null });
    }
    ok(res, { logged_out: true });
  }));

  /** 修改当前账户密码（需账户登录）。成功后踢掉该账户其它会话 */
  router.post("/api/v1/admin/password", publicLimiter, wrap(async (req, res) => {
    const identity = await resolveIdentity(req);
    if (!identity || identity.source !== "account" || !identity.username) {
      throw new ServiceError(ErrCode.AUTH_FORBIDDEN, 403);
    }

    const body = (req.body ?? {}) as Record<string, unknown>;
    const oldPw = typeof body["old_password"] === "string" ? body["old_password"] : "";
    const newPw = typeof body["new_password"] === "string" ? body["new_password"] : "";
    if (!oldPw || !newPw) throw new ServiceError(ErrCode.INVALID_PARAM);

    const header = req.headers.authorization ?? "";
    const keep = header.startsWith("Bearer ") ? header.slice(7).trim() : null;

    const kicked = await service.changePassword(
      identity.username, oldPw, newPw, keep,
      { ip: clientIp(req), appVersion: null },
    );
    ok(res, { changed: true, sessions_revoked: kicked });
  }));

  /** 当前身份与可选角色清单 */
  router.get("/api/v1/admin/me", wrap(async (req, res) => {
    const id = await resolveIdentity(req);
    if (!id) throw new ServiceError(ErrCode.AUTH_REQUIRED, 401);

    // 账户登录是最高的第 4 级，标签要与管理令牌区分开 ——
    // 否则用户会以为手里的 root 令牌和账户一样能签发令牌。
    const isAccount = id.source === "account";

    ok(res, {
      ...id,
      role_label: isAccount ? "最高管理员" : ROLE_LABEL[id.role],
      role_desc: isAccount
        ? "账户登录 · 唯一可签发与撤销令牌的身份"
        : ROLE_DESC[id.role],
      /** 只有账户密码登录能管理令牌 —— 令牌不能派生令牌 */
      can_manage_tokens: isAccount && id.role === "root",
      can_change_password: isAccount,
      max_token_ttl_seconds: MAX_TOKEN_TTL_SECONDS,
      roles: (["readonly", "operator", "root"] as AdminRole[]).map((r) => ({
        value: r, label: ROLE_LABEL[r], desc: ROLE_DESC[r],
      })),
    });
  }));

  // ============ 管理接口 ============

  const admin = Router();
  // 先限流再鉴权：否则令牌可以被无限次暴力尝试
  admin.use(publicLimiter);
  admin.use(requireAuth("readonly"));

  // ---- 管理员令牌管理（仅 root） ----

  admin.get("/tokens", requireAccount, wrap(async (req, res) => {
    const q = req.query;

    const kindRaw = str(q["kind"]);
    const roleRaw = str(q["role"]);
    const stateRaw = str(q["state"]);
    const sinceRaw = str(q["since_minutes"]);

    const kind =
      kindRaw === "session" || kindRaw === "issued" ? kindRaw : undefined;
    const role =
      roleRaw === "root" || roleRaw === "operator" || roleRaw === "readonly"
        ? roleRaw
        : undefined;
    const state =
      stateRaw === "active" || stateRaw === "revoked" || stateRaw === "expired"
        ? stateRaw
        : undefined;
    const sinceMinutes = sinceRaw !== null ? Number(sinceRaw) : undefined;

    const tokens = await service.listAdminTokens({
      kind,
      role,
      state,
      sinceMinutes:
        sinceMinutes !== undefined && Number.isFinite(sinceMinutes) && sinceMinutes > 0
          ? sinceMinutes
          : undefined,
    });

    // 两类各有多少条（不受筛选影响），前端下拉里显示数量用
    const all = await service.listAdminTokens({});
    ok(res, {
      tokens,
      counts: {
        session: all.filter((t) => t.is_session).length,
        issued: all.filter((t) => !t.is_session).length,
      },
    });
  }));

  admin.post("/tokens", requireAccount, wrap(async (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const identity = (req as AuthedRequest).admin!;

    const role = body["role"];
    if (!isAdminRole(role)) throw new ServiceError(ErrCode.INVALID_PARAM);

    const ttl = Number(body["ttl_seconds"] ?? 1800);
    const result = await service.createAdminToken(
      role, str(body["name"]), ttl, identity.name,
    );
    ok(res, result);
  }));

  admin.post("/tokens/:id/revoke", requireAccount, wrap(async (req, res) => {
    const identity = (req as AuthedRequest).admin!;
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) throw new ServiceError(ErrCode.INVALID_PARAM);

    await service.revokeAdminToken(id, identity.name);
    ok(res, { id, revoked: true });
  }));

  // ============ 软件注册表 ============
  // 卡密的 product 维度只能从这里来，杜绝手输错字

  /** 软件列表 */
  admin.get("/products", wrap(async (req, res) => {
    const s = str(req.query["status"]);
    const status = s === "active" || s === "pending" || s === "disabled" ? s : undefined;
    const products = await service.listProducts(status);
    ok(res, {
      products,
      total: products.length,
      pending: products.filter((p) => p.status === "pending").length,
    });
  }));

  /** 手动新增软件 */
  admin.post("/products", requireAuth("root"), wrap(async (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const code = str(body["code"]);
    if (!code) throw new ServiceError(ErrCode.INVALID_PARAM);
    const row = await service.createProduct(code, str(body["name"]) ?? code, str(body["note"]));
    ok(res, row);
  }));

  /** 改名 / 改备注 */
  admin.patch("/products/:code", requireAuth("root"), wrap(async (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const patch: { name?: string; note?: string | null } = {};
    const name = str(body["name"]);
    if (name) patch.name = name;
    if ("note" in body) patch.note = str(body["note"]);
    await service.updateProductInfo(String(req.params.code), patch);
    ok(res, { code: req.params.code, updated: true });
  }));

  /** 启用 / 停用 / 确认待审 */
  admin.post("/products/:code/status", requireAuth("root"), wrap(async (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const s = str(body["status"]);
    if (s !== "active" && s !== "pending" && s !== "disabled") {
      throw new ServiceError(ErrCode.INVALID_PARAM);
    }
    await service.setProductStatus(String(req.params.code), s);
    ok(res, { code: req.params.code, status: s });
  }));

  /** 删除（已有卡密的软件不允许删） */
  admin.delete("/products/:code", requireAuth("root"), wrap(async (req, res) => {
    await service.deleteProduct(String(req.params.code));
    ok(res, { code: req.params.code, deleted: true });
  }));

  /** 批量生成卡密 */
  admin.post("/licenses/generate", requireAuth("operator"), wrap(async (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const count = Number(body["count"] ?? 1);
    if (!Number.isInteger(count) || count < 1 || count > 1000) {
      throw new ServiceError(ErrCode.INVALID_PARAM);
    }

    const keys = await service.generate(count, {
      product: str(body["product"]) ?? "default",
      max_devices: Number(body["max_devices"] ?? 1),
      max_activations: Number(body["max_activations"] ?? 1),
      activation_days: Number(body["activation_days"] ?? 365),
      max_unbinds: Number(body["max_unbinds"] ?? 3),
      refund_on_unbind: body["refund_on_unbind"] !== false,
      check_mode: body["check_mode"] === "interval" ? "interval" : "frequency",
      check_frequency: Number(body["check_frequency"] ?? 1),
      check_interval_days: Number(body["check_interval_days"] ?? 0),
      check_remind_percent: Number(body["check_remind_percent"] ?? 20),
      expires_in_days: body["expires_in_days"] === null || body["expires_in_days"] === undefined
        ? null
        : Number(body["expires_in_days"]),
      note: str(body["note"]),
    });

    ok(res, { count: keys.length, keys });
  }));

  /** 卡密列表 */
  admin.get("/licenses", wrap(async (req, res) => {
    const statusRaw = str(req.query["status"]);
    const status = statusRaw === "unused" || statusRaw === "active" || statusRaw === "banned"
      ? statusRaw
      : undefined;

    const page = Math.max(1, Number(req.query["page"] ?? 1) || 1);
    const pageSize = Math.min(200, Math.max(1, Number(req.query["page_size"] ?? 50) || 50));

    const result = await service.list({
      status,
      product: str(req.query["product"]) ?? undefined,
      q: str(req.query["q"]) ?? undefined,
      hideExpired: str(req.query["hide_expired"]) === "1",
      page,
      pageSize,
    });
    ok(res, { ...result, page, page_size: pageSize });
  }));

  /**
   * 批量删除卡密（彻底删除，不可恢复）。
   *
   * 需要 root 权限 —— 这是不可逆的破坏性操作。
   * 支持传完整卡密或唯一前缀；前缀歧义的会被跳过并列在 notFound 里，不猜。
   */
  admin.post("/licenses/delete", requireAuth("root"), wrap(async (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const raw = body["keys"];

    if (!Array.isArray(raw) || raw.length === 0) {
      throw new ServiceError(ErrCode.INVALID_PARAM);
    }
    if (raw.length > 200) {
      fail(res, 4001, "一次最多删除 200 张", 400);
      return;
    }

    const keys = raw.filter((k): k is string => typeof k === "string");
    if (keys.length === 0) throw new ServiceError(ErrCode.INVALID_PARAM);

    const identity = (req as AuthedRequest).admin!;
    const result = await service.deleteLicenses(
      keys, identity.name, { ip: clientIp(req), appVersion: str(body["app_version"]) },
    );
    ok(res, result);
  }));

  /** 单卡详情：支持完整卡密或前缀 */
  admin.get("/licenses/:key", wrap(async (req, res) => {
    const key = String(req.params.key);

    let lic = await service.findByKey(key);
    if (!lic) {
      const candidates = await service.findByPrefix(key);
      if (candidates.length === 1) {
        lic = candidates[0]!;
      } else if (candidates.length > 1) {
        fail(res, 4002, `前缀匹配到 ${candidates.length} 条，请提供更长的前缀`, 400);
        return;
      }
    }
    if (!lic) throw new ServiceError(ErrCode.LICENSE_NOT_FOUND);

    const bindings = await service.bindingsOf(lic);
    // 每台设备的授权期 / 校验排期 / 下次校验时间 / 强制校验状态
    const devices = await service.deviceDetails(lic);
    const audit = await service.auditOf(lic, 100);

    ok(res, { license: lic, bindings, devices, audit });
  }));

  // ============ 强制校验 ============

  /**
   * 命令客户端立即校验。
   * 客户端下次心跳 / 启动查询会读到 force_check=true，必须弹不可跳过的校验窗。
   * 不传 device_fp 表示对该卡密下所有设备生效。
   */
  admin.post("/licenses/:key/force-check", requireAuth("operator"), wrap(async (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const lic = await service.findByKeyOrPrefix(String(req.params.key));
    if (!lic) throw new ServiceError(ErrCode.LICENSE_NOT_FOUND);

    // ⚠️ str() 返回 null 而不是 undefined，判断要用 !== null
    const deviceFp = str(body["device_fp"]);
    if (deviceFp !== null && !isValidDeviceFp(deviceFp)) {
      throw new ServiceError(ErrCode.INVALID_PARAM);
    }

    const identity = (req as AuthedRequest).admin!;
    const n = await service.forceCheck(lic, deviceFp, str(body["reason"]), identity.name);

    ok(res, { license_id: lic.id, device_fp: deviceFp ?? null, devices: n });
  }));

  /** 撤销强制校验标记 */
  admin.post("/licenses/:key/force-check/clear", requireAuth("operator"), wrap(async (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const lic = await service.findByKeyOrPrefix(String(req.params.key));
    if (!lic) throw new ServiceError(ErrCode.LICENSE_NOT_FOUND);

    // ⚠️ str() 返回 null 而不是 undefined，判断要用 !== null
    const deviceFp = str(body["device_fp"]);
    if (deviceFp !== null && !isValidDeviceFp(deviceFp)) {
      throw new ServiceError(ErrCode.INVALID_PARAM);
    }

    const identity = (req as AuthedRequest).admin!;
    const n = await service.clearForceCheck(lic, deviceFp, identity.name);

    ok(res, { license_id: lic.id, cleared: n });
  }));

  /** 封禁 */
  admin.post("/licenses/ban", requireAuth("root"), wrap(async (req, res) => {
    const key = str(((req.body ?? {}) as Record<string, unknown>)["license_key"]);
    if (!key) throw new ServiceError(ErrCode.INVALID_PARAM);
    const lic = await service.findByKey(key);
    if (!lic) throw new ServiceError(ErrCode.LICENSE_NOT_FOUND);
    await service.setStatus(lic, "banned", { ip: clientIp(req), appVersion: null });
    ok(res, { id: lic.id, status: "banned" });
  }));

  /** 解封 */
  admin.post("/licenses/unban", requireAuth("root"), wrap(async (req, res) => {
    const key = str(((req.body ?? {}) as Record<string, unknown>)["license_key"]);
    if (!key) throw new ServiceError(ErrCode.INVALID_PARAM);
    const lic = await service.findByKey(key);
    if (!lic) throw new ServiceError(ErrCode.LICENSE_NOT_FOUND);
    const next = lic.activation_count > 0 ? "active" : "unused";
    await service.setStatus(lic, next, { ip: clientIp(req), appVersion: null });
    ok(res, { id: lic.id, status: next });
  }));

  /** 管理员强制解绑（不受解绑次数限制，也不扣次数） */
  admin.post("/licenses/unbind", requireAuth("operator"), wrap(async (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const key = str(body["license_key"]);
    const deviceFp = str(body["device_fp"]);
    if (!key) throw new ServiceError(ErrCode.INVALID_PARAM);

    const result = await service.unbind(key, deviceFp, { ip: clientIp(req), appVersion: null }, true);
    ok(res, result);
  }));

  // ---- 全局审计日志（登录记录 / 令牌操作 / 卡密操作） ----

  admin.get("/audit", wrap(async (req, res) => {
    const page = Math.max(1, Number(req.query["page"] ?? 1) || 1);
    const pageSize = Math.min(200, Math.max(1, Number(req.query["page_size"] ?? 50) || 50));

    const result = await service.listAuditGlobal({
      eventPrefix: str(req.query["prefix"]) ?? undefined,
      event: str(req.query["event"]) ?? undefined,
      page,
      pageSize,
    });
    ok(res, { ...result, page, page_size: pageSize });
  }));

  router.use("/admin/v1", admin);

  // ============ 兜底错误处理 ============

  router.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    if (err instanceof ServiceError) {
      fail(res, err.code, err.message, err.httpStatus);
      return;
    }
    // 不把内部错误细节吐给客户端
    console.error("[unhandled]", err);
    fail(res, 5000, "服务器内部错误", 500);
  });

  router.use((_req: Request, res: Response) => {
    fail(res, 4040, "接口不存在", 404);
  });

  return router;
}

export { MAX_BODY };
