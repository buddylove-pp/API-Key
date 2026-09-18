/**
 * HTTP 路由层
 *
 * 只做三件事：解析请求 → 调用 service → 包装响应。
 * 所有业务判断都在 service.ts 里，路由层不做业务决策。
 */

import { timingSafeEqual } from "node:crypto";
import { Router, type NextFunction, type Request, type Response } from "express";
import { keyFingerprint, publicKeyToPem, isValidDeviceFp, type TicketPayload } from "./crypto.js";
import type { KeyObject } from "node:crypto";
import { ErrCode, ServiceError, type CallContext, type LicenseService } from "./service.js";
import { RateLimiter } from "./ratelimit.js";

const MAX_BODY = "16kb";

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

function ctxOf(req: Request, body: Record<string, unknown>): CallContext {
  return { ip: clientIp(req), appVersion: str(body["app_version"]) };
}

/** 管理接口鉴权：定长比较，避免时序侧信道 */
function adminAuth(expected: string) {
  const expectedBuf = Buffer.from(expected, "utf8");
  return (req: Request, res: Response, next: NextFunction): void => {
    const header = req.headers.authorization ?? "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : "";
    const givenBuf = Buffer.from(token, "utf8");

    const same = givenBuf.length === expectedBuf.length && timingSafeEqual(givenBuf, expectedBuf);
    if (!same) {
      fail(res, 4010, "管理令牌无效", 401);
      return;
    }
    next();
  };
}

export interface RouterDeps {
  service: LicenseService;
  publicKey: KeyObject;
  adminToken: string;
  rateLimitMax: number;
  rateLimitWindowSec: number;
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

  router.get("/health", (_req, res) => {
    ok(res, { status: "up", server_time: Math.floor(Date.now() / 1000) });
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

  const admin = Router();
  admin.use(adminAuth(adminToken));

  /** 批量生成卡密 */
  admin.post("/licenses/generate", wrap(async (req, res) => {
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
      page,
      pageSize,
    });
    ok(res, { ...result, page, page_size: pageSize });
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
    const audit = await service.auditOf(lic, 50);
    ok(res, { license: lic, bindings, audit });
  }));

  /** 封禁 */
  admin.post("/licenses/ban", wrap(async (req, res) => {
    const key = str(((req.body ?? {}) as Record<string, unknown>)["license_key"]);
    if (!key) throw new ServiceError(ErrCode.INVALID_PARAM);
    const lic = await service.findByKey(key);
    if (!lic) throw new ServiceError(ErrCode.LICENSE_NOT_FOUND);
    await service.setStatus(lic, "banned", { ip: clientIp(req), appVersion: null });
    ok(res, { id: lic.id, status: "banned" });
  }));

  /** 解封 */
  admin.post("/licenses/unban", wrap(async (req, res) => {
    const key = str(((req.body ?? {}) as Record<string, unknown>)["license_key"]);
    if (!key) throw new ServiceError(ErrCode.INVALID_PARAM);
    const lic = await service.findByKey(key);
    if (!lic) throw new ServiceError(ErrCode.LICENSE_NOT_FOUND);
    const next = lic.activation_count > 0 ? "active" : "unused";
    await service.setStatus(lic, next, { ip: clientIp(req), appVersion: null });
    ok(res, { id: lic.id, status: next });
  }));

  /** 管理员强制解绑（不受解绑次数限制，也不扣次数） */
  admin.post("/licenses/unbind", wrap(async (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const key = str(body["license_key"]);
    const deviceFp = str(body["device_fp"]);
    if (!key) throw new ServiceError(ErrCode.INVALID_PARAM);

    const result = await service.unbind(key, deviceFp, { ip: clientIp(req), appVersion: null }, true);
    ok(res, result);
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
