/**
 * 核心业务逻辑：激活 / 心跳 / 解绑 / 卡密管理
 *
 * 所有校验都在这里，路由层只负责解析请求和包装响应。
 * 这样做的目的是让业务规则可以被独立测试，不受 HTTP 层干扰。
 */

import type { KeyObject } from "node:crypto";
import {
  generateLicenseKey,
  keyPrefixOf,
  normalizeLicenseKey,
  sha256Hex,
  signTicket,
  verifyTicket,
  TICKET_VERSION,
  type TicketPayload,
} from "./crypto.js";
import type { BindingRow, LicenseRow, Repo } from "./repo.js";

export const nowSec = (): number => Math.floor(Date.now() / 1000);

const SECONDS_PER_DAY = 86_400;

// ============ 错误码 ============
// 客户端按 code 做本地化提示，不要依赖 msg 文案

export const ErrCode = {
  OK: 0,
  INVALID_PARAM: 4001,

  LICENSE_NOT_FOUND: 1001,
  LICENSE_BANNED: 1002,
  ACTIVATION_EXHAUSTED: 1003,
  LICENSE_EXPIRED: 1004,
  DEVICE_LIMIT_REACHED: 1005,
  PRODUCT_MISMATCH: 1006,

  TICKET_INVALID: 2001,

  NOT_BOUND: 3001,
  UNBIND_EXHAUSTED: 3002,
} as const;

const ERR_MESSAGE: Record<number, string> = {
  [ErrCode.INVALID_PARAM]: "请求参数不合法",
  [ErrCode.LICENSE_NOT_FOUND]: "卡密不存在",
  [ErrCode.LICENSE_BANNED]: "卡密已被封禁",
  [ErrCode.ACTIVATION_EXHAUSTED]: "该卡密的激活次数已用尽",
  [ErrCode.LICENSE_EXPIRED]: "卡密已过期",
  [ErrCode.DEVICE_LIMIT_REACHED]: "绑定设备数已达上限，请先解绑其他设备",
  [ErrCode.PRODUCT_MISMATCH]: "该卡密不适用于本软件",
  [ErrCode.TICKET_INVALID]: "授权已失效，请重新激活",
  [ErrCode.NOT_BOUND]: "该设备未绑定到此卡密",
  [ErrCode.UNBIND_EXHAUSTED]: "解绑次数已用尽，请联系客服",
};

export class ServiceError extends Error {
  constructor(public readonly code: number, public readonly httpStatus = 400) {
    super(ERR_MESSAGE[code] ?? "未知错误");
    this.name = "ServiceError";
  }
}

// ============ 对外返回结构 ============

export interface TicketInfo {
  ticket: string;
  expires_at: number;
  server_time: number;
}

export interface ActivateResult extends TicketInfo {
  license: {
    activation_days: number;
    max_activations: number;
    activation_count: number;
    max_devices: number;
    max_unbinds: number;
    unbind_count: number;
    expires_at: number | null;
  };
}

export interface GenerateOptions {
  /** 软件维度：卡密归属的产品标识 */
  product: string;
  max_devices: number;
  max_activations: number;
  activation_days: number;
  max_unbinds: number;
  refund_on_unbind: boolean;
  /** 卡密绝对有效期（天）。null = 不限制 */
  expires_in_days: number | null;
  note: string | null;
}

export interface CallContext {
  ip: string | null;
  appVersion: string | null;
}

// ============ 服务 ============

export class LicenseService {
  constructor(
    private readonly repo: Repo,
    private readonly privateKey: KeyObject,
    private readonly publicKey: KeyObject,
  ) {}

  // ---------- 内部工具 ----------

  /**
   * 票据过期时间 = min(现在 + 本次激活授予天数, 卡密绝对到期时间)
   * 这样「每次激活给 N 天」和「卡密本身某天作废」两条规则能同时生效
   */
  private computeTicketExpiry(lic: LicenseRow, now: number): number {
    let exp = now + lic.activation_days * SECONDS_PER_DAY;
    if (lic.expires_at !== null) exp = Math.min(exp, lic.expires_at);
    return exp;
  }

  private issueTicket(lic: LicenseRow, deviceFp: string, now: number): TicketInfo {
    const exp = this.computeTicketExpiry(lic, now);
    const payload: TicketPayload = {
      v: TICKET_VERSION,
      lid: lic.id,
      fp: deviceFp,
      iat: now,
      exp,
    };
    return {
      ticket: signTicket(this.privateKey, payload),
      expires_at: exp,
      server_time: now,
    };
  }

  private assertUsable(lic: LicenseRow, now: number): void {
    if (lic.status === "banned") throw new ServiceError(ErrCode.LICENSE_BANNED);
    if (lic.expires_at !== null && now > lic.expires_at) {
      throw new ServiceError(ErrCode.LICENSE_EXPIRED);
    }
  }

  // ---------- 激活 ----------

  async activate(
    rawKey: string,
    deviceFp: string,
    deviceName: string | null,
    product: string,
    ctx: CallContext,
  ): Promise<ActivateResult> {
    const now = nowSec();
    const normalized = normalizeLicenseKey(rawKey);
    if (normalized.length < 10) throw new ServiceError(ErrCode.INVALID_PARAM);

    const lic = await this.repo.findLicenseByKeyHash(sha256Hex(normalized));
    if (!lic) throw new ServiceError(ErrCode.LICENSE_NOT_FOUND);

    // 软件维度校验：A 软件的卡密不能在 B 软件上激活
    if (lic.product !== product) throw new ServiceError(ErrCode.PRODUCT_MISMATCH);

    this.assertUsable(lic, now);

    // 同一设备重复激活 → 幂等，直接发票据，不消耗激活次数
    // （用户重装软件是高频场景，不能因此扣次数）
    const existing = await this.repo.findBinding(lic.id, deviceFp);
    if (existing) {
      await this.repo.touchBinding(lic.id, deviceFp, now);
      await this.repo.audit({
        license_id: lic.id, event: "activate", device_fp: deviceFp,
        ip: ctx.ip, app_version: ctx.appVersion, detail: "idempotent", created_at: now,
      });
      return this.buildActivateResult(lic, deviceFp, now);
    }

    // 设备数上限
    const bindings = await this.repo.listBindings(lic.id);
    if (bindings.length >= lic.max_devices) {
      throw new ServiceError(ErrCode.DEVICE_LIMIT_REACHED);
    }

    // 激活次数上限
    if (lic.activation_count >= lic.max_activations) {
      throw new ServiceError(ErrCode.ACTIVATION_EXHAUSTED);
    }

    await this.repo.createBinding(lic.id, deviceFp, deviceName, now);
    await this.repo.incrementActivation(lic.id, now);

    await this.repo.audit({
      license_id: lic.id, event: "activate", device_fp: deviceFp,
      ip: ctx.ip, app_version: ctx.appVersion, detail: null, created_at: now,
    });

    // 重新读取，拿到自增后的计数
    const fresh = (await this.repo.findLicenseById(lic.id)) ?? lic;
    return this.buildActivateResult(fresh, deviceFp, now);
  }

  private buildActivateResult(lic: LicenseRow, deviceFp: string, now: number): ActivateResult {
    const t = this.issueTicket(lic, deviceFp, now);
    return {
      ...t,
      license: {
        activation_days: lic.activation_days,
        max_activations: lic.max_activations,
        activation_count: lic.activation_count,
        max_devices: lic.max_devices,
        max_unbinds: lic.max_unbinds,
        unbind_count: lic.unbind_count,
        expires_at: lic.expires_at,
      },
    };
  }

  // ---------- 心跳续期 ----------

  async heartbeat(ticket: string, deviceFp: string, ctx: CallContext): Promise<TicketInfo> {
    const now = nowSec();

    const payload = verifyTicket(this.publicKey, ticket);
    if (!payload) throw new ServiceError(ErrCode.TICKET_INVALID, 403);
    if (payload.v !== TICKET_VERSION) throw new ServiceError(ErrCode.TICKET_INVALID, 403);
    if (payload.exp <= now) throw new ServiceError(ErrCode.TICKET_INVALID, 403);
    // 票据与设备绑定，防止被复制到别的机器
    if (payload.fp !== deviceFp) throw new ServiceError(ErrCode.TICKET_INVALID, 403);

    const lic = await this.repo.findLicenseById(payload.lid);
    if (!lic) throw new ServiceError(ErrCode.TICKET_INVALID, 403);

    // 这里是吊销生效点：封禁 / 过期 / 被解绑，都会在下一次心跳被踢掉
    this.assertUsable(lic, now);

    const binding = await this.repo.findBinding(lic.id, deviceFp);
    if (!binding) throw new ServiceError(ErrCode.TICKET_INVALID, 403);

    await this.repo.touchBinding(lic.id, deviceFp, now);
    await this.repo.audit({
      license_id: lic.id, event: "heartbeat", device_fp: deviceFp,
      ip: ctx.ip, app_version: ctx.appVersion, detail: null, created_at: now,
    });

    return this.issueTicket(lic, deviceFp, now);
  }

  // ---------- 解绑 ----------

  async unbind(
    rawKey: string,
    deviceFp: string | null,
    ctx: CallContext,
    forced: boolean,
  ): Promise<{ unbind_count: number; max_unbinds: number; released: string[] }> {
    const now = nowSec();
    const normalized = normalizeLicenseKey(rawKey);

    const lic = await this.repo.findLicenseByKeyHash(sha256Hex(normalized));
    if (!lic) throw new ServiceError(ErrCode.LICENSE_NOT_FOUND);

    const bindings = await this.repo.listBindings(lic.id);

    let targets: BindingRow[];
    if (forced) {
      // 管理员强制解绑：指定则解绑指定设备，未指定则清空全部
      targets = deviceFp ? bindings.filter((b) => b.device_fp === deviceFp) : bindings;
      if (deviceFp && targets.length === 0) throw new ServiceError(ErrCode.NOT_BOUND);
    } else {
      if (!deviceFp) throw new ServiceError(ErrCode.INVALID_PARAM);
      targets = bindings.filter((b) => b.device_fp === deviceFp);
      if (targets.length === 0) throw new ServiceError(ErrCode.NOT_BOUND);
      // 用户自助解绑才受次数限制
      if (lic.unbind_count >= lic.max_unbinds) {
        throw new ServiceError(ErrCode.UNBIND_EXHAUSTED);
      }
    }

    const released: string[] = [];
    for (const b of targets) {
      const ok = await this.repo.deleteBinding(lic.id, b.device_fp);
      if (ok) released.push(b.device_fp);
    }

    if (!forced) {
      await this.repo.incrementUnbind(lic.id);
      // 解绑返还激活次数：用户换机是正当需求，用 max_unbinds 限流已足够
      if (lic.refund_on_unbind) {
        await this.repo.decrementActivation(lic.id);
      }
    }

    await this.repo.audit({
      license_id: lic.id, event: "unbind", device_fp: deviceFp,
      ip: ctx.ip, app_version: ctx.appVersion,
      detail: forced ? `forced:${released.length}` : `self:${released.length}`,
      created_at: now,
    });

    const fresh = (await this.repo.findLicenseById(lic.id)) ?? lic;
    return {
      unbind_count: fresh.unbind_count,
      max_unbinds: fresh.max_unbinds,
      released,
    };
  }

  // ---------- 管理端 ----------

  async generate(count: number, opts: GenerateOptions): Promise<string[]> {
    if (count < 1 || count > 1000) throw new ServiceError(ErrCode.INVALID_PARAM);

    const now = nowSec();
    const expiresAt = opts.expires_in_days === null
      ? null
      : now + opts.expires_in_days * SECONDS_PER_DAY;

    const keys: string[] = [];
    for (let i = 0; i < count; i++) {
      // 极小概率撞库，重试几次
      let created = false;
      for (let attempt = 0; attempt < 5 && !created; attempt++) {
        const key = generateLicenseKey();
        const normalized = normalizeLicenseKey(key);
        const hash = sha256Hex(normalized);
        const dup = await this.repo.findLicenseByKeyHash(hash);
        if (dup) continue;

        await this.repo.createLicense({
          key_hash: hash,
          key_prefix: keyPrefixOf(normalized),
          product: opts.product,
          max_devices: opts.max_devices,
          max_activations: opts.max_activations,
          activation_days: opts.activation_days,
          max_unbinds: opts.max_unbinds,
          refund_on_unbind: opts.refund_on_unbind,
          expires_at: expiresAt,
          note: opts.note,
          created_at: now,
        });
        keys.push(key);
        created = true;
      }
      if (!created) throw new Error("卡密生成失败：连续冲突，请重试");
    }

    await this.repo.audit({
      license_id: null, event: "generate", detail: `count=${keys.length}`, created_at: now,
    });

    return keys;
  }

  async findByKey(rawKey: string): Promise<LicenseRow | null> {
    return this.repo.findLicenseByKeyHash(sha256Hex(normalizeLicenseKey(rawKey)));
  }

  async findByPrefix(prefix: string): Promise<LicenseRow[]> {
    return this.repo.findLicensesByPrefix(prefix);
  }

  async list(opts: {
    status?: "unused" | "active" | "banned";
    product?: string;
    q?: string;
    page: number;
    pageSize: number;
  }) {
    return this.repo.listLicenses(opts);
  }

  async setStatus(lic: LicenseRow, status: "unused" | "active" | "banned", ctx: CallContext): Promise<void> {
    await this.repo.setLicenseStatus(lic.id, status);
    await this.repo.audit({
      license_id: lic.id, event: status === "banned" ? "ban" : "unban",
      ip: ctx.ip, created_at: nowSec(),
    });
  }

  async bindingsOf(lic: LicenseRow): Promise<BindingRow[]> {
    return this.repo.listBindings(lic.id);
  }

  async auditOf(lic: LicenseRow, limit: number) {
    return this.repo.listAudit(lic.id, limit);
  }
}
