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
import type {
  AuditQuery, BindingRow, LicenseRow, ProductRow, ProductStatus, Repo,
} from "./repo.js";
import {
  SECONDS_PER_DAY,
  advanceNextCheck,
  computeRemindAt,
  deriveState,
  initialPlan,
  resolveIntervalDays,
  type CheckMode,
} from "./checkplan.js";
import {
  DEFAULT_TOKEN_TTL_SECONDS,
  MAX_TOKEN_TTL_SECONDS,
  generateAdminToken,
  hashAdminToken,
  hashPassword,
  isAdminRole,
  tokenPrefixOf,
  verifyPassword,
  type AdminIdentity,
  type AdminRole,
} from "./adminauth.js";

/** 账户登录后签发的会话令牌有效期：12 小时 */
export const LOGIN_SESSION_TTL_SECONDS = 12 * 60 * 60;

export const nowSec = (): number => Math.floor(Date.now() / 1000);

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
  PRODUCT_NOT_REGISTERED: 1007,
  /** 本设备授权已到期（校验也救不回来，只能重新激活） */
  ENTITLEMENT_EXPIRED: 1008,

  TICKET_INVALID: 2001,

  NOT_BOUND: 3001,
  UNBIND_EXHAUSTED: 3002,

  AUTH_REQUIRED: 4010,
  AUTH_FAILED: 4011,
  AUTH_FORBIDDEN: 4012,
} as const;

const ERR_MESSAGE: Record<number, string> = {
  [ErrCode.INVALID_PARAM]: "请求参数不合法",
  [ErrCode.LICENSE_NOT_FOUND]: "卡密不存在",
  [ErrCode.LICENSE_BANNED]: "卡密已被封禁",
  [ErrCode.ACTIVATION_EXHAUSTED]: "该卡密的激活次数已用尽",
  [ErrCode.LICENSE_EXPIRED]: "卡密已过期",
  [ErrCode.DEVICE_LIMIT_REACHED]: "绑定设备数已达上限，请先解绑其他设备",
  [ErrCode.PRODUCT_MISMATCH]: "该卡密不适用于本软件",
  [ErrCode.PRODUCT_NOT_REGISTERED]: "该软件尚未在后台启用，请联系管理员确认",
  [ErrCode.ENTITLEMENT_EXPIRED]: "本设备授权已到期，请重新使用卡密激活",
  [ErrCode.TICKET_INVALID]: "授权已失效，请重新激活",
  [ErrCode.NOT_BOUND]: "该设备未绑定到此卡密",
  [ErrCode.UNBIND_EXHAUSTED]: "解绑次数已用尽，请联系客服",
  [ErrCode.AUTH_REQUIRED]: "未登录或登录已失效，请重新登录",
  [ErrCode.AUTH_FAILED]: "账号或密码错误",
  [ErrCode.AUTH_FORBIDDEN]: "当前身份无权执行此操作",
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
  /** 本设备的授权与校验排期 */
  entitlement: EntitlementInfo;
}

/**
 * 本设备的授权状态。客户端据此决定：
 *   state = active   → 正常使用
 *   state = due      → 进入提醒期，可提示用户去校验（用户可跳过）
 *   state = overdue  → 必须校验，否则强制停用
 */
export interface EntitlementInfo {
  /** 首次激活时间（时间锚点） */
  activated_at: number;
  /** 本设备授权到期 */
  expires_at: number;
  /** 授权剩余天数（向上取整，最小 0） */
  days_left: number;

  check_mode: CheckMode;
  check_frequency: number;
  check_interval_days: number;
  check_remind_percent: number;

  /** 上次校验时间 */
  last_check_at: number;
  /** 计划下次校验时间；null = 不校验 */
  next_check_at: number | null;
  /** 提醒开始时间；null = 不提醒 */
  remind_at: number | null;

  state: "active" | "due" | "overdue";
  /** 是否已到必须校验的时刻（超期即强制停用） */
  must_check: boolean;
}

/** 校验结果：票据 + 新的排期 */
export interface CheckResult extends TicketInfo {
  entitlement: EntitlementInfo;
  /** 本次是否推进了校验周期 */
  advanced: boolean;
  /** 上次计划校验时间，便于客户端核对 */
  previous_next_check_at: number | null;
}

export interface GenerateOptions {
  /** 软件维度：卡密归属的产品标识 */
  product: string;
  max_devices: number;
  max_activations: number;
  activation_days: number;
  max_unbinds: number;
  refund_on_unbind: boolean;
  /** 校验排期方式：frequency 定频率 / interval 定时间 */
  check_mode: CheckMode;
  /** 定频率模式：把 activation_days 等分成 N 段；1 = 不校验 */
  check_frequency: number;
  /** 定时间模式：直接指定每 D 天校验一次；0 = 不校验 */
  check_interval_days: number;
  /** 提前提醒比例（%），0 = 不提醒 */
  check_remind_percent: number;
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
    /** 票据（离线容忍窗口）的最大天数。默认 7 天 */
    private readonly ticketMaxTtlDays: number = 7,
  ) {}

  // ---------- 内部工具 ----------

  /**
   * 票据有效期 = 离线容忍窗口。
   *
   * ⚠️ 必须被「下次校验时间」截断：票据是客户端离线运行的凭据，
   * 如果它能覆盖过整个校验周期，用户只要断网就永远不用校验了。
   *
   * 取三者最小值：
   *   1. 授权到期时间
   *   2. 下次校验时间（没设定期校验时为 ∞）
   *   3. now + ticketMaxTtlDays（兜底上限，防止 interval 设得过大）
   */
  private computeTicketExpiry(lic: LicenseRow, binding: BindingRow, now: number): number {
    let exp = binding.entitlement_expires_at
      ?? now + lic.activation_days * SECONDS_PER_DAY;

    if (binding.next_check_at !== null) exp = Math.min(exp, binding.next_check_at);

    const cap = now + this.ticketMaxTtlDays * SECONDS_PER_DAY;
    return Math.min(exp, cap);
  }

  private issueTicket(
    lic: LicenseRow, deviceFp: string, now: number, binding: BindingRow,
  ): TicketInfo {
    const exp = this.computeTicketExpiry(lic, binding, now);
    const payload: TicketPayload = {
      v: TICKET_VERSION,
      lid: lic.id,
      fp: deviceFp,
      iat: now,
      exp,
      aat: binding.first_seen,
      eat: binding.entitlement_expires_at ?? exp,
      nca: binding.next_check_at,
      rat: binding.next_check_at === null
        ? null
        : computeRemindAt(
            binding.next_check_at,
            binding.check_interval_days,
            binding.check_remind_percent,
          ),
    };
    return {
      ticket: signTicket(this.privateKey, payload),
      expires_at: exp,
      server_time: now,
    };
  }

  /** 组装给客户端的授权状态 */
  private buildEntitlement(lic: LicenseRow, binding: BindingRow, now: number): EntitlementInfo {
    const entExpires = binding.entitlement_expires_at
      ?? binding.first_seen + lic.activation_days * SECONDS_PER_DAY;

    const remindAt = binding.next_check_at === null
      ? null
      : computeRemindAt(
          binding.next_check_at,
          binding.check_interval_days,
          binding.check_remind_percent,
        );

    const state = deriveState(now, binding.next_check_at, remindAt, entExpires);

    return {
      activated_at: binding.first_seen,
      expires_at: entExpires,
      days_left: Math.max(0, Math.ceil((entExpires - now) / SECONDS_PER_DAY)),
      check_mode: lic.check_mode,
      check_frequency: binding.check_frequency,
      check_interval_days: binding.check_interval_days,
      check_remind_percent: binding.check_remind_percent,
      last_check_at: binding.last_check_at ?? binding.first_seen,
      next_check_at: binding.next_check_at,
      remind_at: remindAt,
      state,
      must_check: state === "overdue",
    };
  }

  /** 激活时算出本设备的授权期与首次校验计划 */
  private buildInitialEntitlement(lic: LicenseRow, at: number) {
    const intervalDays = resolveIntervalDays(
      lic.check_mode, lic.activation_days, lic.check_frequency, lic.check_interval_days,
    );
    const plan = initialPlan(at, intervalDays, lic.check_remind_percent);

    return {
      entitlement_expires_at: at + lic.activation_days * SECONDS_PER_DAY,
      check_frequency: lic.check_frequency,
      check_interval_days: intervalDays,
      check_remind_percent: lic.check_remind_percent,
      last_check_at: at,
      next_check_at: plan.nextCheckAt,
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

    // 软件注册校验：标识必须已在后台启用。
    // 未登记过的先登记为 pending，管理员在后台确认后即可发卡。
    // ⚠️ 顺序很关键：放在卡密校验之后，否则无效卡密能把注册表刷爆。
    const prod = await this.repo.findProductByCode(product);
    if (!prod) {
      await this.repo.registerUnknownProduct(product, now, ctx.ip, ctx.appVersion);
      throw new ServiceError(ErrCode.PRODUCT_NOT_REGISTERED);
    }
    if (prod.status !== "active") {
      throw new ServiceError(ErrCode.PRODUCT_NOT_REGISTERED);
    }

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
      return this.buildActivateResult(lic, deviceFp, now, existing);
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

    // 授权期与首次校验计划在激活这一刻一次算定，之后不再受卡密自身有效期影响
    await this.repo.createBinding(
      lic.id, deviceFp, deviceName, now, this.buildInitialEntitlement(lic, now),
    );
    await this.repo.incrementActivation(lic.id, now);

    await this.repo.audit({
      license_id: lic.id, event: "activate", device_fp: deviceFp,
      ip: ctx.ip, app_version: ctx.appVersion, detail: null, created_at: now,
    });

    // 重新读取，拿到自增后的计数与刚写入的排期
    const fresh = (await this.repo.findLicenseById(lic.id)) ?? lic;
    const binding = (await this.repo.findBinding(lic.id, deviceFp))!;
    return this.buildActivateResult(fresh, deviceFp, now, binding);
  }

  private buildActivateResult(
    lic: LicenseRow, deviceFp: string, now: number, binding: BindingRow,
  ): ActivateResult {
    const t = this.issueTicket(lic, deviceFp, now, binding);
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
      entitlement: this.buildEntitlement(lic, binding, now),
    };
  }

  // ---------- 心跳续期 ----------

  /**
   * 解析会话：验票据 + 取卡密与设备绑定。
   *
   * ⚠️ 只拦「封禁」，**不拦卡密自身过期** —— 卡密过期只是不能再激活，
   * 已激活的设备在授权期内仍要能校验（这是明确要求）。
   * 授权是否过期由调用方单独判断。
   */
  private async resolveSession(ticket: string, deviceFp: string, now: number) {
    const payload = verifyTicket(this.publicKey, ticket);
    if (!payload) throw new ServiceError(ErrCode.TICKET_INVALID, 403);
    if (payload.v !== TICKET_VERSION) throw new ServiceError(ErrCode.TICKET_INVALID, 403);
    if (payload.exp <= now) throw new ServiceError(ErrCode.TICKET_INVALID, 403);
    // 票据与设备绑定，防止被复制到别的机器
    if (payload.fp !== deviceFp) throw new ServiceError(ErrCode.TICKET_INVALID, 403);

    const lic = await this.repo.findLicenseById(payload.lid);
    if (!lic) throw new ServiceError(ErrCode.TICKET_INVALID, 403);

    // 吊销生效点：封禁后下一次心跳/校验即被踢掉
    if (lic.status === "banned") throw new ServiceError(ErrCode.LICENSE_BANNED, 403);

    const binding = await this.repo.findBinding(lic.id, deviceFp);
    if (!binding) throw new ServiceError(ErrCode.TICKET_INVALID, 403);

    return { lic, binding, payload };
  }

  /** 本设备的授权到期时间 */
  private entitlementExpiryOf(lic: LicenseRow, binding: BindingRow): number {
    return binding.entitlement_expires_at
      ?? binding.first_seen + lic.activation_days * SECONDS_PER_DAY;
  }

  async heartbeat(ticket: string, deviceFp: string, ctx: CallContext): Promise<TicketInfo> {
    const now = nowSec();
    const { lic, binding } = await this.resolveSession(ticket, deviceFp, now);

    await this.repo.touchBinding(lic.id, deviceFp, now);
    await this.repo.audit({
      license_id: lic.id, event: "heartbeat", device_fp: deviceFp,
      ip: ctx.ip, app_version: ctx.appVersion, detail: null, created_at: now,
    });

    return this.issueTicket(lic, deviceFp, now, binding);
  }

  /**
   * 定期校验。
   *
   * 与心跳的区别：**校验会推进校验周期**，心跳只是续票据。
   * 校验不消耗卡密的激活次数 —— 只有重新激活才消耗。
   */
  async check(ticket: string, deviceFp: string, ctx: CallContext): Promise<CheckResult> {
    const now = nowSec();
    const { lic, binding } = await this.resolveSession(ticket, deviceFp, now);

    const entExpires = this.entitlementExpiryOf(lic, binding);
    // 授权本身已到期 → 校验也救不回来，只能重新激活
    if (now >= entExpires) {
      throw new ServiceError(ErrCode.ENTITLEMENT_EXPIRED, 403);
    }

    const previousNext = binding.next_check_at;
    let advanced = false;

    if (previousNext !== null && binding.check_interval_days > 0) {
      // 提前或准时 → 以原计划时间为基准；超期 → 以实际校验时间为基准
      const next = advanceNextCheck(previousNext, now, binding.check_interval_days);
      await this.repo.updateBindingSchedule(lic.id, deviceFp, {
        last_check_at: now,
        next_check_at: next,
        check_state: "active",
        overdue_since: null,
      });
      advanced = true;
    } else {
      // 没设定期校验的卡密，校验只刷新一次记录
      await this.repo.updateBindingSchedule(lic.id, deviceFp, {
        last_check_at: now,
        check_state: "active",
        overdue_since: null,
      });
    }

    await this.repo.touchBinding(lic.id, deviceFp, now);
    await this.repo.audit({
      license_id: lic.id, event: "check", device_fp: deviceFp,
      ip: ctx.ip, app_version: ctx.appVersion,
      detail: previousNext === null
        ? "no-schedule"
        : `prev=${previousNext} now=${now} advanced=${advanced}`,
      created_at: now,
    });

    const fresh = (await this.repo.findBinding(lic.id, deviceFp))!;
    const t = this.issueTicket(lic, deviceFp, now, fresh);

    return {
      ...t,
      entitlement: this.buildEntitlement(lic, fresh, now),
      advanced,
      previous_next_check_at: previousNext,
    };
  }

  /** 只读查询授权状态，不推进任何排期 */
  async getEntitlement(ticket: string, deviceFp: string): Promise<EntitlementInfo> {
    const now = nowSec();
    const { lic, binding } = await this.resolveSession(ticket, deviceFp, now);
    return this.buildEntitlement(lic, binding, now);
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

    // 只能为「已启用」的软件发卡，避免标识打错字造出对不上的卡密
    const prod = await this.repo.findProductByCode(opts.product);
    if (!prod || prod.status !== "active") {
      throw new ServiceError(ErrCode.PRODUCT_NOT_REGISTERED);
    }

    // 校验排期参数合法性
    if (opts.check_mode !== "frequency" && opts.check_mode !== "interval") {
      throw new ServiceError(ErrCode.INVALID_PARAM);
    }
    if (!Number.isFinite(opts.check_frequency) || opts.check_frequency < 1 || opts.check_frequency > 1000) {
      throw new ServiceError(ErrCode.INVALID_PARAM);
    }
    if (!Number.isFinite(opts.check_interval_days) || opts.check_interval_days < 0 || opts.check_interval_days > 3650) {
      throw new ServiceError(ErrCode.INVALID_PARAM);
    }
    if (!Number.isFinite(opts.check_remind_percent) || opts.check_remind_percent < 0 || opts.check_remind_percent > 90) {
      throw new ServiceError(ErrCode.INVALID_PARAM);
    }

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
          check_mode: opts.check_mode,
          check_frequency: opts.check_frequency,
          check_interval_days: opts.check_interval_days,
          check_remind_percent: opts.check_remind_percent,
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

  // ---------- 软件注册表 ----------

  async listProducts(status?: ProductStatus): Promise<ProductRow[]> {
    return this.repo.listProducts(status);
  }

  async createProduct(code: string, name: string, note: string | null): Promise<ProductRow> {
    const trimmed = code.trim();
    // 客户端上报的标识必须是安全字符集，避免注入到日志或 SQL 里出问题
    if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{1,63}$/.test(trimmed)) {
      throw new ServiceError(ErrCode.INVALID_PARAM);
    }
    if (await this.repo.findProductByCode(trimmed)) {
      throw new ServiceError(ErrCode.INVALID_PARAM);
    }

    const now = nowSec();
    const row = await this.repo.createProduct({
      code: trimmed,
      name: name.trim() || trimmed,
      status: "active",
      note,
      created_at: now,
    });
    await this.repo.audit({
      license_id: null, event: "product.create", detail: trimmed, created_at: now,
    });
    return row;
  }

  async setProductStatus(code: string, status: ProductStatus): Promise<void> {
    if (!(await this.repo.findProductByCode(code))) {
      throw new ServiceError(ErrCode.PRODUCT_NOT_REGISTERED);
    }
    await this.repo.setProductStatus(code, status);
    await this.repo.audit({
      license_id: null, event: `product.${status}`, detail: code, created_at: nowSec(),
    });
  }

  async updateProductInfo(
    code: string, patch: { name?: string; note?: string | null },
  ): Promise<void> {
    if (!(await this.repo.findProductByCode(code))) {
      throw new ServiceError(ErrCode.PRODUCT_NOT_REGISTERED);
    }
    await this.repo.updateProductInfo(code, patch);
  }

  async deleteProduct(code: string): Promise<void> {
    if (!(await this.repo.findProductByCode(code))) {
      throw new ServiceError(ErrCode.PRODUCT_NOT_REGISTERED);
    }
    // 已有卡密的软件不允许删除，避免留下孤儿卡密
    const { total } = await this.repo.listLicenses({ product: code, page: 1, pageSize: 1 });
    if (total > 0) throw new ServiceError(ErrCode.INVALID_PARAM);

    await this.repo.deleteProduct(code);
    await this.repo.audit({
      license_id: null, event: "product.delete", detail: code, created_at: nowSec(),
    });
  }

  // ---------- 管理员账户与令牌 ----------

  /**
   * 首次启动时种下 root 账户。已有账户则什么都不做 ——
   * 所以改密码要走后台，改环境变量不会覆盖已有账户。
   */
  async ensureRootUser(username: string, password: string): Promise<boolean> {
    if ((await this.repo.countAdminUsers()) > 0) return false;

    const now = nowSec();
    await this.repo.createAdminUser({
      username,
      password_hash: hashPassword(password),
      role: "root",
      created_at: now,
    });
    await this.repo.audit({
      license_id: null, event: "admin.bootstrap", detail: `首次创建 root 账户 ${username}`,
      created_at: now,
    });
    return true;
  }

  /** 账户密码登录 → 签发会话令牌 */
  async login(
    username: string, password: string, ctx: CallContext,
  ): Promise<{ token: string; expires_at: number; role: AdminRole; username: string }> {
    const now = nowSec();
    const user = await this.repo.findAdminUser(username);

    // 用户名不存在也走一次哈希校验，避免通过响应时间探测用户是否存在
    const ok = verifyPassword(password, user?.password_hash ?? "scrypt$0$0$0$AAAA$AAAA");

    if (!user || !ok || user.disabled) {
      await this.repo.audit({
        license_id: null, event: "admin.login.fail",
        detail: `user=${username}`, ip: ctx.ip, created_at: now,
      });
      throw new ServiceError(ErrCode.AUTH_FAILED, 401);
    }

    const raw = generateAdminToken();
    const expiresAt = now + LOGIN_SESSION_TTL_SECONDS;

    await this.repo.createAdminToken({
      token_hash: hashAdminToken(raw),
      token_prefix: tokenPrefixOf(raw),
      name: `登录会话 · ${username}`,
      role: user.role,
      created_by: username,
      created_at: now,
      expires_at: expiresAt,
      // 标记为会话令牌 —— 只有这种身份能管理令牌
      owner_username: username,
    });
    await this.repo.touchAdminUserLogin(user.id, now);
    await this.repo.audit({
      license_id: null, event: "admin.login.ok",
      detail: `user=${username}`, ip: ctx.ip, created_at: now,
    });

    return { token: raw, expires_at: expiresAt, role: user.role, username };
  }

  /**
   * 校验动态令牌。
   * 静态 ADMIN_TOKEN 的校验在路由层完成（它不落库、永不过期）。
   */
  async resolveToken(raw: string): Promise<AdminIdentity | null> {
    if (!raw.startsWith("adm_")) return null;

    const row = await this.repo.findAdminTokenByHash(hashAdminToken(raw));
    if (!row || row.revoked) return null;

    const now = nowSec();
    if (row.expires_at <= now) return null;

    // 顺手记录最近使用时间，便于后台看出哪些令牌还在被用
    await this.repo.touchAdminToken(row.id, now);

    // owner_username 非空 = 账户密码登录产生的会话令牌。
    // 只有这种身份能管理令牌 —— 令牌不能派生令牌。
    if (row.owner_username !== null) {
      return {
        name: row.owner_username,
        role: row.role,
        source: "account",
        username: row.owner_username,
      };
    }

    return { name: row.name ?? row.token_prefix, role: row.role, source: "token" };
  }

  /** 签发下级令牌（需 root） */
  async createAdminToken(
    role: AdminRole, name: string | null, ttlSeconds: number, createdBy: string,
  ): Promise<{ token: string; row: AdminTokenRowView }> {
    if (!isAdminRole(role)) throw new ServiceError(ErrCode.INVALID_PARAM);

    const ttl = Math.floor(ttlSeconds);
    if (!Number.isFinite(ttl) || ttl < 60 || ttl > MAX_TOKEN_TTL_SECONDS) {
      throw new ServiceError(ErrCode.INVALID_PARAM);
    }

    const now = nowSec();
    const raw = generateAdminToken();
    const row = await this.repo.createAdminToken({
      token_hash: hashAdminToken(raw),
      token_prefix: tokenPrefixOf(raw),
      name: name?.trim() || null,
      role,
      created_by: createdBy,
      created_at: now,
      expires_at: now + ttl,
      // 手动签发的下级令牌，不是会话令牌
      owner_username: null,
    });

    await this.repo.audit({
      license_id: null, event: "admin.token.create",
      detail: `role=${role} ttl=${ttl}s by=${createdBy}`, created_at: now,
    });

    return { token: raw, row: toTokenView(row) };
  }

  async listAdminTokens(): Promise<AdminTokenRowView[]> {
    const rows = await this.repo.listAdminTokens();
    return rows.map(toTokenView);
  }

  async revokeAdminToken(id: number, by: string): Promise<void> {
    const ok = await this.repo.revokeAdminToken(id);
    if (!ok) throw new ServiceError(ErrCode.INVALID_PARAM);
    await this.repo.audit({
      license_id: null, event: "admin.token.revoke", detail: `id=${id} by=${by}`,
      created_at: nowSec(),
    });
  }

  /**
   * 退出登录：撤销本次会话令牌。
   *
   * 每次账户登录都会新建一条会话令牌，退出时不撤销就会不断堆积，
   * 留下大量仍然有效的最高权限凭据 —— 等于把风险敞口留在那里。
   * 静态 ADMIN_TOKEN 不落库，直接忽略。
   */
  async logout(raw: string, ctx: CallContext): Promise<void> {
    if (!raw.startsWith("adm_")) return;

    const row = await this.repo.findAdminTokenByHash(hashAdminToken(raw));
    if (!row || row.revoked) return;

    await this.repo.revokeAdminToken(row.id);
    await this.repo.audit({
      license_id: null, event: "admin.logout",
      detail: `user=${row.owner_username ?? row.created_by} token=${row.token_prefix}`,
      ip: ctx.ip, created_at: nowSec(),
    });
  }

  /** 撤销某账户的全部会话令牌（改密码后调用，把其它设备踢下线） */
  async revokeSessionsOf(username: string, keepTokenHash: string | null): Promise<number> {
    const rows = await this.repo.listAdminTokens();
    let n = 0;
    for (const t of rows) {
      if (t.owner_username !== username) continue;
      if (t.revoked) continue;
      if (keepTokenHash !== null && t.token_hash === keepTokenHash) continue;
      if (await this.repo.revokeAdminToken(t.id)) n++;
    }
    return n;
  }

  /** 修改账户密码。需原密码；成功后撤销该账户其它会话 */
  async changePassword(
    username: string,
    oldPassword: string,
    newPassword: string,
    keepToken: string | null,
    ctx: CallContext,
  ): Promise<number> {
    if (newPassword.length < 8) throw new ServiceError(ErrCode.INVALID_PARAM);

    const user = await this.repo.findAdminUser(username);
    // 用户名不存在也走一次哈希，避免通过响应时间探测
    const ok = verifyPassword(oldPassword, user?.password_hash ?? "scrypt$0$0$0$AAAA$AAAA");

    if (!user || !ok || user.disabled) {
      await this.repo.audit({
        license_id: null, event: "admin.password.fail",
        detail: `user=${username}`, ip: ctx.ip, created_at: nowSec(),
      });
      throw new ServiceError(ErrCode.AUTH_FAILED, 401);
    }

    await this.repo.updateAdminPassword(user.id, hashPassword(newPassword));

    // 改完密码把其它会话踢掉：密码变更通常意味着怀疑泄露
    const keepHash = keepToken === null ? null : hashAdminToken(keepToken);
    const kicked = await this.revokeSessionsOf(username, keepHash);

    await this.repo.audit({
      license_id: null, event: "admin.password.change",
      detail: `user=${username} kicked=${kicked}`, ip: ctx.ip, created_at: nowSec(),
    });
    return kicked;
  }

  /** 全局审计日志（登录记录、令牌操作、卡密操作） */
  async listAuditGlobal(query: AuditQuery) {
    return this.repo.listAuditGlobal(query);
  }
}

/** 对外返回的令牌视图：不含哈希 */
export interface AdminTokenRowView {
  id: number;
  token_prefix: string;
  name: string | null;
  role: AdminRole;
  created_by: string;
  created_at: number;
  expires_at: number;
  revoked: boolean;
  last_used_at: number | null;
  /** 是否已过期 */
  expired: boolean;
  /** true = 账户登录的会话令牌；false = 手动签发的下级令牌 */
  is_session: boolean;
  owner_username: string | null;
}

function toTokenView(row: {
  id: number; token_prefix: string; name: string | null; role: AdminRole;
  created_by: string; created_at: number; expires_at: number;
  revoked: boolean; last_used_at: number | null; owner_username?: string | null;
}): AdminTokenRowView {
  return {
    id: row.id,
    token_prefix: row.token_prefix,
    name: row.name,
    role: row.role,
    created_by: row.created_by,
    created_at: row.created_at,
    expires_at: row.expires_at,
    revoked: row.revoked,
    last_used_at: row.last_used_at,
    expired: row.expires_at <= nowSec(),
    is_session: row.owner_username !== null && row.owner_username !== undefined,
    owner_username: row.owner_username ?? null,
  };
}

export { DEFAULT_TOKEN_TTL_SECONDS };
