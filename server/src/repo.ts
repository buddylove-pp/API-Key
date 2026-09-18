/**
 * 数据访问层
 *
 * 提供两套实现：
 *   - MemoryRepo —— 内存，用于本地开发与自动化测试（进程重启数据全丢）
 *   - PgRepo     —— PostgreSQL，生产环境
 *
 * 抽这一层的目的：让核心业务逻辑可以在没有数据库的情况下被完整测试。
 * 所有 SQL 一律使用参数绑定，杜绝拼接。
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import pg from "pg";
import type { AdminRole } from "./adminauth.js";

// node-postgres 默认把 BIGINT 当字符串返回，这里统一转成 number
pg.types.setTypeParser(20, (v: string) => Number(v));

// ============ 类型 ============

export type LicenseStatus = "unused" | "active" | "banned";

/** 校验排期方式 */
export type CheckMode = "frequency" | "interval";

/** 设备的校验状态：正常 / 进入提醒期 / 已超期停用 */
export type CheckState = "active" | "due" | "overdue";

/** 软件状态：active 可正常发卡；pending 客户端上报过但管理员未确认；disabled 停用 */
export type ProductStatus = "active" | "pending" | "disabled";

export interface ProductRow {
  id: number;
  code: string;
  name: string;
  status: ProductStatus;
  note: string | null;
  created_at: number;
  first_seen_at: number | null;
  first_seen_ip: string | null;
  app_version: string | null;
}

export interface CreateProductInput {
  code: string;
  name: string;
  status: ProductStatus;
  note: string | null;
  created_at: number;
}

// ============ 管理员账户与令牌 ============

export interface AdminUserRow {
  id: number;
  username: string;
  password_hash: string;
  role: AdminRole;
  disabled: boolean;
  created_at: number;
  last_login_at: number | null;
}

export interface AdminTokenRow {
  id: number;
  token_hash: string;
  token_prefix: string;
  name: string | null;
  role: AdminRole;
  created_by: string;
  created_at: number;
  expires_at: number;
  revoked: boolean;
  last_used_at: number | null;
}

export interface LicenseRow {
  id: number;
  key_hash: string;
  key_prefix: string;
  status: LicenseStatus;
  /** 软件维度：卡密属于哪个产品 */
  product: string;
  max_devices: number;
  max_activations: number;
  activation_days: number;
  max_unbinds: number;
  refund_on_unbind: boolean;
  /** 排期方式：frequency = 按频率等分总时长；interval = 直接指定天数 */
  check_mode: CheckMode;
  /** 校验频率：把 activation_days 等分成 N 段；1 = 不做定期校验（仅 frequency 模式） */
  check_frequency: number;
  /** 直接指定的校验周期天数；0 = 不做定期校验（仅 interval 模式） */
  check_interval_days: number;
  /** 提前提醒比例（%），0 = 不提醒 */
  check_remind_percent: number;
  activation_count: number;
  unbind_count: number;
  created_at: number;
  first_activated_at: number | null;
  expires_at: number | null;
  note: string | null;
}

export interface BindingRow {
  id: number;
  license_id: number;
  device_fp: string;
  device_name: string | null;
  /** 首次激活时间 —— 授权期与校验排期的时间锚点，写入后不可变 */
  first_seen: number;
  last_seen: number;

  /** 本设备授权到期 = first_seen + activation_days（激活时一次算定） */
  entitlement_expires_at: number | null;

  /** 已解析的校验周期（天），0 = 不校验 */
  check_interval_days: number;
  check_frequency: number;
  check_remind_percent: number;
  /** 上次校验时间（激活时 = first_seen） */
  last_check_at: number | null;
  /** 计划下次校验时间；NULL = 不校验 */
  next_check_at: number | null;
  check_state: CheckState;
  overdue_since: number | null;
}

/** 可更新的排期字段 */
export interface BindingSchedulePatch {
  entitlement_expires_at?: number;
  check_frequency?: number;
  check_interval_days?: number;
  check_remind_percent?: number;
  last_check_at?: number;
  next_check_at?: number | null;
  check_state?: CheckState;
  overdue_since?: number | null;
}

/** 创建绑定时的授权与排期参数 */
export interface BindingEntitlement {
  entitlement_expires_at: number;
  check_frequency: number;
  check_interval_days: number;
  check_remind_percent: number;
  last_check_at: number;
  next_check_at: number | null;
}

export interface AuditEntry {
  license_id: number | null;
  event: string;
  device_fp?: string | null;
  ip?: string | null;
  app_version?: string | null;
  detail?: string | null;
  created_at: number;
}

export interface CreateLicenseInput {
  key_hash: string;
  key_prefix: string;
  product: string;
  max_devices: number;
  max_activations: number;
  activation_days: number;
  max_unbinds: number;
  refund_on_unbind: boolean;
  check_mode: CheckMode;
  check_frequency: number;
  check_interval_days: number;
  check_remind_percent: number;
  expires_at: number | null;
  note: string | null;
  created_at: number;
}

export interface ListOptions {
  status?: LicenseStatus | undefined;
  product?: string | undefined;
  q?: string | undefined;
  page: number;
  pageSize: number;
}

export interface Repo {
  init(): Promise<void>;
  close(): Promise<void>;

  createLicense(input: CreateLicenseInput): Promise<LicenseRow>;
  findLicenseByKeyHash(keyHash: string): Promise<LicenseRow | null>;
  findLicenseById(id: number): Promise<LicenseRow | null>;
  findLicensesByPrefix(prefix: string): Promise<LicenseRow[]>;
  listLicenses(opts: ListOptions): Promise<{ rows: LicenseRow[]; total: number }>;
  setLicenseStatus(id: number, status: LicenseStatus): Promise<void>;

  incrementActivation(id: number, at: number): Promise<void>;
  decrementActivation(id: number): Promise<void>;
  incrementUnbind(id: number): Promise<void>;

  listBindings(licenseId: number): Promise<BindingRow[]>;
  findBinding(licenseId: number, deviceFp: string): Promise<BindingRow | null>;
  createBinding(
    licenseId: number, deviceFp: string, deviceName: string | null,
    at: number, entitlement: BindingEntitlement,
  ): Promise<void>;
  deleteBinding(licenseId: number, deviceFp: string): Promise<boolean>;
  touchBinding(licenseId: number, deviceFp: string, at: number): Promise<void>;
  /** 更新某台设备的授权与校验排期 */
  updateBindingSchedule(
    licenseId: number, deviceFp: string, patch: BindingSchedulePatch,
  ): Promise<void>;

  audit(entry: AuditEntry): Promise<void>;
  listAudit(licenseId: number, limit: number): Promise<AuditEntry[]>;

  // ---- 软件注册表 ----
  createProduct(input: CreateProductInput): Promise<ProductRow>;
  findProductByCode(code: string): Promise<ProductRow | null>;
  listProducts(status?: ProductStatus): Promise<ProductRow[]>;
  setProductStatus(code: string, status: ProductStatus): Promise<void>;
  updateProductInfo(code: string, patch: { name?: string; note?: string | null }): Promise<void>;
  /** 客户端上报未知标识时登记为 pending；已存在则只补首次发现信息 */
  registerUnknownProduct(
    code: string, at: number, ip: string | null, appVersion: string | null,
  ): Promise<void>;
  deleteProduct(code: string): Promise<boolean>;

  // ---- 管理员账户 ----
  countAdminUsers(): Promise<number>;
  createAdminUser(input: {
    username: string; password_hash: string; role: AdminRole; created_at: number;
  }): Promise<AdminUserRow>;
  findAdminUser(username: string): Promise<AdminUserRow | null>;
  touchAdminUserLogin(id: number, at: number): Promise<void>;

  // ---- 管理员令牌 ----
  createAdminToken(input: {
    token_hash: string; token_prefix: string; name: string | null;
    role: AdminRole; created_by: string; created_at: number; expires_at: number;
  }): Promise<AdminTokenRow>;
  findAdminTokenByHash(hash: string): Promise<AdminTokenRow | null>;
  listAdminTokens(): Promise<AdminTokenRow[]>;
  revokeAdminToken(id: number): Promise<boolean>;
  touchAdminToken(id: number, at: number): Promise<void>;
  /** 清理已过期或已撤销超过一定时间的令牌记录 */
  purgeAdminTokens(expiredBefore: number): Promise<number>;
}

// ============ 内存实现 ============

export class MemoryRepo implements Repo {
  private licenses = new Map<number, LicenseRow>();
  private bindings: BindingRow[] = [];
  private auditLog: AuditEntry[] = [];
  private products = new Map<string, ProductRow>();
  private adminUsers = new Map<string, AdminUserRow>();
  private adminTokens = new Map<number, AdminTokenRow>();
  private nextLicenseId = 1;
  private nextBindingId = 1;
  private nextProductId = 1;
  private nextAdminUserId = 1;
  private nextAdminTokenId = 1;

  async init(): Promise<void> {
    // 与 sql/schema.sql 的预置数据保持一致，让内存模式也能开箱即用
    if (!this.products.has("license-tester")) {
      this.products.set("license-tester", {
        id: this.nextProductId++,
        code: "license-tester",
        name: "卡密授权测试客户端",
        status: "active",
        note: "仓库内置的测试工具",
        created_at: Math.floor(Date.now() / 1000),
        first_seen_at: null,
        first_seen_ip: null,
        app_version: null,
      });
    }
  }

  async close(): Promise<void> {}

  async createLicense(input: CreateLicenseInput): Promise<LicenseRow> {
    const row: LicenseRow = {
      id: this.nextLicenseId++,
      key_hash: input.key_hash,
      key_prefix: input.key_prefix,
      status: "unused",
      product: input.product,
      max_devices: input.max_devices,
      max_activations: input.max_activations,
      activation_days: input.activation_days,
      max_unbinds: input.max_unbinds,
      refund_on_unbind: input.refund_on_unbind,
      check_mode: input.check_mode,
      check_frequency: input.check_frequency,
      check_interval_days: input.check_interval_days,
      check_remind_percent: input.check_remind_percent,
      activation_count: 0,
      unbind_count: 0,
      created_at: input.created_at,
      first_activated_at: null,
      expires_at: input.expires_at,
      note: input.note,
    };
    this.licenses.set(row.id, row);
    return { ...row };
  }

  async findLicenseByKeyHash(keyHash: string): Promise<LicenseRow | null> {
    for (const row of this.licenses.values()) {
      if (row.key_hash === keyHash) return { ...row };
    }
    return null;
  }

  async findLicenseById(id: number): Promise<LicenseRow | null> {
    const row = this.licenses.get(id);
    return row ? { ...row } : null;
  }

  async findLicensesByPrefix(prefix: string): Promise<LicenseRow[]> {
    const up = prefix.toUpperCase();
    return [...this.licenses.values()]
      .filter((r) => r.key_prefix.startsWith(up))
      .map((r) => ({ ...r }));
  }

  async listLicenses(opts: ListOptions): Promise<{ rows: LicenseRow[]; total: number }> {
    let all = [...this.licenses.values()].sort((a, b) => b.id - a.id);
    if (opts.status) all = all.filter((r) => r.status === opts.status);
    if (opts.product) all = all.filter((r) => r.product === opts.product);
    if (opts.q) {
      const q = opts.q.toUpperCase();
      all = all.filter((r) => r.key_prefix.includes(q) || (r.note ?? "").toUpperCase().includes(q));
    }
    const total = all.length;
    const start = (opts.page - 1) * opts.pageSize;
    return { rows: all.slice(start, start + opts.pageSize).map((r) => ({ ...r })), total };
  }

  async setLicenseStatus(id: number, status: LicenseStatus): Promise<void> {
    const row = this.licenses.get(id);
    if (row) row.status = status;
  }

  async incrementActivation(id: number, at: number): Promise<void> {
    const row = this.licenses.get(id);
    if (!row) return;
    row.activation_count += 1;
    if (row.first_activated_at === null) row.first_activated_at = at;
    if (row.status === "unused") row.status = "active";
  }

  async decrementActivation(id: number): Promise<void> {
    const row = this.licenses.get(id);
    if (!row) return;
    row.activation_count = Math.max(0, row.activation_count - 1);
  }

  async incrementUnbind(id: number): Promise<void> {
    const row = this.licenses.get(id);
    if (row) row.unbind_count += 1;
  }

  async listBindings(licenseId: number): Promise<BindingRow[]> {
    return this.bindings.filter((b) => b.license_id === licenseId).map((b) => ({ ...b }));
  }

  async findBinding(licenseId: number, deviceFp: string): Promise<BindingRow | null> {
    const b = this.bindings.find((x) => x.license_id === licenseId && x.device_fp === deviceFp);
    return b ? { ...b } : null;
  }

  async createBinding(
    licenseId: number, deviceFp: string, deviceName: string | null,
    at: number, entitlement: BindingEntitlement,
  ): Promise<void> {
    this.bindings.push({
      id: this.nextBindingId++,
      license_id: licenseId,
      device_fp: deviceFp,
      device_name: deviceName,
      first_seen: at,
      last_seen: at,
      entitlement_expires_at: entitlement.entitlement_expires_at,
      check_frequency: entitlement.check_frequency,
      check_interval_days: entitlement.check_interval_days,
      check_remind_percent: entitlement.check_remind_percent,
      last_check_at: entitlement.last_check_at,
      next_check_at: entitlement.next_check_at,
      check_state: "active",
      overdue_since: null,
    });
  }

  async updateBindingSchedule(
    licenseId: number, deviceFp: string, patch: BindingSchedulePatch,
  ): Promise<void> {
    const b = this.bindings.find((x) => x.license_id === licenseId && x.device_fp === deviceFp);
    if (!b) return;
    if (patch.entitlement_expires_at !== undefined) b.entitlement_expires_at = patch.entitlement_expires_at;
    if (patch.check_frequency !== undefined) b.check_frequency = patch.check_frequency;
    if (patch.check_interval_days !== undefined) b.check_interval_days = patch.check_interval_days;
    if (patch.check_remind_percent !== undefined) b.check_remind_percent = patch.check_remind_percent;
    if (patch.last_check_at !== undefined) b.last_check_at = patch.last_check_at;
    if (patch.next_check_at !== undefined) b.next_check_at = patch.next_check_at;
    if (patch.check_state !== undefined) b.check_state = patch.check_state;
    if (patch.overdue_since !== undefined) b.overdue_since = patch.overdue_since;
  }

  async deleteBinding(licenseId: number, deviceFp: string): Promise<boolean> {
    const before = this.bindings.length;
    this.bindings = this.bindings.filter(
      (b) => !(b.license_id === licenseId && b.device_fp === deviceFp),
    );
    return this.bindings.length < before;
  }

  async touchBinding(licenseId: number, deviceFp: string, at: number): Promise<void> {
    const b = this.bindings.find((x) => x.license_id === licenseId && x.device_fp === deviceFp);
    if (b) b.last_seen = at;
  }

  async audit(entry: AuditEntry): Promise<void> {
    this.auditLog.push({ ...entry });
  }

  async listAudit(licenseId: number, limit: number): Promise<AuditEntry[]> {
    return this.auditLog
      .filter((a) => a.license_id === licenseId)
      .slice(-limit)
      .reverse()
      .map((a) => ({ ...a }));
  }

  // ---- 软件注册表 ----

  async createProduct(input: CreateProductInput): Promise<ProductRow> {
    const row: ProductRow = {
      id: this.nextProductId++,
      code: input.code,
      name: input.name,
      status: input.status,
      note: input.note,
      created_at: input.created_at,
      first_seen_at: null,
      first_seen_ip: null,
      app_version: null,
    };
    this.products.set(row.code, row);
    return { ...row };
  }

  async findProductByCode(code: string): Promise<ProductRow | null> {
    const p = this.products.get(code);
    return p ? { ...p } : null;
  }

  async listProducts(status?: ProductStatus): Promise<ProductRow[]> {
    return [...this.products.values()]
      .filter((p) => status === undefined || p.status === status)
      .sort((a, b) => a.code.localeCompare(b.code))
      .map((p) => ({ ...p }));
  }

  async setProductStatus(code: string, status: ProductStatus): Promise<void> {
    const p = this.products.get(code);
    if (p) p.status = status;
  }

  async updateProductInfo(code: string, patch: { name?: string; note?: string | null }): Promise<void> {
    const p = this.products.get(code);
    if (!p) return;
    if (patch.name !== undefined) p.name = patch.name;
    if (patch.note !== undefined) p.note = patch.note;
  }

  async registerUnknownProduct(
    code: string, at: number, ip: string | null, appVersion: string | null,
  ): Promise<void> {
    const existing = this.products.get(code);
    if (existing) {
      if (existing.first_seen_at === null) {
        existing.first_seen_at = at;
        existing.first_seen_ip = ip;
        existing.app_version = appVersion;
      }
      return;
    }
    this.products.set(code, {
      id: this.nextProductId++,
      code,
      name: code,
      status: "pending",
      note: null,
      created_at: at,
      first_seen_at: at,
      first_seen_ip: ip,
      app_version: appVersion,
    });
  }

  async deleteProduct(code: string): Promise<boolean> {
    return this.products.delete(code);
  }

  // ---- 管理员账户 ----

  async countAdminUsers(): Promise<number> {
    return this.adminUsers.size;
  }

  async createAdminUser(input: {
    username: string; password_hash: string; role: AdminRole; created_at: number;
  }): Promise<AdminUserRow> {
    const row: AdminUserRow = {
      id: this.nextAdminUserId++,
      username: input.username,
      password_hash: input.password_hash,
      role: input.role,
      disabled: false,
      created_at: input.created_at,
      last_login_at: null,
    };
    this.adminUsers.set(row.username, row);
    return { ...row };
  }

  async findAdminUser(username: string): Promise<AdminUserRow | null> {
    const u = this.adminUsers.get(username);
    return u ? { ...u } : null;
  }

  async touchAdminUserLogin(id: number, at: number): Promise<void> {
    for (const u of this.adminUsers.values()) {
      if (u.id === id) u.last_login_at = at;
    }
  }

  // ---- 管理员令牌 ----

  async createAdminToken(input: {
    token_hash: string; token_prefix: string; name: string | null;
    role: AdminRole; created_by: string; created_at: number; expires_at: number;
  }): Promise<AdminTokenRow> {
    const row: AdminTokenRow = {
      id: this.nextAdminTokenId++,
      token_hash: input.token_hash,
      token_prefix: input.token_prefix,
      name: input.name,
      role: input.role,
      created_by: input.created_by,
      created_at: input.created_at,
      expires_at: input.expires_at,
      revoked: false,
      last_used_at: null,
    };
    this.adminTokens.set(row.id, row);
    return { ...row };
  }

  async findAdminTokenByHash(hash: string): Promise<AdminTokenRow | null> {
    for (const t of this.adminTokens.values()) {
      if (t.token_hash === hash) return { ...t };
    }
    return null;
  }

  async listAdminTokens(): Promise<AdminTokenRow[]> {
    return [...this.adminTokens.values()]
      .sort((a, b) => b.id - a.id)
      .map((t) => ({ ...t }));
  }

  async revokeAdminToken(id: number): Promise<boolean> {
    const t = this.adminTokens.get(id);
    if (!t) return false;
    t.revoked = true;
    return true;
  }

  async touchAdminToken(id: number, at: number): Promise<void> {
    const t = this.adminTokens.get(id);
    if (t) t.last_used_at = at;
  }

  async purgeAdminTokens(expiredBefore: number): Promise<number> {
    let n = 0;
    for (const [id, t] of this.adminTokens) {
      if (t.expires_at < expiredBefore) {
        this.adminTokens.delete(id);
        n++;
      }
    }
    return n;
  }
}

// ============ PostgreSQL 实现 ============

export class PgRepo implements Repo {
  private pool: pg.Pool;
  private sslEnabled: boolean;
  private readonly connectionString: string;

  constructor(connectionString: string, sslMode: "auto" | "disable" | "require" = "auto") {
    this.connectionString = connectionString;
    // auto：URL 里写了 sslmode=disable 就不开 SSL，否则开
    this.sslEnabled = sslMode === "require"
      || (sslMode === "auto" && !/sslmode=disable/.test(connectionString));

    this.pool = this.makePool(connectionString, this.sslEnabled);
  }

  private makePool(connectionString: string, ssl: boolean): pg.Pool {
    return new pg.Pool({
      connectionString,
      max: 5,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 10_000,
      ssl: ssl ? { rejectUnauthorized: false } : false,
    });
  }

  async init(): Promise<void> {
    const here = dirname(fileURLToPath(import.meta.url));
    // 编译后 dist/repo.js → ../sql/schema.sql
    const schemaPath = join(here, "..", "sql", "schema.sql");
    const sql = readFileSync(schemaPath, "utf8");

    try {
      await this.pool.query(sql);
      return;
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);

      // 托管平台的内网数据库通常不支持 SSL，而外部数据库通常强制 SSL。
      // 与其让用户猜该不该开，不如按错误自动降级重试一次。
      const sslMismatch = /does not support SSL/i.test(msg)
        || /SSL required/i.test(msg)
        || /no pg_hba.conf entry/i.test(msg);

      if (sslMismatch && this.connectionString !== "") {
        const retrySsl = !this.sslEnabled;
        console.warn(`[db] 连接失败（${msg}），改用 ssl=${retrySsl} 重试`);

        await this.pool.end().catch(() => undefined);
        this.sslEnabled = retrySsl;
        this.pool = this.makePool(this.connectionString, retrySsl);
        await this.pool.query(sql);
        return;
      }

      // 其它错误：整批多语句查询在 Postgres 里是隐式事务，
      // 一条失败会全部回滚 —— 迁移等于没做，还很难定位。
      // 这里退化成逐条执行：单条失败只记录，其余照常生效。
      console.warn(`[db] 整批建表失败（${msg}），改为逐条执行`);
      await this.execStatementByStatement(sql);
    }
  }

  /** 逐条执行 schema；单条失败不中断，最后把失败项一次性报出来 */
  private async execStatementByStatement(sql: string): Promise<void> {
    const statements = sql
      .split(/;\s*(?:\r?\n|$)/)
      .map((s) => s.trim())
      .filter((s) => s !== "");

    const failures: string[] = [];
    for (const stmt of statements) {
      try {
        await this.pool.query(stmt);
      } catch (e) {
        const head = stmt.replace(/\s+/g, " ").slice(0, 70);
        failures.push(`${head}… → ${e instanceof Error ? e.message : String(e)}`);
      }
    }

    if (failures.length > 0) {
      throw new Error(`建表有 ${failures.length} 条语句失败：\n` + failures.join("\n"));
    }
  }

  async close(): Promise<void> {
    await this.pool.end();
  }

  async createLicense(input: CreateLicenseInput): Promise<LicenseRow> {
    const { rows } = await this.pool.query<LicenseRow>(
      `INSERT INTO licenses
         (key_hash, key_prefix, product, status, max_devices, max_activations, activation_days,
          max_unbinds, refund_on_unbind, check_mode, check_frequency, check_interval_days,
          check_remind_percent, activation_count, unbind_count,
          created_at, first_activated_at, expires_at, note)
       VALUES ($1,$2,$3,'unused',$4,$5,$6,$7,$8,$9,$10,$11,$12,0,0,$13,NULL,$14,$15)
       RETURNING *`,
      [
        input.key_hash, input.key_prefix, input.product,
        input.max_devices, input.max_activations,
        input.activation_days, input.max_unbinds, input.refund_on_unbind,
        input.check_mode, input.check_frequency, input.check_interval_days,
        input.check_remind_percent,
        input.created_at, input.expires_at, input.note,
      ],
    );
    return rows[0]!;
  }

  async findLicenseByKeyHash(keyHash: string): Promise<LicenseRow | null> {
    const { rows } = await this.pool.query<LicenseRow>(
      `SELECT * FROM licenses WHERE key_hash = $1 LIMIT 1`, [keyHash],
    );
    return rows[0] ?? null;
  }

  async findLicenseById(id: number): Promise<LicenseRow | null> {
    const { rows } = await this.pool.query<LicenseRow>(
      `SELECT * FROM licenses WHERE id = $1 LIMIT 1`, [id],
    );
    return rows[0] ?? null;
  }

  async findLicensesByPrefix(prefix: string): Promise<LicenseRow[]> {
    const { rows } = await this.pool.query<LicenseRow>(
      `SELECT * FROM licenses WHERE key_prefix LIKE $1 ORDER BY id DESC LIMIT 50`,
      [`${prefix.toUpperCase()}%`],
    );
    return rows;
  }

  async listLicenses(opts: ListOptions): Promise<{ rows: LicenseRow[]; total: number }> {
    const where: string[] = [];
    const params: unknown[] = [];

    if (opts.status) {
      params.push(opts.status);
      where.push(`status = $${params.length}`);
    }
    if (opts.product) {
      params.push(opts.product);
      where.push(`product = $${params.length}`);
    }
    if (opts.q) {
      params.push(`%${opts.q.toUpperCase()}%`);
      where.push(`(key_prefix LIKE $${params.length} OR UPPER(COALESCE(note,'')) LIKE $${params.length})`);
    }
    const whereSql = where.length > 0 ? `WHERE ${where.join(" AND ")}` : "";

    const countRes = await this.pool.query<{ n: number }>(
      `SELECT COUNT(*)::int AS n FROM licenses ${whereSql}`, params,
    );

    const listParams = [...params, opts.pageSize, (opts.page - 1) * opts.pageSize];
    const { rows } = await this.pool.query<LicenseRow>(
      `SELECT * FROM licenses ${whereSql}
       ORDER BY id DESC
       LIMIT $${listParams.length - 1} OFFSET $${listParams.length}`,
      listParams,
    );

    return { rows, total: countRes.rows[0]?.n ?? 0 };
  }

  async setLicenseStatus(id: number, status: LicenseStatus): Promise<void> {
    await this.pool.query(`UPDATE licenses SET status = $2 WHERE id = $1`, [id, status]);
  }

  async incrementActivation(id: number, at: number): Promise<void> {
    await this.pool.query(
      `UPDATE licenses
          SET activation_count = activation_count + 1,
              first_activated_at = COALESCE(first_activated_at, $2),
              status = CASE WHEN status = 'unused' THEN 'active' ELSE status END
        WHERE id = $1`,
      [id, at],
    );
  }

  async decrementActivation(id: number): Promise<void> {
    await this.pool.query(
      `UPDATE licenses SET activation_count = GREATEST(0, activation_count - 1) WHERE id = $1`,
      [id],
    );
  }

  async incrementUnbind(id: number): Promise<void> {
    await this.pool.query(
      `UPDATE licenses SET unbind_count = unbind_count + 1 WHERE id = $1`, [id],
    );
  }

  async listBindings(licenseId: number): Promise<BindingRow[]> {
    const { rows } = await this.pool.query<BindingRow>(
      `SELECT * FROM bindings WHERE license_id = $1 ORDER BY id`, [licenseId],
    );
    return rows;
  }

  async findBinding(licenseId: number, deviceFp: string): Promise<BindingRow | null> {
    const { rows } = await this.pool.query<BindingRow>(
      `SELECT * FROM bindings WHERE license_id = $1 AND device_fp = $2 LIMIT 1`,
      [licenseId, deviceFp],
    );
    return rows[0] ?? null;
  }

  async createBinding(
    licenseId: number, deviceFp: string, deviceName: string | null,
    at: number, entitlement: BindingEntitlement,
  ): Promise<void> {
    await this.pool.query(
      `INSERT INTO bindings
         (license_id, device_fp, device_name, first_seen, last_seen,
          entitlement_expires_at, check_frequency, check_interval_days, check_remind_percent,
          last_check_at, next_check_at, check_state, overdue_since)
       VALUES ($1,$2,$3,$4,$4,$5,$6,$7,$8,$9,$10,'active',NULL)
       ON CONFLICT (license_id, device_fp) DO UPDATE
         SET last_seen = $4,
             entitlement_expires_at = $5,
             check_frequency = $6,
             check_interval_days = $7,
             check_remind_percent = $8,
             last_check_at = $9,
             next_check_at = $10,
             check_state = 'active',
             overdue_since = NULL`,
      [
        licenseId, deviceFp, deviceName, at,
        entitlement.entitlement_expires_at,
        entitlement.check_frequency,
        entitlement.check_interval_days,
        entitlement.check_remind_percent,
        entitlement.last_check_at,
        entitlement.next_check_at,
      ],
    );
  }

  async updateBindingSchedule(
    licenseId: number, deviceFp: string, patch: BindingSchedulePatch,
  ): Promise<void> {
    const map: Record<string, unknown> = {
      entitlement_expires_at: patch.entitlement_expires_at,
      check_frequency: patch.check_frequency,
      check_interval_days: patch.check_interval_days,
      check_remind_percent: patch.check_remind_percent,
      last_check_at: patch.last_check_at,
      next_check_at: patch.next_check_at,
      check_state: patch.check_state,
      overdue_since: patch.overdue_since,
    };

    const sets: string[] = [];
    const params: unknown[] = [licenseId, deviceFp];
    for (const [col, val] of Object.entries(map)) {
      if (val === undefined) continue;
      params.push(val);
      sets.push(`${col} = $${params.length}`);
    }
    if (sets.length === 0) return;

    await this.pool.query(
      `UPDATE bindings SET ${sets.join(", ")} WHERE license_id = $1 AND device_fp = $2`,
      params,
    );
  }

  async deleteBinding(licenseId: number, deviceFp: string): Promise<boolean> {
    const res = await this.pool.query(
      `DELETE FROM bindings WHERE license_id = $1 AND device_fp = $2`,
      [licenseId, deviceFp],
    );
    return (res.rowCount ?? 0) > 0;
  }

  async touchBinding(licenseId: number, deviceFp: string, at: number): Promise<void> {
    await this.pool.query(
      `UPDATE bindings SET last_seen = $3 WHERE license_id = $1 AND device_fp = $2`,
      [licenseId, deviceFp, at],
    );
  }

  async audit(entry: AuditEntry): Promise<void> {
    await this.pool.query(
      `INSERT INTO audit_log (license_id, event, device_fp, ip, app_version, detail, created_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [
        entry.license_id, entry.event, entry.device_fp ?? null, entry.ip ?? null,
        entry.app_version ?? null, entry.detail ?? null, entry.created_at,
      ],
    );
  }

  async listAudit(licenseId: number, limit: number): Promise<AuditEntry[]> {
    const { rows } = await this.pool.query<AuditEntry>(
      `SELECT * FROM audit_log WHERE license_id = $1 ORDER BY created_at DESC LIMIT $2`,
      [licenseId, limit],
    );
    return rows;
  }

  // ---- 软件注册表 ----

  async createProduct(input: CreateProductInput): Promise<ProductRow> {
    const { rows } = await this.pool.query<ProductRow>(
      `INSERT INTO products (code, name, status, note, created_at)
       VALUES ($1,$2,$3,$4,$5)
       RETURNING *`,
      [input.code, input.name, input.status, input.note, input.created_at],
    );
    return rows[0]!;
  }

  async findProductByCode(code: string): Promise<ProductRow | null> {
    const { rows } = await this.pool.query<ProductRow>(
      `SELECT * FROM products WHERE code = $1 LIMIT 1`, [code],
    );
    return rows[0] ?? null;
  }

  async listProducts(status?: ProductStatus): Promise<ProductRow[]> {
    if (status) {
      const { rows } = await this.pool.query<ProductRow>(
        `SELECT * FROM products WHERE status = $1 ORDER BY code`, [status],
      );
      return rows;
    }
    const { rows } = await this.pool.query<ProductRow>(
      `SELECT * FROM products ORDER BY
         CASE status WHEN 'pending' THEN 0 WHEN 'active' THEN 1 ELSE 2 END, code`,
    );
    return rows;
  }

  async setProductStatus(code: string, status: ProductStatus): Promise<void> {
    await this.pool.query(`UPDATE products SET status = $2 WHERE code = $1`, [code, status]);
  }

  async updateProductInfo(code: string, patch: { name?: string; note?: string | null }): Promise<void> {
    const sets: string[] = [];
    const params: unknown[] = [code];
    if (patch.name !== undefined) {
      params.push(patch.name);
      sets.push(`name = $${params.length}`);
    }
    if (patch.note !== undefined) {
      params.push(patch.note);
      sets.push(`note = $${params.length}`);
    }
    if (sets.length === 0) return;
    await this.pool.query(`UPDATE products SET ${sets.join(", ")} WHERE code = $1`, params);
  }

  async registerUnknownProduct(
    code: string, at: number, ip: string | null, appVersion: string | null,
  ): Promise<void> {
    // 已存在则只补首次发现信息，绝不覆盖状态（管理员确认过的不能被降级）
    await this.pool.query(
      `INSERT INTO products (code, name, status, created_at, first_seen_at, first_seen_ip, app_version)
       VALUES ($1,$1,'pending',$2,$2,$3,$4)
       ON CONFLICT (code) DO UPDATE
         SET first_seen_at = COALESCE(products.first_seen_at, EXCLUDED.first_seen_at),
             first_seen_ip = COALESCE(products.first_seen_ip, EXCLUDED.first_seen_ip),
             app_version   = COALESCE(products.app_version, EXCLUDED.app_version)`,
      [code, at, ip, appVersion],
    );
  }

  async deleteProduct(code: string): Promise<boolean> {
    const res = await this.pool.query(`DELETE FROM products WHERE code = $1`, [code]);
    return (res.rowCount ?? 0) > 0;
  }

  // ---- 管理员账户 ----

  async countAdminUsers(): Promise<number> {
    const { rows } = await this.pool.query<{ n: number }>(
      `SELECT COUNT(*)::int AS n FROM admin_users`,
    );
    return rows[0]?.n ?? 0;
  }

  async createAdminUser(input: {
    username: string; password_hash: string; role: AdminRole; created_at: number;
  }): Promise<AdminUserRow> {
    const { rows } = await this.pool.query<AdminUserRow>(
      `INSERT INTO admin_users (username, password_hash, role, created_at)
       VALUES ($1,$2,$3,$4) RETURNING *`,
      [input.username, input.password_hash, input.role, input.created_at],
    );
    return rows[0]!;
  }

  async findAdminUser(username: string): Promise<AdminUserRow | null> {
    const { rows } = await this.pool.query<AdminUserRow>(
      `SELECT * FROM admin_users WHERE username = $1 LIMIT 1`, [username],
    );
    return rows[0] ?? null;
  }

  async touchAdminUserLogin(id: number, at: number): Promise<void> {
    await this.pool.query(`UPDATE admin_users SET last_login_at = $2 WHERE id = $1`, [id, at]);
  }

  // ---- 管理员令牌 ----

  async createAdminToken(input: {
    token_hash: string; token_prefix: string; name: string | null;
    role: AdminRole; created_by: string; created_at: number; expires_at: number;
  }): Promise<AdminTokenRow> {
    const { rows } = await this.pool.query<AdminTokenRow>(
      `INSERT INTO admin_tokens
         (token_hash, token_prefix, name, role, created_by, created_at, expires_at, revoked)
       VALUES ($1,$2,$3,$4,$5,$6,$7,FALSE)
       RETURNING *`,
      [
        input.token_hash, input.token_prefix, input.name, input.role,
        input.created_by, input.created_at, input.expires_at,
      ],
    );
    return rows[0]!;
  }

  async findAdminTokenByHash(hash: string): Promise<AdminTokenRow | null> {
    const { rows } = await this.pool.query<AdminTokenRow>(
      `SELECT * FROM admin_tokens WHERE token_hash = $1 LIMIT 1`, [hash],
    );
    return rows[0] ?? null;
  }

  async listAdminTokens(): Promise<AdminTokenRow[]> {
    const { rows } = await this.pool.query<AdminTokenRow>(
      `SELECT * FROM admin_tokens ORDER BY id DESC LIMIT 200`,
    );
    return rows;
  }

  async revokeAdminToken(id: number): Promise<boolean> {
    const res = await this.pool.query(
      `UPDATE admin_tokens SET revoked = TRUE WHERE id = $1 AND revoked = FALSE`, [id],
    );
    return (res.rowCount ?? 0) > 0;
  }

  async touchAdminToken(id: number, at: number): Promise<void> {
    await this.pool.query(`UPDATE admin_tokens SET last_used_at = $2 WHERE id = $1`, [id, at]);
  }

  async purgeAdminTokens(expiredBefore: number): Promise<number> {
    const res = await this.pool.query(
      `DELETE FROM admin_tokens WHERE expires_at < $1 OR (revoked = TRUE AND created_at < $1)`,
      [expiredBefore],
    );
    return res.rowCount ?? 0;
  }
}

export function createRepo(driver: "pg" | "memory", databaseUrl: string): Repo {
  return driver === "pg" ? new PgRepo(databaseUrl) : new MemoryRepo();
}
