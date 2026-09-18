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

// node-postgres 默认把 BIGINT 当字符串返回，这里统一转成 number
pg.types.setTypeParser(20, (v: string) => Number(v));

// ============ 类型 ============

export type LicenseStatus = "unused" | "active" | "banned";

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
  first_seen: number;
  last_seen: number;
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
  createBinding(licenseId: number, deviceFp: string, deviceName: string | null, at: number): Promise<void>;
  deleteBinding(licenseId: number, deviceFp: string): Promise<boolean>;
  touchBinding(licenseId: number, deviceFp: string, at: number): Promise<void>;

  audit(entry: AuditEntry): Promise<void>;
  listAudit(licenseId: number, limit: number): Promise<AuditEntry[]>;
}

// ============ 内存实现 ============

export class MemoryRepo implements Repo {
  private licenses = new Map<number, LicenseRow>();
  private bindings: BindingRow[] = [];
  private auditLog: AuditEntry[] = [];
  private nextLicenseId = 1;
  private nextBindingId = 1;

  async init(): Promise<void> {}

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

  async createBinding(licenseId: number, deviceFp: string, deviceName: string | null, at: number): Promise<void> {
    this.bindings.push({
      id: this.nextBindingId++,
      license_id: licenseId,
      device_fp: deviceFp,
      device_name: deviceName,
      first_seen: at,
      last_seen: at,
    });
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
}

// ============ PostgreSQL 实现 ============

export class PgRepo implements Repo {
  private pool: pg.Pool;

  constructor(connectionString: string) {
    this.pool = new pg.Pool({
      connectionString,
      max: 5,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 10_000,
      // 托管数据库通常要求 TLS；本地/内网可放宽
      ssl: /sslmode=disable/.test(connectionString) ? false : { rejectUnauthorized: false },
    });
  }

  async init(): Promise<void> {
    const here = dirname(fileURLToPath(import.meta.url));
    // 编译后 dist/repo.js → ../sql/schema.sql
    const schemaPath = join(here, "..", "sql", "schema.sql");
    const sql = readFileSync(schemaPath, "utf8");
    await this.pool.query(sql);
  }

  async close(): Promise<void> {
    await this.pool.end();
  }

  async createLicense(input: CreateLicenseInput): Promise<LicenseRow> {
    const { rows } = await this.pool.query<LicenseRow>(
      `INSERT INTO licenses
         (key_hash, key_prefix, product, status, max_devices, max_activations, activation_days,
          max_unbinds, refund_on_unbind, activation_count, unbind_count,
          created_at, first_activated_at, expires_at, note)
       VALUES ($1,$2,$3,'unused',$4,$5,$6,$7,$8,0,0,$9,NULL,$10,$11)
       RETURNING *`,
      [
        input.key_hash, input.key_prefix, input.product,
        input.max_devices, input.max_activations,
        input.activation_days, input.max_unbinds, input.refund_on_unbind,
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

  async createBinding(licenseId: number, deviceFp: string, deviceName: string | null, at: number): Promise<void> {
    await this.pool.query(
      `INSERT INTO bindings (license_id, device_fp, device_name, first_seen, last_seen)
       VALUES ($1,$2,$3,$4,$4)
       ON CONFLICT (license_id, device_fp) DO UPDATE SET last_seen = $4`,
      [licenseId, deviceFp, deviceName, at],
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
}

export function createRepo(driver: "pg" | "memory", databaseUrl: string): Repo {
  return driver === "pg" ? new PgRepo(databaseUrl) : new MemoryRepo();
}
