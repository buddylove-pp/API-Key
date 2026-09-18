/**
 * 配置读取与环境变量校验
 * 启动即校验，缺少必需项直接崩溃 —— 不允许带着坏配置跑起来
 */

function required(name: string): string {
  const v = process.env[name];
  if (v === undefined || v.trim() === "") {
    throw new Error(`缺少必需的环境变量: ${name}`);
  }
  return v.trim();
}

function optional(name: string, fallback: string): string {
  const v = process.env[name];
  return v !== undefined && v.trim() !== "" ? v.trim() : fallback;
}

function num(name: string, fallback: number): number {
  const v = process.env[name];
  if (v === undefined || v.trim() === "") return fallback;
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function bool(name: string, fallback: boolean): boolean {
  const v = process.env[name];
  if (v === undefined || v.trim() === "") return fallback;
  return /^(1|true|yes|on)$/i.test(v.trim());
}

/**
 * 环境变量里的 PEM 换行常被写成字面量 \n，这里还原成真实换行。
 * 同时兼容已经带真实换行的情况。
 */
function normalizePem(raw: string): string {
  const s = raw.includes("\\n") ? raw.replace(/\\n/g, "\n") : raw;
  return s.trim() + "\n";
}

const dbDriver = optional("DB_DRIVER", "memory");

export const config = {
  port: num("PORT", 8080),

  /** pg = PostgreSQL（生产）；memory = 内存（本地开发，重启丢数据） */
  dbDriver: (dbDriver === "pg" ? "pg" : "memory") as "pg" | "memory",

  databaseUrl: optional("DATABASE_URL", ""),

  /** 管理接口令牌 */
  adminToken: required("ADMIN_TOKEN"),

  /**
   * 管理后台的 HTTP Basic Auth 登录门，格式 `用户名:密码`。
   * 留空则不启用。设置后浏览器打开 /admin 会弹原生登录框。
   * 与 ADMIN_TOKEN 是两层独立防护，建议都开。
   */
  adminBasicAuth: optional("ADMIN_BASIC_AUTH", ""),

  /**
   * 首次启动时用于创建 root 账户。
   * ⚠️ 只在 admin_users 表为空时生效；账户已存在则忽略，
   *    所以改密码必须走后台，改这里不会覆盖。
   */
  adminUsername: optional("ADMIN_USERNAME", ""),
  adminPassword: optional("ADMIN_PASSWORD", ""),

  /** 票据签名私钥（PKCS#8 PEM）。私钥泄露 = 授权系统失效，只放服务端环境变量 */
  ticketPrivateKeyPem: normalizePem(required("TICKET_PRIVATE_KEY_PEM")),

  publicBaseUrl: optional("PUBLIC_BASE_URL", ""),
  autoMigrate: bool("AUTO_MIGRATE", true),

  /**
   * 票据（离线容忍窗口）最大天数。
   * 票据有效期同时受「下次校验时间」与「授权到期」约束，这里只是兜底上限。
   * 调大 = 更能容忍断网，但用户也能更久不联网；默认 7 天。
   */
  ticketMaxTtlDays: num("TICKET_MAX_TTL_DAYS", 7),

  rateLimitMax: num("RATE_LIMIT_MAX", 60),
  rateLimitWindowSec: num("RATE_LIMIT_WINDOW_SEC", 60),

  /** 票据协议版本，客户端需校验 */
  ticketVersion: 1 as const,
} as const;

export function validateConfig(): void {
  if (config.dbDriver === "pg" && config.databaseUrl === "") {
    throw new Error("DB_DRIVER=pg 时必须提供 DATABASE_URL");
  }
  if (config.adminToken.length < 24) {
    throw new Error("ADMIN_TOKEN 太短，请使用至少 32 位随机字符串");
  }
  if (!config.ticketPrivateKeyPem.includes("BEGIN PRIVATE KEY")) {
    throw new Error("TICKET_PRIVATE_KEY_PEM 不是合法的 PKCS#8 PEM 私钥");
  }
  if (config.adminBasicAuth !== "" && !config.adminBasicAuth.includes(":")) {
    throw new Error("ADMIN_BASIC_AUTH 格式应为 `用户名:密码`");
  }
}
