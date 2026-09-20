/**
 * 管理员认证：角色定义、密码哈希、令牌生成
 *
 * 密码用 scrypt（内存硬，抗 GPU 暴力），令牌用 256 bit 随机。
 * 两者都只存哈希，明文永不落库。
 */

import { createHash, randomBytes, scryptSync, timingSafeEqual } from "node:crypto";

// ============ 角色 ============

export type AdminRole =
  | "root_plus"
  | "root"
  | "operator_plus"
  | "operator"
  | "readonly";

/** 权限从低到高 */
export const ROLE_RANK: Record<AdminRole, number> = {
  readonly: 1,
  operator: 2,
  operator_plus: 3,
  root: 4,
  root_plus: 5,
};

/** 全部可签发等级，从低到高（给前端下拉用） */
export const ISSUABLE_ROLES: AdminRole[] = [
  "readonly",
  "operator",
  "operator_plus",
  "root",
  "root_plus",
];

/**
 * 权限等级。
 *
 * ⚠️ 一共 6 个层级，只有 5 个能被令牌承载：
 *
 *   第 6 级  账户密码登录的会话 —— 唯一能签发/撤销令牌的身份
 *   第 5 级  管理+令牌   root_plus
 *   第 4 级  管理令牌    root
 *   第 3 级  运营+令牌   operator_plus
 *   第 2 级  运营令牌    operator
 *   第 1 级  只读令牌    readonly
 *
 * 令牌一律**不能签发令牌**（否则一次泄露就能无限复制权限）。
 * 所以最高一级令牌叫「管理+」而不是「最高权限」——
 * 那会让人误以为它能签发令牌。
 *
 * 分级依据是「操作可不可逆」+「参数上限」两条线：
 *   只读     → 只能看
 *   运营     → 只做可逆的日常操作（发卡、解绑、催校验）
 *   运营+    → 同上，但卡密参数上限更高
 *   管理     → 才允许破坏性操作（封禁用户、增删改软件）
 *   管理+    → 才允许**不可逆**操作（删除卡密）
 */
export const ROLE_LABEL: Record<AdminRole, string> = {
  readonly: "只读",
  operator: "运营",
  operator_plus: "运营+",
  root: "管理",
  root_plus: "管理+",
};

export const ROLE_DESC: Record<AdminRole, string> = {
  readonly: "只能查看卡密、软件、日志与统计，不能做任何修改",
  operator: "可生成卡密、解绑设备、下发强制校验；不能封禁用户，也不能增删改软件",
  operator_plus: "运营的全部权限，卡密参数上限更高；仍不能封禁用户、不能增删改软件",
  root: "运营+ 的全部权限，另可封禁/解封卡密、增删改软件；但不能删除卡密，也不能签发令牌",
  root_plus: "管理的全部权限，另可删除卡密；但仍不能签发令牌",
};

export function isAdminRole(v: unknown): v is AdminRole {
  // 用 ROLE_RANK 查表而不是硬编码枚举 ——
  // 以后再加等级时不会漏掉这里
  return typeof v === "string" && Object.prototype.hasOwnProperty.call(ROLE_RANK, v);
}

// ============ 角色限额 ============

/**
 * 一个身份能做什么、能设多大。
 *
 * 设计原则：**权限越高的身份能设的授权参数越大，逐级递减**。
 * 这样即使某个下级令牌泄露，攻击者能造成的最大伤害也是有限的 ——
 * 比如运营令牌最多只能发 90 天的卡密，发不出"永久授权"。
 *
 * ⚠️ 这里只是**上限**。真正的把关在服务端 `generate` 路由里，
 *    前端设的 max 属性只是提示，不能当防线。
 */
export interface RoleLimits {
  /** 能否生成卡密 */
  canGenerate: boolean;
  /** 一次最多生成多少张 */
  maxGenerateCount: number;
  /** 卡密的「同时绑定设备数」上限 */
  maxDevices: number;
  /** 卡密的「可激活次数」上限 */
  maxActivations: number;
  /** 卡密的「每次激活授予天数」上限 */
  maxActivationDays: number;
  /** 卡密的「可解绑次数」上限 */
  maxUnbinds: number;
  /**
   * 是否允许把「卡密绝对有效期」留空（= 永久有效）。
   *
   * 只有账户密码登录能发永久卡密 —— 这是最有价值的一种卡密，
   * 不该让下级令牌随手发出去。
   */
  allowUnlimitedExpiry: boolean;
  /** 能签发的令牌有效期上限（秒）。0 = 不能签发令牌 */
  maxTokenTtlSeconds: number;
}

/** 只读：只能看，什么都做不了 */
const READONLY_LIMITS: RoleLimits = {
  canGenerate: false,
  maxGenerateCount: 0,
  maxDevices: 0,
  maxActivations: 0,
  maxActivationDays: 0,
  maxUnbinds: 0,
  allowUnlimitedExpiry: false,
  maxTokenTtlSeconds: 0,
};

/** 运营：能发卡，但都是「短期、小规模」的 */
const OPERATOR_LIMITS: RoleLimits = {
  canGenerate: true,
  maxGenerateCount: 50,
  maxDevices: 1,
  maxActivations: 5,
  maxActivationDays: 90,
  maxUnbinds: 3,
  allowUnlimitedExpiry: false,
  maxTokenTtlSeconds: 0,
};

/** 运营+：权限与运营相同，只是卡密参数上限高一档 */
const OPERATOR_PLUS_LIMITS: RoleLimits = {
  canGenerate: true,
  maxGenerateCount: 100,
  maxDevices: 2,
  maxActivations: 8,
  maxActivationDays: 180,
  maxUnbinds: 4,
  allowUnlimitedExpiry: false,
  maxTokenTtlSeconds: 0,
};

/** 管理：可做破坏性操作（封禁用户、增删改软件），参数上限再高一档 */
const ROOT_LIMITS: RoleLimits = {
  canGenerate: true,
  maxGenerateCount: 200,
  maxDevices: 3,
  maxActivations: 10,
  maxActivationDays: 365,
  maxUnbinds: 5,
  allowUnlimitedExpiry: false,
  maxTokenTtlSeconds: 0,
};

/** 管理+：可做不可逆操作（删除卡密），参数上限最高 */
const ROOT_PLUS_LIMITS: RoleLimits = {
  canGenerate: true,
  maxGenerateCount: 500,
  maxDevices: 5,
  maxActivations: 20,
  maxActivationDays: 730,
  maxUnbinds: 8,
  allowUnlimitedExpiry: false,
  maxTokenTtlSeconds: 0,
};

/**
 * 账户密码登录：实际上不设限。
 *
 * 仍给一个技术上限，避免手滑输入天文数字把数据库撑坏；
 * 这些值大到正常业务永远碰不到。
 */
const ACCOUNT_LIMITS: RoleLimits = {
  canGenerate: true,
  maxGenerateCount: 1000,
  maxDevices: 100,
  maxActivations: 10_000,
  maxActivationDays: 36_500,   // 100 年
  maxUnbinds: 1_000,
  allowUnlimitedExpiry: true,
  maxTokenTtlSeconds: 3_650 * 24 * 60 * 60,  // 10 年
};

export const ROLE_LIMITS: Record<AdminRole, RoleLimits> = {
  readonly: READONLY_LIMITS,
  operator: OPERATOR_LIMITS,
  operator_plus: OPERATOR_PLUS_LIMITS,
  root: ROOT_LIMITS,
  root_plus: ROOT_PLUS_LIMITS,
};

/**
 * 取某个身份的限额。
 *
 * 账户密码登录和静态 ADMIN_TOKEN 都走 ACCOUNT_LIMITS（不设限）——
 * 静态令牌是应急通道，权限上不该比账户低，否则数据库出问题时
 * 连救急都做不了。
 */
export function limitsFor(identity: { source: string; role: AdminRole }): RoleLimits {
  if (identity.source === "account" || identity.source === "static") return ACCOUNT_LIMITS;
  return ROLE_LIMITS[identity.role];
}

/** role 是否达到 min 的要求 */
export function roleAtLeast(role: AdminRole, min: AdminRole): boolean {
  return ROLE_RANK[role] >= ROLE_RANK[min];
}

/** 调用者身份 */
export interface AdminIdentity {
  /** 展示名：账户登录为用户名，令牌登录为令牌备注 */
  name: string;
  role: AdminRole;
  /**
   * 来源：
   *   account = 账户密码登录的会话令牌（唯一能管理令牌的身份）
   *   static  = 环境变量里的静态 ADMIN_TOKEN
   *   token   = 后台手动签发的下级令牌
   */
  source: "account" | "static" | "token";
  /** 账户登录时带上用户名，便于改密码等自助操作 */
  username?: string;
}

// ============ 密码哈希（scrypt） ============

const SCRYPT_N = 16_384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const KEY_LEN = 64;
const MAX_MEM = 64 * 1024 * 1024;

/** 产出 `scrypt$N$r$p$saltB64$hashB64` */
export function hashPassword(password: string): string {
  const salt = randomBytes(16);
  const hash = scryptSync(password, salt, KEY_LEN, {
    N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P, maxmem: MAX_MEM,
  });
  return [
    "scrypt", SCRYPT_N, SCRYPT_R, SCRYPT_P,
    salt.toString("base64"), hash.toString("base64"),
  ].join("$");
}

export function verifyPassword(password: string, stored: string): boolean {
  try {
    const parts = stored.split("$");
    if (parts.length !== 6 || parts[0] !== "scrypt") return false;

    const N = Number(parts[1]);
    const r = Number(parts[2]);
    const p = Number(parts[3]);
    const salt = Buffer.from(parts[4]!, "base64");
    const expected = Buffer.from(parts[5]!, "base64");
    if (!Number.isFinite(N) || !Number.isFinite(r) || !Number.isFinite(p)) return false;

    const actual = scryptSync(password, salt, expected.length, {
      N, r, p, maxmem: MAX_MEM,
    });
    return timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

// ============ 管理员令牌 ============

/** 明文形如 `adm_xxxxxxxx…`，256 bit 熵，不可枚举 */
export function generateAdminToken(): string {
  return "adm_" + randomBytes(32).toString("base64url");
}

export function hashAdminToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

/** 列表展示用的前缀，够辨认又不泄露 */
export function tokenPrefixOf(token: string): string {
  return token.slice(0, 12);
}

/** 令牌有效期上限：30 天。防止签发一个永不过期的令牌把体系架空 */
export const MAX_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60;
export const DEFAULT_TOKEN_TTL_SECONDS = 30 * 60;
