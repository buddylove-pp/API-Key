/**
 * 管理员认证：角色定义、密码哈希、令牌生成
 *
 * 密码用 scrypt（内存硬，抗 GPU 暴力），令牌用 256 bit 随机。
 * 两者都只存哈希，明文永不落库。
 */

import { createHash, randomBytes, scryptSync, timingSafeEqual } from "node:crypto";

// ============ 角色 ============

export type AdminRole = "root" | "operator" | "readonly";

/** 权限从低到高 */
export const ROLE_RANK: Record<AdminRole, number> = {
  readonly: 1,
  operator: 2,
  root: 3,
};

/**
 * 权限等级。
 *
 * ⚠️ 这里有 4 个层级，但只有 3 个能被令牌承载：
 *
 *   第 4 级  账户密码登录的会话 —— 唯一能签发/撤销令牌的身份
 *   第 3 级  管理令牌   root
 *   第 2 级  运营令牌   operator
 *   第 1 级  只读令牌   readonly
 *
 * 令牌一律**不能签发令牌**（否则一次泄露就能无限复制权限）。
 * 所以最高一级令牌也只能叫「管理」，不能叫「最高权限」——
 * 那会让人误以为它能签发令牌。
 *
 * 三级的划分依据是「操作可不可逆」：
 *   只读 → 看
 *   运营 → 只做可逆的日常操作（发卡、解绑、催校验）
 *   管理 → 才允许做破坏性操作（封禁用户、增删改软件）
 */
export const ROLE_LABEL: Record<AdminRole, string> = {
  readonly: "只读",
  operator: "运营",
  root: "管理",
};

export const ROLE_DESC: Record<AdminRole, string> = {
  readonly: "只能查看卡密、软件、日志与统计，不能做任何修改",
  operator: "可生成卡密、解绑设备、下发强制校验；不能封禁用户，也不能增删改软件",
  root: "运营的全部权限，另可封禁/解封卡密、增删改软件；但仍不能签发令牌",
};

export function isAdminRole(v: unknown): v is AdminRole {
  return v === "root" || v === "operator" || v === "readonly";
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
