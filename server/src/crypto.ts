/**
 * 密码学原语：卡密生成、票据签名/验签
 *
 * ⚠️ 关键互操作细节
 * ECDsa 签名有两种编码：DER 与 IEEE P1363（r||s 定长拼接）。
 * Node 默认输出 DER，而 .NET 的 ECDsa.VerifyData() 默认按 P1363 解析。
 * 因此服务端必须显式指定 dsaEncoding: "ieee-p1363"，否则 .NET 客户端验签必然失败。
 *
 * ⚠️ 签名对象
 * 签名的是 payload 的 **base64url 字符串本身**（的 ASCII 字节），不是解码后的 JSON。
 * 这样客户端验签时无需重新序列化 JSON，避免字段顺序/空白差异导致的验签失败。
 */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  sign as nodeSign,
  verify as nodeVerify,
  type KeyObject,
} from "node:crypto";

/** Crockford Base32：剔除 I / L / O / U，避免用户输入歧义 */
const BASE32_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

export const TICKET_VERSION = 1;

// ============ 卡密 ============

/**
 * 生成卡密：CSPRNG → Base32 → 分组
 * 默认 5 组 × 5 字符 = 25 字符 = 125 bit 熵，不可枚举
 * 输出形如：4XK79-M2PQW-3N8RT-6YB4Z-C7DFG
 */
export function generateLicenseKey(groups = 5, groupSize = 5): string {
  const totalChars = groups * groupSize;
  const neededBytes = Math.ceil((totalChars * 5) / 8);
  const buf = randomBytes(neededBytes);

  let out = "";
  let acc = 0;
  let accBits = 0;
  let idx = 0;

  while (out.length < totalChars) {
    if (accBits < 5) {
      acc = (acc << 8) | (buf[idx++] ?? 0);
      accBits += 8;
    }
    accBits -= 5;
    out += BASE32_ALPHABET[(acc >> accBits) & 31];
  }

  return out.match(new RegExp(`.{1,${groupSize}}`, "g"))!.join("-");
}

/**
 * 规范化用户输入的卡密：去分隔符、转大写、修正易混字符
 * 让用户输错 O/0、I/1、L/1 也能通过
 */
export function normalizeLicenseKey(input: string): string {
  return input
    .toUpperCase()
    .replace(/[^0-9A-Z]/g, "")
    .replace(/[IL]/g, "1")
    .replace(/O/g, "0");
}

export function sha256Hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

/** 展示用前缀：规范化后的前 8 位，给客服肉眼定位 */
export function keyPrefixOf(normalizedKey: string): string {
  return normalizedKey.slice(0, 8);
}

// ============ 密钥对 ============

export function loadPrivateKey(pem: string): KeyObject {
  return createPrivateKey({ key: pem, format: "pem" });
}

export function derivePublicKey(privateKey: KeyObject): KeyObject {
  return createPublicKey(privateKey);
}

export function publicKeyToPem(publicKey: KeyObject): string {
  return publicKey.export({ type: "spki", format: "pem" }).toString();
}

/** 公钥指纹，客户端可用来确认拿到的是同一把钥匙 */
export function keyFingerprint(publicKey: KeyObject): string {
  const der = publicKey.export({ type: "spki", format: "der" }) as Buffer;
  return createHash("sha256").update(der).digest("hex").slice(0, 32);
}

// ============ 票据 ============

export interface TicketPayload {
  /** 协议版本 */
  v: number;
  /** 卡密 ID */
  lid: number;
  /** 设备指纹哈希，绑定设备，防止票据被复制到别的机器 */
  fp: string;
  /** 签发时间（Unix 秒） */
  iat: number;
  /** 票据过期时间（Unix 秒）—— 短周期，用于离线容忍窗口 */
  exp: number;

  // ---- 以下为授权与校验排期，客户端可离线据此判断是否该弹校验窗口 ----

  /** 首次激活时间（授权时间锚点） */
  aat: number;
  /** 本设备授权到期时间 */
  eat: number;
  /** 计划下次校验时间；null = 不做定期校验 */
  nca: number | null;
  /** 提醒开始时间；null = 不提醒 */
  rat: number | null;
}

/**
 * 签发票据 → `<base64url(payloadJson)>.<base64url(signature)>`
 */
export function signTicket(privateKey: KeyObject, payload: TicketPayload): string {
  const body = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  const signature = nodeSign("sha256", Buffer.from(body, "ascii"), {
    key: privateKey,
    dsaEncoding: "ieee-p1363", // ← .NET 客户端要求 P1363
  }).toString("base64url");

  return `${body}.${signature}`;
}

/**
 * 验签并解析票据。任何一步失败都返回 null（不抛异常，避免泄露失败细节）
 */
export function verifyTicket(publicKey: KeyObject, ticket: string): TicketPayload | null {
  if (typeof ticket !== "string") return null;

  const parts = ticket.split(".");
  if (parts.length !== 2) return null;

  const body = parts[0]!;
  const sigB64 = parts[1]!;
  if (body === "" || sigB64 === "") return null;

  let signature: Buffer;
  try {
    signature = Buffer.from(sigB64, "base64url");
  } catch {
    return null;
  }

  let ok: boolean;
  try {
    ok = nodeVerify("sha256", Buffer.from(body, "ascii"), {
      key: publicKey,
      dsaEncoding: "ieee-p1363",
    }, signature);
  } catch {
    return null;
  }
  if (!ok) return null;

  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  } catch {
    return null;
  }

  if (typeof parsed !== "object" || parsed === null) return null;
  const p = parsed as Record<string, unknown>;

  if (
    typeof p.v !== "number" ||
    typeof p.lid !== "number" ||
    typeof p.fp !== "string" ||
    typeof p.iat !== "number" ||
    typeof p.exp !== "number"
  ) {
    return null;
  }

  return {
    v: p.v,
    lid: p.lid,
    fp: p.fp,
    iat: p.iat,
    exp: p.exp,
    // 老版本票据没有这些字段，退回合理默认值，保证向后兼容
    aat: typeof p.aat === "number" ? p.aat : p.iat,
    eat: typeof p.eat === "number" ? p.eat : p.exp,
    nca: typeof p.nca === "number" ? p.nca : null,
    rat: typeof p.rat === "number" ? p.rat : null,
  };
}

/** 设备指纹格式校验：只接受 32~64 位十六进制 */
export function isValidDeviceFp(fp: unknown): fp is string {
  return typeof fp === "string" && /^[0-9a-f]{32,64}$/i.test(fp);
}
