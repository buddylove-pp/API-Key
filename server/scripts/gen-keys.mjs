#!/usr/bin/env node
/**
 * 生成票据签名密钥对（ECDsa P-256）
 *
 * 用法：npm run gen-keys
 *
 * 产出（都在 keys/ 目录，已被 .gitignore 忽略）：
 *   private.pem        私钥，写入服务端环境变量 TICKET_PRIVATE_KEY_PEM
 *   private.oneline.txt 私钥的单行转义版，直接粘贴到环境变量框
 *   public.pem         公钥，嵌入客户端
 *   public.csharp.txt  C# 可直接用的公钥常量
 *
 * ⚠️ 私钥只放服务端环境变量，绝不提交到 Git、绝不放进客户端。
 *    公钥可以随便分发 —— 它的作用就是让客户端验证票据真伪。
 */

import { generateKeyPairSync, createHash } from "node:crypto";
import { mkdirSync, writeFileSync, existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const keysDir = join(here, "..", "keys");
const privPath = join(keysDir, "private.pem");

if (existsSync(privPath) && !process.argv.includes("--force")) {
  console.error("检测到 keys/private.pem 已存在。");
  console.error("重新生成会使所有已签发的票据全部失效，客户端需重新激活。");
  console.error("确实要重新生成，请加 --force：npm run gen-keys -- --force");
  process.exit(1);
}

const { publicKey, privateKey } = generateKeyPairSync("ec", {
  namedCurve: "prime256v1", // = NIST P-256 / secp256r1
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

const publicDer = Buffer.from(
  publicKey.replace(/-----[A-Z ]+-----/g, "").replace(/\s+/g, ""),
  "base64",
);
const fingerprint = createHash("sha256").update(publicDer).digest("hex").slice(0, 32);

const privateOneLine = privateKey.replace(/\n/g, "\\n");
const publicB64 = publicKey.replace(/-----[A-Z ]+-----/g, "").replace(/\s+/g, "");

mkdirSync(keysDir, { recursive: true });
writeFileSync(privPath, privateKey, { mode: 0o600 });
writeFileSync(join(keysDir, "private.oneline.txt"), privateOneLine + "\n", { mode: 0o600 });
writeFileSync(join(keysDir, "public.pem"), publicKey, { mode: 0o644 });
writeFileSync(
  join(keysDir, "public.csharp.txt"),
  [
    "// 票据验签公钥 —— 嵌入客户端，可以公开分发",
    "internal static class LicensePublicKey",
    "{",
    `    public const string KeyId = "${fingerprint}";`,
    "",
    '    public const string Pem = """',
    publicKey.trimEnd(),
    '""";',
    "}",
    "",
  ].join("\n"),
  { mode: 0o644 },
);

console.log("密钥对已生成（ECDsa P-256）\n");
console.log(`公钥指纹: ${fingerprint}\n`);
console.log("── 服务端环境变量（复制整行）────────────────────────");
console.log(`TICKET_PRIVATE_KEY_PEM=${privateOneLine}`);
console.log();
console.log("── 客户端用公钥（C# 常量）──────────────────────────");
console.log(readFileSync(join(keysDir, "public.csharp.txt"), "utf8"));
console.log("文件已写入 keys/ 目录（该目录不会进 Git）");
console.log("⚠️  私钥请立即放入服务端环境变量，不要在本地长期留存明文");
