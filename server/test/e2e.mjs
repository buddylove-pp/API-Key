#!/usr/bin/env node
/**
 * 端到端测试
 *
 * 用内存驱动启动真实 HTTP 服务，走完整链路：
 *   健康检查 → 生成卡密 → 激活 → 离线验签 → 心跳 → 解绑 → 换机 → 封禁
 *
 * 重点验证「客户端能否离线验签」—— 服务端签的票据必须能被
 * 独立的一方用公钥验过，否则 .NET 客户端一定验不过。
 *
 * 用法：npm run build && npm test
 */

import { spawn } from "node:child_process";
import {
  generateKeyPairSync,
  createPublicKey,
  verify as cryptoVerify,
} from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");

const PORT = 18080;
const BASE = `http://127.0.0.1:${PORT}`;
const ADMIN_TOKEN = "test_admin_token_0123456789abcdefghijklmn";
const ADMIN_USER = "XIaoLKey";
const ADMIN_PASS = "test-password-55588800";

/** 本测试客户端对应的软件标识 */
const PRODUCT = "license-tester";
const OTHER_PRODUCT = "some-other-app";

// 测试用密钥对（与生产无关，每次运行临时生成）
const { privateKey, publicKey } = generateKeyPairSync("ec", {
  namedCurve: "prime256v1",
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

let passed = 0;
let failed = 0;
const failures = [];

function check(name, cond, extra = "") {
  if (cond) {
    passed++;
    console.log(`  ✓ ${name}`);
  } else {
    failed++;
    failures.push(name);
    console.log(`  ✗ ${name}${extra ? "  → " + extra : ""}`);
  }
}

function section(title) {
  console.log(`\n${title}`);
}

async function api(path, { method = "POST", body, token } = {}) {
  const headers = { "Content-Type": "application/json" };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const res = await fetch(BASE + path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let json = null;
  try {
    json = await res.json();
  } catch {
    /* 非 JSON 响应 */
  }
  return { status: res.status, json };
}

/**
 * 取卡密前缀（与服务端 keyPrefixOf 对齐）。
 * ⚠️ 卡密展示时带连字符，但入库前缀是**去掉连字符**的规范化形式，
 *    直接 key.slice(0,8) 会带上 '-' 而匹配不到。
 */
function prefixOf(key) {
  return String(key)
    .toUpperCase()
    .replace(/[^0-9A-Z]/g, "")
    .replace(/[IL]/g, "1")
    .replace(/O/g, "0")
    .slice(0, 8);
}

/** 激活请求：自动带上软件标识，避免每处重复写 */
function activate(body) {
  return api("/api/v1/activate", { body: { product: PRODUCT, ...body } });
}

/** 直连 /api/v1/* 的请求（api() 的前缀是 /admin/v1） */
async function rawPost(path, body, token) {
  const headers = { "Content-Type": "application/json" };
  if (token) headers["Authorization"] = "Bearer " + token;
  const res = await fetch(BASE + path, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
  let json = null;
  try {
    json = await res.json();
  } catch {
    /* 非 JSON */
  }
  return { status: res.status, json };
}

async function rawGet(path, token) {
  const headers = {};
  if (token) headers["Authorization"] = "Bearer " + token;
  const res = await fetch(BASE + path, { headers });
  let json = null;
  try {
    json = await res.json();
  } catch {
    /* 非 JSON */
  }
  return { status: res.status, json };
}

/** 模拟 .NET 客户端离线验签 */
function verifyTicketOffline(ticket) {
  const parts = ticket.split(".");
  if (parts.length !== 2) return { ok: false, reason: "格式错误" };
  const [body, sig] = parts;
  const ok = cryptoVerify(
    "sha256",
    Buffer.from(body, "ascii"),
    { key: createPublicKey(publicKey), dsaEncoding: "ieee-p1363" },
    Buffer.from(sig, "base64url"),
  );
  if (!ok) return { ok: false, reason: "签名不匹配" };
  const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  return { ok: true, payload };
}

const FP_A = "a".repeat(40);
const FP_B = "b".repeat(40);
const FP_C = "c".repeat(40);

// ============ 启动服务 ============

const child = spawn(process.execPath, [join(root, "dist", "index.js")], {
  cwd: root,
  env: {
    ...process.env,
    PORT: String(PORT),
    DB_DRIVER: "memory",
    ADMIN_TOKEN,
    ADMIN_USERNAME: ADMIN_USER,
    ADMIN_PASSWORD: ADMIN_PASS,
    TICKET_PRIVATE_KEY_PEM: privateKey.replace(/\n/g, "\\n"),
    AUTO_MIGRATE: "true",
    RATE_LIMIT_MAX: "100000",
    RATE_LIMIT_WINDOW_SEC: "60",
  },
  stdio: ["ignore", "pipe", "pipe"],
});

let serverLog = "";
child.stdout.on("data", (d) => (serverLog += d.toString()));
child.stderr.on("data", (d) => (serverLog += d.toString()));

async function waitForHealth(timeoutMs = 20000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(BASE + "/health");
      if (res.ok) return true;
    } catch {
      /* 还没起来 */
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  return false;
}

function cleanup(code) {
  try {
    child.kill("SIGKILL");
  } catch {
    /* ignore */
  }
  process.exit(code);
}

// ============ 测试主体 ============

async function run() {
  const up = await waitForHealth();
  if (!up) {
    console.error("服务未能启动，输出如下：\n" + serverLog);
    cleanup(1);
  }

  section("1. 基础接口");
  {
    const h = await api("/health", { method: "GET" });
    check("GET /health 返回 200", h.status === 200, `实际 ${h.status}`);
    check("health.code === 0", h.json?.code === 0);

    const p = await api("/api/v1/pubkey", { method: "GET" });
    check("GET /api/v1/pubkey 返回 200", p.status === 200);
    check("公钥算法为 ES256", p.json?.data?.algorithm === "ES256");
    check(
      "签名格式声明为 ieee-p1363（.NET 客户端要求）",
      p.json?.data?.signature_format === "ieee-p1363",
    );
    check("返回了 key_id 指纹", typeof p.json?.data?.key_id === "string");

    const nf = await api("/api/v1/nope", { method: "GET" });
    check("未知路径返回 404", nf.status === 404);

    const adminRes = await fetch(BASE + "/admin");
    const adminHtml = await adminRes.text();
    check(
      "管理后台页面可访问",
      adminRes.status === 200 && adminHtml.includes("卡密管理后台"),
      `HTTP ${adminRes.status}`,
    );
  }

  section("2. 管理接口鉴权");
  {
    const noAuth = await api("/admin/v1/licenses/generate", { body: { count: 1 } });
    check("无令牌访问管理接口被拒 401", noAuth.status === 401, `实际 ${noAuth.status}`);

    const badAuth = await api("/admin/v1/licenses/generate", {
      body: { count: 1 },
      token: "wrong-token-wrong-token-wrong-token",
    });
    check("错误令牌被拒 401", badAuth.status === 401);
  }

  section("3. 生成卡密（带软件维度）");
  let key1, key2, otherKey;
  {
    const g = await api("/admin/v1/licenses/generate", {
      token: ADMIN_TOKEN,
      body: {
        product: PRODUCT,
        count: 2,
        max_devices: 1,
        max_activations: 2,
        activation_days: 30,
        max_unbinds: 2,
        refund_on_unbind: true,
        note: "e2e-test",
      },
    });
    check("生成 2 张卡密成功", g.status === 200 && g.json?.data?.count === 2);
    key1 = g.json?.data?.keys?.[0];
    key2 = g.json?.data?.keys?.[1];
    check("卡密格式为 5 组 × 5 字符", /^[0-9A-Z]{5}(-[0-9A-Z]{5}){4}$/.test(key1 ?? ""), key1);
    check("两张卡密不重复", key1 !== key2);

    // 软件必须先注册才能发卡（防止标识打错字造出对不上的卡密）
    const cp = await api("/admin/v1/products", {
      token: ADMIN_TOKEN,
      body: { code: OTHER_PRODUCT, name: "另一个软件" },
    });
    check("可注册新软件", cp.json?.code === 0, JSON.stringify(cp.json));

    const g2 = await api("/admin/v1/licenses/generate", {
      token: ADMIN_TOKEN,
      body: { product: OTHER_PRODUCT, count: 1, activation_days: 30 },
    });
    otherKey = g2.json?.data?.keys?.[0];
    check("可为另一个软件单独生成卡密", typeof otherKey === "string");

    const badProd = await api("/admin/v1/licenses/generate", {
      token: ADMIN_TOKEN,
      body: { product: "never-registered-app", count: 1 },
    });
    check("未注册的软件无法发卡（1007）", badProd.json?.code === 1007, JSON.stringify(badProd.json));

    const byProduct = await api(`/admin/v1/licenses?product=${PRODUCT}`, {
      method: "GET",
      token: ADMIN_TOKEN,
    });
    check(
      "按软件维度筛选只返回本软件卡密",
      byProduct.status === 200 && byProduct.json?.data?.total === 2,
      `total=${byProduct.json?.data?.total}`,
    );
  }

  section("4. 激活与离线验签");
  let ticketA;
  {
    const a = await activate({
      license_key: key1,
      device_fp: FP_A,
      device_name: "TEST-PC-A",
      app_version: "1.0.0",
    });
    check("首次激活成功", a.status === 200 && a.json?.code === 0, JSON.stringify(a.json));
    ticketA = a.json?.data?.ticket;
    check("返回了票据", typeof ticketA === "string" && ticketA.includes("."));

    const v = verifyTicketOffline(ticketA);
    check("★ 票据可被独立验签（模拟 .NET 客户端）", v.ok, v.reason);
    check("票据内绑定的是本设备指纹", v.payload?.fp === FP_A);
    check("票据含过期时间", typeof v.payload?.exp === "number" && v.payload.exp > v.payload.iat);

    const days = (v.payload.exp - v.payload.iat) / 86400;
    check("票据有效期为 7 天（离线容忍窗口上限）", Math.abs(days - 7) < 0.01, `实际 ${days} 天`);

    const ent = a.json?.data?.entitlement;
    check("返回了授权信息", ent !== undefined && ent !== null);
    check("授权期为 30 天", Math.abs((ent.expires_at - ent.activated_at) / 86400 - 30) < 0.01,
      `实际 ${(ent.expires_at - ent.activated_at) / 86400} 天`);
    check("票据内带授权到期时间", v.payload?.eat === ent.expires_at);
    check("频率 1 → 不做定期校验", ent?.next_check_at === null, JSON.stringify(ent));

    check("激活计数为 1", a.json?.data?.license?.activation_count === 1);
    check("返回了服务端时间", typeof a.json?.data?.server_time === "number");
  }

  section("5. 软件维度校验");
  {
    const wrong = await api("/api/v1/activate", {
      body: { license_key: key1, device_fp: FP_A, product: OTHER_PRODUCT },
    });
    check("★ 跨软件使用卡密被拒 1006", wrong.json?.code === 1006, JSON.stringify(wrong.json));

    const noProduct = await api("/api/v1/activate", {
      body: { license_key: key1, device_fp: FP_A },
    });
    check("缺少软件标识被拒 4001", noProduct.json?.code === 4001, JSON.stringify(noProduct.json));

    const ownKey = await api("/api/v1/activate", {
      body: { license_key: otherKey, device_fp: FP_A, product: OTHER_PRODUCT },
    });
    check("另一软件的客户端可用其专属卡密激活", ownKey.json?.code === 0, JSON.stringify(ownKey.json));

    // 客户端首次上报未知软件标识 → 自动登记为 pending，管理员在后台一键确认
    const unknown = await api("/api/v1/activate", {
      body: { license_key: key1, device_fp: FP_B, product: "brand-new-app" },
    });
    check("未注册软件激活被拒（1007）", unknown.json?.code === 1007, JSON.stringify(unknown.json));

    const pending = await api("/admin/v1/products?status=pending", {
      method: "GET", token: ADMIN_TOKEN,
    });
    const codes = (pending.json?.data?.products ?? []).map((p) => p.code);
    check("未注册软件被自动登记为待确认", codes.includes("brand-new-app"), JSON.stringify(codes));

    const approve = await api("/admin/v1/products/brand-new-app/status", {
      token: ADMIN_TOKEN, body: { status: "active" },
    });
    check("可一键确认待审软件", approve.json?.code === 0, JSON.stringify(approve.json));

    // 确认后同一个标识就能正常走后续校验（此处卡密不属于该软件，应为 1006 而非 1007）
    const afterApprove = await api("/api/v1/activate", {
      body: { license_key: key1, device_fp: FP_B, product: "brand-new-app" },
    });
    check("确认后不再报未注册（转为卡密不匹配 1006）", afterApprove.json?.code === 1006,
      JSON.stringify(afterApprove.json));
  }

  section("6. 幂等与设备上限");
  {
    const again = await activate({ license_key: key1, device_fp: FP_A });
    check("同设备重复激活成功（幂等）", again.status === 200);
    check("重复激活不消耗激活次数", again.json?.data?.license?.activation_count === 1);

    const other = await activate({ license_key: key1, device_fp: FP_B });
    check("换设备激活被拒（设备数上限）", other.json?.code === 1005, JSON.stringify(other.json));
  }

  section("7. 解绑与换机");
  {
    const u = await api("/api/v1/unbind", { body: { license_key: key1, device_fp: FP_A } });
    check("自助解绑成功", u.status === 200 && u.json?.code === 0, JSON.stringify(u.json));
    check("解绑计数 +1", u.json?.data?.unbind_count === 1);
    check("释放了原设备", Array.isArray(u.json?.data?.released) && u.json.data.released.includes(FP_A));

    const rebind = await activate({ license_key: key1, device_fp: FP_B, device_name: "TEST-PC-B" });
    check("换机后可重新激活", rebind.status === 200 && rebind.json?.code === 0, JSON.stringify(rebind.json));
    check(
      "解绑返还了激活次数（refund_on_unbind=true）",
      rebind.json?.data?.license?.activation_count === 1,
      `实际 ${rebind.json?.data?.license?.activation_count}`,
    );
  }

  section("8. 心跳续期与吊销");
  let ticketB;
  {
    const oldHb = await api("/api/v1/heartbeat", { body: { ticket: ticketA, device_fp: FP_A } });
    check("已解绑设备的旧票据心跳被拒", oldHb.json?.code === 2001, JSON.stringify(oldHb.json));

    const b = await activate({ license_key: key1, device_fp: FP_B });
    ticketB = b.json?.data?.ticket;

    const hb = await api("/api/v1/heartbeat", { body: { ticket: ticketB, device_fp: FP_B } });
    check("有效票据心跳成功", hb.status === 200 && hb.json?.code === 0, JSON.stringify(hb.json));
    const nv = verifyTicketOffline(hb.json?.data?.ticket);
    check("续期返回的新票据可验签", nv.ok, nv.reason);

    const mismatch = await api("/api/v1/heartbeat", { body: { ticket: ticketB, device_fp: FP_C } });
    check("票据与设备指纹不匹配时被拒", mismatch.json?.code === 2001);

    const tampered = ticketB.slice(0, -3) + (ticketB.endsWith("AAA") ? "BBB" : "AAA");
    const t = await api("/api/v1/heartbeat", { body: { ticket: tampered, device_fp: FP_B } });
    check("票据被篡改后验签失败", t.json?.code === 2001);
  }

  section("9. 封禁即时生效");
  {
    const ban = await api("/admin/v1/licenses/ban", { token: ADMIN_TOKEN, body: { license_key: key1 } });
    check("封禁成功", ban.status === 200 && ban.json?.data?.status === "banned");

    const hb = await api("/api/v1/heartbeat", { body: { ticket: ticketB, device_fp: FP_B } });
    // 服务端会返回更精确的 1002（卡密已被封禁），而非泛化的 2001
    check(
      "封禁后心跳被拒（吊销生效）",
      hb.json?.code === 1002 || hb.json?.code === 2001,
      JSON.stringify(hb.json),
    );

    const act = await activate({ license_key: key1, device_fp: FP_C });
    check("封禁后无法激活", act.json?.code === 1002, JSON.stringify(act.json));

    const unban = await api("/admin/v1/licenses/unban", { token: ADMIN_TOKEN, body: { license_key: key1 } });
    check("解封成功", unban.status === 200);
  }

  section("10. 激活次数与解绑次数");
  {
    const a1 = await activate({ license_key: key2, device_fp: FP_A });
    check("key2 第 1 次激活成功", a1.json?.code === 0);

    const a2 = await activate({ license_key: key2, device_fp: FP_B });
    check("key2 换设备被设备上限拦下（max_devices=1）", a2.json?.code === 1005);

    await api("/api/v1/unbind", { body: { license_key: key2, device_fp: FP_A } });
    const a3 = await activate({ license_key: key2, device_fp: FP_B });
    check("解绑后激活成功（次数已返还）", a3.json?.code === 0);

    const u2 = await api("/api/v1/unbind", { body: { license_key: key2, device_fp: FP_B } });
    check("第 2 次解绑成功", u2.json?.code === 0, JSON.stringify(u2.json));
    const a4 = await activate({ license_key: key2, device_fp: FP_C });
    check("第 3 次激活成功", a4.json?.code === 0);

    const u3 = await api("/api/v1/unbind", { body: { license_key: key2, device_fp: FP_C } });
    check("第 3 次解绑被拒（max_unbinds=2）", u3.json?.code === 3002, JSON.stringify(u3.json));
  }

  section("11. 参数与错误处理");
  {
    const bad = await activate({ license_key: "NOPE-NOPE-NOPE-NOPE-NOPE", device_fp: FP_A });
    check("不存在的卡密返回 1001", bad.json?.code === 1001, JSON.stringify(bad.json));

    const badFp = await activate({ license_key: key1, device_fp: "zzz" });
    check("非法设备指纹返回 4001", badFp.json?.code === 4001);

    const noFp = await activate({ license_key: key1 });
    check("缺少设备指纹返回 4001", noFp.json?.code === 4001);

    const res = await fetch(BASE + "/api/v1/activate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{ this is not json",
    });
    check("非法 JSON 返回 400 而非 500", res.status === 400, `实际 ${res.status}`);
  }

  section("12. 卡密查询与审计");
  {
    const prefix = key1.replace(/-/g, "").slice(0, 8);
    const q = await api(`/admin/v1/licenses/${prefix}`, { method: "GET", token: ADMIN_TOKEN });
    check("按前缀查询卡密成功", q.status === 200 && q.json?.code === 0, JSON.stringify(q.json));
    check("返回了绑定记录", Array.isArray(q.json?.data?.bindings));
    check("返回了审计日志", Array.isArray(q.json?.data?.audit) && q.json.data.audit.length > 0);
    check("卡密带软件标识", q.json?.data?.license?.product === PRODUCT);

    const list = await api("/admin/v1/licenses?page=1&page_size=10", { method: "GET", token: ADMIN_TOKEN });
    check("卡密列表可查", list.status === 200 && Array.isArray(list.json?.data?.rows));
    check("列表返回总数", typeof list.json?.data?.total === "number");
  }

  section("13. 管理员账户与令牌");
  {
    const anon = await api("/admin/v1/licenses", { method: "GET" });
    check("未登录访问管理接口被拒 401", anon.status === 401, `HTTP ${anon.status}`);

    const badLogin = await api("/api/v1/admin/login", {
      body: { username: ADMIN_USER, password: "definitely-wrong" },
    });
    check("密码错误被拒 4011", badLogin.json?.code === 4011, JSON.stringify(badLogin.json));

    const login = await api("/api/v1/admin/login", {
      body: { username: ADMIN_USER, password: ADMIN_PASS },
    });
    check("账户密码登录成功", login.json?.code === 0, JSON.stringify(login.json));
    const session = login.json?.data?.token;
    check("登录返回会话令牌", typeof session === "string" && session.startsWith("adm_"));
    check("root 账户角色为 root", login.json?.data?.role === "root");

    const me = await api("/api/v1/admin/me", { method: "GET", token: session });
    check("会话令牌可查当前身份", me.json?.data?.role === "root", JSON.stringify(me.json));

    const mk = await api("/admin/v1/tokens", {
      token: session,
      body: { role: "readonly", name: "只读测试", ttl_seconds: 1800 },
    });
    check("可签发下级令牌", mk.json?.code === 0, JSON.stringify(mk.json));
    const roToken = mk.json?.data?.token;
    check("签发返回明文令牌（仅此一次）", typeof roToken === "string" && roToken.startsWith("adm_"));

    const roList = await api("/admin/v1/licenses", { method: "GET", token: roToken });
    check("只读令牌可查列表", roList.json?.code === 0, JSON.stringify(roList.json));

    const roGen = await api("/admin/v1/licenses/generate", {
      token: roToken, body: { product: PRODUCT, count: 1 },
    });
    check("只读令牌无法生成卡密（403）", roGen.status === 403, `HTTP ${roGen.status}`);

    const roMk = await api("/admin/v1/tokens", {
      token: roToken, body: { role: "root", ttl_seconds: 1800 },
    });
    check("只读令牌无法签发令牌（403）", roMk.status === 403, `HTTP ${roMk.status}`);

    // ---- 关键安全约束：令牌不能派生令牌 ----

    const rootTok = await api("/admin/v1/tokens", {
      token: session, body: { role: "root", name: "root级令牌", ttl_seconds: 1800 },
    });
    const rootToken = rootTok.json?.data?.token;
    check("账户可签发 root 角色令牌", typeof rootToken === "string", JSON.stringify(rootTok.json));

    const rootMk = await api("/admin/v1/tokens", {
      token: rootToken, body: { role: "root", ttl_seconds: 1800 },
    });
    check("★ root 令牌无法再签发令牌（403）", rootMk.status === 403, `HTTP ${rootMk.status}`);

    const staticMk = await api("/admin/v1/tokens", {
      token: ADMIN_TOKEN, body: { role: "root", ttl_seconds: 1800 },
    });
    check("★ 静态 ADMIN_TOKEN 也无法签发令牌（403）", staticMk.status === 403, `HTTP ${staticMk.status}`);

    const rootGen = await api("/admin/v1/licenses/generate", {
      token: rootToken, body: { product: PRODUCT, count: 1 },
    });
    check("root 令牌仍可发卡（业务权限不受影响）", rootGen.json?.code === 0, JSON.stringify(rootGen.json));

    const meRootTok = await rawGet("/api/v1/admin/me", rootToken);
    check("★ root 令牌的 can_manage_tokens 为 false",
      meRootTok.json?.data?.can_manage_tokens === false, JSON.stringify(meRootTok.json?.data));

    const meSession = await rawGet("/api/v1/admin/me", session);
    check("★ 账户会话的 can_manage_tokens 为 true",
      meSession.json?.data?.can_manage_tokens === true, JSON.stringify(meSession.json?.data));
    check("账户会话的 source 为 account", meSession.json?.data?.source === "account");
    check("root 令牌的 source 为 token", meRootTok.json?.data?.source === "token");

    // ---- 操作日志 ----

    const audit = await api("/admin/v1/audit?page=1&page_size=100", { method: "GET", token: session });
    check("可查操作日志", audit.json?.code === 0 && audit.json.data.total > 0, JSON.stringify(audit.json));
    const events = (audit.json?.data?.rows ?? []).map((a) => a.event);
    check("日志含登录成功", events.includes("admin.login.ok"), JSON.stringify(events.slice(0, 12)));
    check("日志含登录失败", events.includes("admin.login.fail"));
    check("日志含令牌签发", events.includes("admin.token.create"));
    check("日志含卡密激活", events.includes("activate"));

    const onlyLogin = await api("/admin/v1/audit?prefix=admin.login", { method: "GET", token: session });
    const loginEvents = (onlyLogin.json?.data?.rows ?? []).map((a) => a.event);
    check("按前缀筛选生效",
      loginEvents.length > 0 && loginEvents.every((e) => e.startsWith("admin.login")),
      JSON.stringify(loginEvents));

    const tooLong = await api("/admin/v1/tokens", {
      token: session, body: { role: "operator", ttl_seconds: 99999999 },
    });
    check("超出上限的有效期被拒", tooLong.json?.code === 4001, JSON.stringify(tooLong.json));

    const tooShort = await api("/admin/v1/tokens", {
      token: session, body: { role: "operator", ttl_seconds: 10 },
    });
    check("过短的有效期被拒", tooShort.json?.code === 4001, JSON.stringify(tooShort.json));

    const tokenList = await api("/admin/v1/tokens", { method: "GET", token: session });
    check("可列出令牌", tokenList.json?.code === 0 && tokenList.json.data.tokens.length >= 2);
    check("列表不含令牌明文", !JSON.stringify(tokenList.json).includes(roToken));

    const roId = tokenList.json?.data?.tokens?.find((t) => t.name === "只读测试")?.id;
    const revoke = await api(`/admin/v1/tokens/${roId}/revoke`, { token: session, body: {} });
    check("可撤销令牌", revoke.json?.code === 0, JSON.stringify(revoke.json));

    const afterRevoke = await api("/admin/v1/licenses", { method: "GET", token: roToken });
    check("撤销后令牌立即失效（401）", afterRevoke.status === 401, `HTTP ${afterRevoke.status}`);

    const staticOk = await api("/admin/v1/licenses", { method: "GET", token: ADMIN_TOKEN });
    check("静态 ADMIN_TOKEN 仍可用（兼容既有接入）", staticOk.json?.code === 0);
  }

  section("14. 定期校验：定频率模式");
  let ckKey, ckTicket;
  {
    const g = await api("/admin/v1/licenses/generate", {
      token: ADMIN_TOKEN,
      body: {
        product: PRODUCT, count: 1, max_devices: 1, max_activations: 1,
        activation_days: 100, max_unbinds: 3,
        check_mode: "frequency", check_frequency: 10, check_remind_percent: 20,
        note: "定期校验测试",
      },
    });
    check("可生成带校验排期的卡密", g.json?.code === 0, JSON.stringify(g.json));
    ckKey = g.json?.data?.keys?.[0];

    const a = await activate({ license_key: ckKey, device_fp: FP_C });
    check("激活成功", a.json?.code === 0, JSON.stringify(a.json));

    const ent = a.json?.data?.entitlement;
    const d = (x, base) => Math.round((x - base) / 86400);

    check("★ 100 天 ÷ 10 → 周期 10 天", ent?.check_interval_days === 10, JSON.stringify(ent));
    check("★ 首次计划在第 10 天", d(ent.next_check_at, ent.activated_at) === 10);
    check("★ 提醒在第 8 天（提前 20%）", d(ent.remind_at, ent.activated_at) === 8);
    check("状态为 active", ent?.state === "active");
    check("授权期为 100 天", d(ent.expires_at, ent.activated_at) === 100);
    check("票据被离线窗口上限截断为 7 天",
      d(a.json.data.expires_at, a.json.data.server_time) === 7,
      `实际 ${d(a.json.data.expires_at, a.json.data.server_time)} 天`);

    ckTicket = a.json?.data?.ticket;
  }

  section("15. 定期校验：执行校验与基准规则");
  {
    const q = await api("/api/v1/entitlement", { body: { ticket: ckTicket, device_fp: FP_C } });
    check("只读查询授权状态成功", q.json?.code === 0, JSON.stringify(q.json));
    const before = q.json?.data?.next_check_at;

    const c1 = await api("/api/v1/check", { body: { ticket: ckTicket, device_fp: FP_C } });
    check("校验成功", c1.json?.code === 0, JSON.stringify(c1.json));
    check("本次推进了校验周期", c1.json?.data?.advanced === true);
    check("返回了上次计划时间", c1.json?.data?.previous_next_check_at === before);

    const ent = c1.json?.data?.entitlement;
    const d = (x, base) => Math.round((x - base) / 86400);
    // 立即校验属于「提前」→ 基准不变，下次 = 原计划第10天 + 10天 = 第20天
    check("★ 提前校验后下次仍在第 20 天（基准不变）",
      d(ent.next_check_at, ent.activated_at) === 20,
      `实际第 ${d(ent.next_check_at, ent.activated_at)} 天`);

    check("校验返回新票据", typeof c1.json?.data?.ticket === "string");
    check("校验不消耗激活次数", c1.json?.data?.entitlement !== undefined);

    // 新票据可离线验签
    const nv = verifyTicketOffline(c1.json?.data?.ticket);
    check("新票据可验签", nv.ok, nv.reason);
    check("票据内带下次校验时间", nv.payload?.nca === ent.next_check_at);
    check("票据内带授权到期时间", nv.payload?.eat === ent.expires_at);

    // 校验后状态回到 active
    const after = await api("/api/v1/entitlement", { body: { ticket: c1.json.data.ticket, device_fp: FP_C } });
    check("校验后状态为 active", after.json?.data?.state === "active");
  }

  section("16. 定期校验：定时间模式");
  {
    const g = await api("/admin/v1/licenses/generate", {
      token: ADMIN_TOKEN,
      body: {
        product: PRODUCT, count: 1, max_devices: 1, max_activations: 1,
        activation_days: 30, check_mode: "interval", check_interval_days: 7,
        check_remind_percent: 0,
      },
    });
    const key = g.json?.data?.keys?.[0];
    check("定时间模式可生成卡密", typeof key === "string");

    const a = await activate({ license_key: key, device_fp: FP_A });
    const ent = a.json?.data?.entitlement;
    const d = (x, base) => Math.round((x - base) / 86400);

    check("★ 总时长 30 天也能设 7 天周期", ent?.check_interval_days === 7, JSON.stringify(ent));
    check("下次校验在第 7 天", d(ent.next_check_at, ent.activated_at) === 7);
    check("★ 提醒比例 0 → 不提醒", ent?.remind_at === null);
    check("授权期仍为 30 天", d(ent.expires_at, ent.activated_at) === 30);
  }

  section("17. 校验参数校验");
  {
    const bad = await api("/admin/v1/licenses/generate", {
      token: ADMIN_TOKEN,
      body: { product: PRODUCT, count: 1, check_frequency: 0 },
    });
    check("频率 0 被拒", bad.json?.code === 4001, JSON.stringify(bad.json));

    const bad2 = await api("/admin/v1/licenses/generate", {
      token: ADMIN_TOKEN,
      body: { product: PRODUCT, count: 1, check_remind_percent: 200 },
    });
    check("提醒比例超过 90 被拒", bad2.json?.code === 4001, JSON.stringify(bad2.json));

    const bad3 = await api("/admin/v1/licenses/generate", {
      token: ADMIN_TOKEN,
      body: { product: PRODUCT, count: 1, check_interval_days: 99999 },
    });
    check("周期天数超上限被拒", bad3.json?.code === 4001, JSON.stringify(bad3.json));
  }

  section("18. 退出登录与改密码");
  {
    // 登录两次，模拟两台设备
    const l1 = await rawPost("/api/v1/admin/login", { username: ADMIN_USER, password: ADMIN_PASS });
    const l2 = await rawPost("/api/v1/admin/login", { username: ADMIN_USER, password: ADMIN_PASS });
    const t1 = l1.json?.data?.token;
    const t2 = l2.json?.data?.token;
    check("可登录拿到两个会话", typeof t1 === "string" && typeof t2 === "string");

    const u1 = await api("/admin/v1/licenses", { method: "GET", token: t1 });
    const u2 = await api("/admin/v1/licenses", { method: "GET", token: t2 });
    check("会话 1 可用", u1.json?.code === 0);
    check("会话 2 可用", u2.json?.code === 0);

    const lo = await rawPost("/api/v1/admin/logout", {}, t1);
    check("退出登录成功", lo.json?.code === 0, JSON.stringify(lo.json));

    const afterLo = await api("/admin/v1/licenses", { method: "GET", token: t1 });
    check("★ 退出后该会话令牌立即失效（401）", afterLo.status === 401, `HTTP ${afterLo.status}`);

    const stillOk = await api("/admin/v1/licenses", { method: "GET", token: t2 });
    check("★ 其它会话不受影响", stillOk.json?.code === 0, JSON.stringify(stillOk.json));

    const loAudit = await api("/admin/v1/audit?event=admin.logout", { method: "GET", token: t2 });
    check("退出被记入日志", (loAudit.json?.data?.total ?? 0) >= 1, JSON.stringify(loAudit.json?.data));

    // ---- 改密码 ----

    const badPw = await rawPost("/api/v1/admin/password",
      { old_password: "definitely-wrong", new_password: "new-password-123" }, t2);
    check("原密码错误被拒 4011", badPw.json?.code === 4011, JSON.stringify(badPw.json));

    const shortPw = await rawPost("/api/v1/admin/password",
      { old_password: ADMIN_PASS, new_password: "123" }, t2);
    check("新密码过短被拒", shortPw.json?.code === 4001, JSON.stringify(shortPw.json));

    const NEW_PASS = "new-password-9876";
    const okPw = await rawPost("/api/v1/admin/password",
      { old_password: ADMIN_PASS, new_password: NEW_PASS }, t2);
    check("改密码成功", okPw.json?.code === 0, JSON.stringify(okPw.json));
    check("返回被撤销的会话数", typeof okPw.json?.data?.sessions_revoked === "number");

    const keepOk = await api("/admin/v1/licenses", { method: "GET", token: t2 });
    check("当前会话保留（没把自己踢掉）", keepOk.json?.code === 0, JSON.stringify(keepOk.json));

    const oldLogin = await rawPost("/api/v1/admin/login", { username: ADMIN_USER, password: ADMIN_PASS });
    check("旧密码无法登录", oldLogin.json?.code === 4011, JSON.stringify(oldLogin.json));

    const newLogin = await rawPost("/api/v1/admin/login", { username: ADMIN_USER, password: NEW_PASS });
    check("★ 新密码可登录", newLogin.json?.code === 0, JSON.stringify(newLogin.json));

    const staticStill = await api("/admin/v1/licenses", { method: "GET", token: ADMIN_TOKEN });
    check("静态 ADMIN_TOKEN 不受改密码影响（应急通道）", staticStill.json?.code === 0);
  }

  section("19. 强制校验与设备详情");
  {
    const g = await api("/admin/v1/licenses/generate", {
      token: ADMIN_TOKEN,
      body: {
        product: PRODUCT, count: 1, max_devices: 1, max_activations: 1,
        activation_days: 100, check_mode: "frequency", check_frequency: 10,
        check_remind_percent: 20, note: "强制校验测试",
      },
    });
    const key = g.json?.data?.keys?.[0];
    const prefix = prefixOf(key);
    check("前缀已规范化（不含连字符）", !prefix.includes("-") && prefix.length === 8, prefix);

    const a = await activate({ license_key: key, device_fp: FP_A });
    check("激活成功", a.json?.code === 0, JSON.stringify(a.json));
    const ticket = a.json?.data?.ticket;

    let ent = (await api("/api/v1/entitlement", { body: { ticket, device_fp: FP_A } })).json?.data;
    check("初始 force_check=false", ent?.force_check === false, JSON.stringify(ent));
    check("初始状态不是 overdue", ent?.state !== "overdue", ent?.state);

    // ---- 管理员下发强制校验 ----
    const fc = await api(`/admin/v1/licenses/${prefix}/force-check`, {
      token: ADMIN_TOKEN, body: { reason: "疑似异常使用" },
    });
    check("下发强制校验成功", fc.json?.code === 0, JSON.stringify(fc.json));
    check("影响 1 台设备", fc.json?.data?.devices === 1, JSON.stringify(fc.json?.data));

    // ---- 客户端读到 ----
    ent = (await api("/api/v1/entitlement", { body: { ticket, device_fp: FP_A } })).json?.data;
    check("★ 客户端读到 force_check=true", ent?.force_check === true, JSON.stringify(ent));
    check("★ 状态变为 overdue（强制停用）", ent?.state === "overdue", ent?.state);
    check("must_check 为 true", ent?.must_check === true);
    check("带回了强制原因", ent?.force_check_reason === "疑似异常使用", ent?.force_check_reason);

    const hb = await api("/api/v1/heartbeat", { body: { ticket, device_fp: FP_A } });
    check("心跳仍可续期（不因强制校验被拒）", hb.json?.code === 0, JSON.stringify(hb.json));

    // ---- 后台设备详情 ----
    const detail = await api(`/admin/v1/licenses/${prefix}`, { method: "GET", token: ADMIN_TOKEN });
    check("详情返回设备列表", Array.isArray(detail.json?.data?.devices), JSON.stringify(detail.json?.data));
    const dev = (detail.json?.data?.devices ?? [])[0];
    check("设备详情含下次校验时间", dev?.next_check_at != null, JSON.stringify(dev));
    check("设备详情含强制校验标记", dev?.force_check === true, JSON.stringify(dev));
    check("设备详情含剩余天数", typeof dev?.days_left === "number", JSON.stringify(dev));
    check("设备详情含提醒时间", dev?.remind_at != null, JSON.stringify(dev));
    check("设备详情含状态", typeof dev?.state === "string", JSON.stringify(dev));

    // ---- 校验后自动清除 ----
    const c = await api("/api/v1/check", { body: { ticket, device_fp: FP_A } });
    check("校验成功", c.json?.code === 0, JSON.stringify(c.json));
    check("★ 校验后 force_check 自动清除",
      c.json?.data?.entitlement?.force_check === false,
      JSON.stringify(c.json?.data?.entitlement));
    check("状态回到正常", c.json?.data?.entitlement?.state !== "overdue",
      c.json?.data?.entitlement?.state);

    // ---- 撤销接口 ----
    await api(`/admin/v1/licenses/${prefix}/force-check`, { token: ADMIN_TOKEN, body: {} });
    const cl = await api(`/admin/v1/licenses/${prefix}/force-check/clear`, {
      token: ADMIN_TOKEN, body: {},
    });
    check("可撤销强制校验", cl.json?.code === 0, JSON.stringify(cl.json));
    check("撤销了 1 台", cl.json?.data?.cleared === 1, JSON.stringify(cl.json?.data));

    // ---- 审计 ----
    const au = await api("/admin/v1/audit?event=admin.force_check", {
      method: "GET", token: ADMIN_TOKEN,
    });
    check("强制校验被记入日志", (au.json?.data?.total ?? 0) >= 1, JSON.stringify(au.json?.data));

    const au2 = await api("/admin/v1/audit?event=check", { method: "GET", token: ADMIN_TOKEN });
    const forced = (au2.json?.data?.rows ?? []).some((r) => String(r.detail || "").includes("管理员强制"));
    check("强制校验的 check 日志有标记", forced, JSON.stringify((au2.json?.data?.rows ?? []).slice(0, 3)));
  }

  // ============ 汇总 ============

  console.log("\n" + "─".repeat(50));
  console.log(`  通过 ${passed} 项，失败 ${failed} 项`);
  if (failed > 0) {
    console.log("  失败项：");
    for (const f of failures) console.log(`    - ${f}`);
  }
  console.log("─".repeat(50));

  cleanup(failed === 0 ? 0 : 1);
}

run().catch((e) => {
  console.error("\n测试执行异常:", e);
  console.error("服务输出:\n" + serverLog);
  cleanup(1);
});
