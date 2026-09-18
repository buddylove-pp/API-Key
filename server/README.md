# 卡密授权验证服务

给软件做网络卡密授权的后端。核心设计：**服务端私钥签发限时票据，客户端只嵌公钥离线验签**。

- 技术栈：Node.js 20+ / TypeScript / Express / PostgreSQL
- 客户端零第三方依赖（`HttpClient` + `System.Text.Json` + `ECDsa`）
- 自带 Web 管理后台，部署完打开 `/admin` 即可生成卡密

---

## 一、核心设计（先看这段，决定了整套东西能不能防住）

卡密只是一次性凭据，用完就换成**签名票据**：

```
卡密（125 bit 随机，一次性）
   ↓ 激活时消耗
票据（设备指纹 + 过期时间 + 服务端私钥签名）
   ↓ 之后所有校验都用它，离线也能验
```

**为什么必须非对称签名？**

| 做法 | 后果 |
|---|---|
| 每次启动联网问服务器 | 断网不可用；服务器抖动全量用户掉线 |
| 卡密存本地比对 | 卡密被提取后全网共用 |
| **对称密钥（HMAC）签票据** | 密钥在客户端里 = 可提取 = **任何人能伪造票据**，等于没做 |

**唯一正确做法**：服务端持私钥签发，客户端只嵌公钥验签。私钥永不出服务器。

**三个必须对齐的互操作细节**（错一个客户端就验不过）：

1. 签名对象是 payload 的 **base64url 字符串本身**，不是解码后的 JSON —— 避免序列化差异
2. 签名编码必须是 **IEEE P1363（r‖s 定长 64 字节）**，不是 DER —— .NET `ECDsa.VerifyData` 默认按 P1363 解析
3. 哈希算法 SHA-256

---

## 二、快速开始（本地）

```bash
npm install
npm run build

# 生成密钥对 + 写 .env（会自动生成随机 ADMIN_TOKEN）
node scripts/dev-setup.mjs

# 启动
node --env-file=.env dist/index.js
```

打开 `http://localhost:8787/admin`，粘贴 `dev-setup.mjs` 打印的 `ADMIN_TOKEN`，即可生成卡密。

> 本地默认端口 8787（8080 常被其他程序占用）。

### 测试

```bash
npm test        # 端到端测试，自建内存库 + 真实 HTTP，59 项断言
```

---

## 三、部署到 orkestr

### 1. 推送代码到 GitHub

代码推上去后，在 orkestr 控制台：

### 2. 创建项目

`Projects → New Project` → 选你的仓库 → 分支 `main`
- 框架选 **Node.js**（有 Dockerfile 时 orkestr 会自动识别）
- 建议 slug：`license-api` → 得到 `https://license-api.orkestr.run`

### 3. 添加 PostgreSQL 附加组件

`Add-ons → Add Service` → 类型选 **PostgreSQL**
- 连接串会自动注入为环境变量 `DATABASE_URL`，**不用手填**

> ⚠️ 不要用内存驱动跑生产。Free 档允许 1 个附加组件，正好够。

### 4. 配置环境变量

`项目 → 环境 → Environment Variables`：

| 变量 | 值 | 说明 |
|---|---|---|
| `DB_DRIVER` | `pg` | 生产必须用 PostgreSQL |
| `ADMIN_TOKEN` | 32 位以上随机串 | 管理接口令牌，见下方生成命令 |
| `TICKET_PRIVATE_KEY_PEM` | 私钥单行转义版 | 见下方说明 |
| `AUTO_MIGRATE` | `true` | 首次部署自动建表，之后可改 `false` |
| `RATE_LIMIT_MAX` | `60` | 每 IP 每窗口请求上限 |
| `RATE_LIMIT_WINDOW_SEC` | `60` | 窗口秒数 |

> `PORT` 由 orkestr 自动注入，**不要自己设**。
> `DATABASE_URL` 由附加组件自动注入，**不要自己设**。

**生成 ADMIN_TOKEN：**

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

**生成密钥对：**

```bash
npm run gen-keys
```

脚本会在 `keys/` 目录产出：
- `private.oneline.txt` —— 直接粘贴到 `TICKET_PRIVATE_KEY_PEM`
- `public.csharp.txt` —— C# 常量形式，嵌入客户端
- 同时打印**公钥指纹（key_id）**，用来核对客户端拿到的公钥是否正确

> ⚠️ **私钥绝不能进 Git**。`keys/` 和 `.env` 都已在 `.gitignore` 里。
> 重新生成密钥对会让所有已签发票据失效，全部用户需重新激活。

### 5. 部署

点 `Deploy`，等状态变 `Live`。

访问 `https://<你的slug>.orkestr.run/admin` 打开管理后台。

### 6. 绑定自定义域名（可选）

`Domains → Add domain` → 填 `api.你的域名.com` → 到 DNS 服务商加 CNAME 指向项目默认域名 → 点 `Verify DNS`。orkestr 自动签发 TLS 证书。

---

## 四、接口一览

### 公共接口（客户端调用）

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/health` | 健康检查 |
| `GET` | `/api/v1/pubkey` | 获取验签公钥（生产建议硬编码，此接口用于对接与排错） |
| `POST` | `/api/v1/activate` | 激活，返回票据 |
| `POST` | `/api/v1/heartbeat` | 心跳续期，返回新票据 |
| `POST` | `/api/v1/unbind` | 自助解绑 |

### 管理接口（`Authorization: Bearer <ADMIN_TOKEN>`）

| 方法 | 路径 | 说明 |
|---|---|---|
| `POST` | `/admin/v1/licenses/generate` | 批量生成卡密 |
| `GET` | `/admin/v1/licenses` | 列表（支持 `product` / `status` / `q` / 分页） |
| `GET` | `/admin/v1/licenses/:key` | 详情（含绑定设备与审计日志，支持前缀匹配） |
| `POST` | `/admin/v1/licenses/ban` | 封禁 |
| `POST` | `/admin/v1/licenses/unban` | 解封 |
| `POST` | `/admin/v1/licenses/unbind` | 强制解绑（不扣用户次数） |

### 激活请求示例

```json
POST /api/v1/activate
{
  "license_key": "0KK46-668Z1-ZTY4Y-97K9A-D1YFA",
  "device_fp": "3f2a...(32~64 位十六进制)",
  "device_name": "DESKTOP-ABC",
  "product": "license-tester",
  "app_version": "1.0.0"
}
```

响应：

```json
{
  "code": 0,
  "msg": "ok",
  "data": {
    "ticket": "<base64url(payload)>.<base64url(signature)>",
    "expires_at": 1785000000,
    "server_time": 1784400000,
    "license": {
      "activation_days": 365,
      "max_activations": 1,
      "activation_count": 1,
      "max_devices": 1,
      "max_unbinds": 3,
      "unbind_count": 0,
      "expires_at": null
    }
  }
}
```

### 错误码

| 码 | 含义 |
|---|---|
| `1001` | 卡密不存在 |
| `1002` | 卡密已被封禁 |
| `1003` | 激活次数已用尽 |
| `1004` | 卡密已过期 |
| `1005` | 绑定设备数已达上限 |
| `1006` | 该卡密不适用于本软件 |
| `2001` | 授权已失效，请重新激活 |
| `3001` | 该设备未绑定到此卡密 |
| `3002` | 解绑次数已用尽 |
| `4001` | 请求参数不合法 |
| `4010` | 管理令牌无效 |
| `4290` | 请求过于频繁 |

---

## 五、授权策略模型

四个独立可配的维度：

| 字段 | 含义 | 消耗时机 |
|---|---|---|
| `max_devices` | **同时**能绑几台设备 | 不消耗，是上限 |
| `max_activations` | 这张卡总共能激活几次 | 每次绑定新设备 −1 |
| `activation_days` | 每次激活授予多少天 | 不消耗，决定票据时长 |
| `max_unbinds` | 总共能解绑几次 | 每次解绑 −1 |
| `refund_on_unbind` | 解绑是否返还激活次数 | 默认 `true` |

票据过期时间：

```
ticket_exp = min(now + activation_days × 86400, license.expires_at)
```

### 典型配置

```
单设备年卡： max_devices=1  max_activations=1  activation_days=365   max_unbinds=3
单设备月卡： max_devices=1  max_activations=1  activation_days=30    max_unbinds=2
3 次卡：    max_devices=1  max_activations=3  activation_days=30    max_unbinds=3
永久卡：    max_devices=1  max_activations=1  activation_days=36500 max_unbinds=5
```

> 永久卡不要用 `expires_at = NULL` 做特例，直接给 `activation_days = 36500`（100 年）。
> 这样续期逻辑统一，代码里少一堆分支。

### 为什么默认「解绑返还激活次数」

用户换电脑、重装系统、换主板都会触发解绑。不返还的话用户会觉得"我买了一次怎么用不了第二次"，客服压力会爆。用 `max_unbinds` 单独限流已经足够防滥用。

要改成不返还，把 `refund_on_unbind` 设为 `false`。

---

## 六、客户端接入要点（.NET）

```csharp
// 1. 验签 —— 三个细节必须对齐
using var ecdsa = ECDsa.Create();
ecdsa.ImportFromPem(publicKeyPem);

var parts = ticket.Split('.');
byte[] signedData = Encoding.ASCII.GetBytes(parts[0]);        // ← 签的是 base64url 字符串本身
byte[] signature  = Base64Url.DecodeFromChars(parts[1]);      // ← System.Buffers.Text.Base64Url
bool ok = ecdsa.VerifyData(signedData, signature, HashAlgorithmName.SHA256);  // ← 默认 P1363
```

```csharp
// 2. 票据载荷
public sealed class TicketPayload
{
    public int V { get; set; }        // 协议版本
    public long Lid { get; set; }     // 卡密 ID
    public string Fp { get; set; }    // 设备指纹，必须与本机一致
    public long Iat { get; set; }     // 签发时间
    public long Exp { get; set; }     // 过期时间
}
```

**客户端要做的事：**

1. **公钥必须硬编码**。不要从服务端拉——中间人可以替换公钥伪造授权。
2. **票据里比对设备指纹**。防止票据被复制到别的机器。
3. **时间回拨检测**。记录上次服务端时间，本地时间早于它超过 1 小时就判定回拨。
4. **校验点分散**。启动时、关键功能入口、定时器（每 30 分钟）各校验一次。单点校验一个 patch 就绕过。
5. **票据本地加密存储**。Windows 用 DPAPI（`CryptProtectData`）。

**离线容忍参数建议：**

| 参数 | 建议值 | 理由 |
|---|---|---|
| 票据有效期 | 7 天 | 断网最多扛 7 天 |
| 心跳间隔 | 24 小时 | 服务端最多 24h 内感知到吊销 |
| 首次激活 | 必须联网 | 没有票据无从验签 |

---

## 七、十个必须避开的坑

| # | 坑 | 后果 | 正确做法 |
|---|---|---|---|
| 1 | 用对称密钥签票据 | 任何人可伪造 | 必须非对称（ECDsa P-256） |
| 2 | 私钥进了 Git 仓库 | 系统彻底废掉 | 环境变量 + `.gitignore` |
| 3 | 每次启动强制联网 | 断网不可用，体验灾难 | 票据 + 离线容忍 |
| 4 | 票据不绑设备 | 一张票据全网传播 | 票据内嵌设备指纹 |
| 5 | 不检测时间回拨 | 改系统时间即绕过 | 服务端时间 + 单调时钟 |
| 6 | 只在一个地方校验 | 一个 patch 即破解 | 多点分散校验 |
| 7 | 明文 HTTP | 中间人伪造响应 | 强制 HTTPS |
| 8 | 卡密用自增 ID | 可枚举，能扫出有效卡 | CSPRNG + Base32 |
| 9 | 数据库存卡密明文 | 泄露即全废 | 存 SHA-256 哈希 |
| 10 | 没有解绑机制 | 客服被问爆 | 自助解绑 + 次数限制 |

---

## 八、诚实预期

**客户端授权没有绝对防破解。** 目标是让破解成本高于购买成本。

真正抗破解的是把价值放在服务端（云同步、在线功能），而不是靠客户端那几行 `if` 校验。桌面软件尤其如此——所有本地校验最终都能被 patch 掉。

---

## 九、目录结构

```
src/
  index.ts        入口：配置校验 → 加载密钥 → 连库 → 建表 → 挂载路由 → 监听
  config.ts       环境变量读取与校验（启动即校验，缺项直接崩）
  crypto.ts       卡密生成 / 票据签名验签（P1363）
  repo.ts         数据访问层（PgRepo 生产 / MemoryRepo 测试）
  service.ts      核心业务：激活 / 心跳 / 解绑 / 卡密管理
  routes.ts       HTTP 路由（只解析请求和包装响应）
  ratelimit.ts    进程内固定窗口限流
public/
  admin.html      管理后台（单文件，无外部依赖）
sql/
  schema.sql      建表 SQL（AUTO_MIGRATE=true 时自动执行）
scripts/
  gen-keys.mjs    生成密钥对
  dev-setup.mjs   本地环境初始化
  smoke.mjs       对运行中的服务做冒烟测试
test/
  e2e.mjs         端到端测试（59 项断言）
```

## 十、本地开发备注

本机 Git Bash 环境有坑，记录一下：

- **8080 端口被沙箱代理占用**，本地开发固定用 8787
- `curl` 访问 localhost 会走代理返回 404，用 Node `fetch` 直连
- `npx` 相关命令需要设 `NO_PROXY=localhost,127.0.0.1`
