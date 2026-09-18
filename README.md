# API-Key · 软件卡密授权系统

给桌面软件做**网络卡密授权**的完整方案。包含服务端、Web 管理后台、以及一个可直接抄进正式软件的 .NET 参考客户端。

```
server/   授权服务端（Node.js + TypeScript + PostgreSQL）+ Web 管理后台
client/   卡密激活测试客户端（.NET 10 + WPF，零第三方依赖）
```

---

## 它解决什么问题

软件卖出去之后，怎么控制"谁能用、能用几台、用多久、能不能远程封禁"。

卡密只是一次性凭据，用完就换成**服务端私钥签名的限时票据**：

```
卡密（125 bit 随机，一次性）
   ↓ 激活时消耗
票据（设备指纹 + 过期时间 + 私钥签名）
   ↓ 之后所有校验都用它，客户端离线也能验
```

**关键点**：服务端持私钥签发票据，客户端只嵌公钥验签。私钥永不出服务器 —— 所以即使客户端被完整逆向，也无法伪造票据。

用对称密钥（HMAC）做这件事是**错的**：密钥在客户端里就能被提取，等于没做。

---

## 能做什么

| 能力 | 说明 |
|---|---|
| 卡密生成 | 125 bit CSPRNG + Base32 分组，不可枚举，自动纠正 O/0、I/L 输入错误 |
| 软件维度隔离 | 卡密绑定到具体产品，A 软件的卡密不能在 B 软件上用 |
| 设备绑定 | 卡密绑定设备指纹（多源采集 + 哈希上报），防票据复制 |
| 次数控制 | 可激活次数、每次激活时长、同时设备数、解绑次数，全部可配 |
| 离线容忍 | 票据自带过期时间，断网仍可用；心跳续期感知吊销 |
| 远程吊销 | 封禁卡密后，客户端下次心跳即失效 |
| 自助解绑 | 用户换机不用找客服，解绑次数可限制 |
| 审计日志 | 每次激活/心跳/解绑都有记录，排查纠纷有据可依 |
| Web 管理后台 | 部署完打开 `/admin`，浏览器里生成/封禁/解绑/查详情 |

---

## 快速开始

### 1. 本地跑服务端

```bash
cd server
npm install
npm run build
node scripts/dev-setup.mjs        # 生成密钥对 + 写 .env
node --env-file=.env dist/index.js
```

打开 `http://localhost:8787/admin`，粘贴控制台打印的 `ADMIN_TOKEN`，生成卡密。

```bash
npm test        # 端到端测试，59 项断言
```

### 2. 部署到 orkestr

详细步骤见 [`server/README.md`](server/README.md)，要点：

1. 推代码到 GitHub → orkestr `Projects → New Project` 选仓库
2. `Add-ons` 添加 **PostgreSQL**（`DATABASE_URL` 自动注入）
3. 配环境变量：`DB_DRIVER=pg`、`ADMIN_TOKEN`、`TICKET_PRIVATE_KEY_PEM`
4. 点 `Deploy`，等状态变 `Live`
5. 访问 `https://<slug>.orkestr.run/admin`

### 3. 跑测试客户端

```bash
cd client
bash build.sh run
```

填服务器地址和软件标识（`license-tester`）→ 粘贴卡密 → 激活 → 本地验签。

---

## 目录结构

```
server/
  src/
    index.ts        入口
    config.ts       环境变量校验
    crypto.ts       卡密生成 / 票据签名验签（ECDsa P-256，P1363 编码）
    repo.ts         数据访问（PgRepo 生产 / MemoryRepo 测试）
    service.ts      核心业务：激活 / 心跳 / 解绑 / 卡密管理
    routes.ts       HTTP 路由
    ratelimit.ts    限流
  public/
    admin.html      Web 管理后台（单文件，无外部依赖）
  sql/schema.sql    建表 SQL
  scripts/
    gen-keys.mjs    生成密钥对
    dev-setup.mjs   本地环境初始化
    smoke.mjs       对运行中的服务冒烟测试
  test/e2e.mjs      端到端测试

client/
  License/
    DeviceFingerprint.cs   设备指纹采集（多源 + 容错）
    TicketVerifier.cs      票据离线验签（P1363）
    LicenseClient.cs       HTTP 客户端
    TicketStore.cs         本地票据存储（DPAPI）
  MainWindow.xaml          测试界面
  build.sh                 构建脚本
```

---

## 三个必须对齐的互操作细节

这是最容易踩的地方，错一个客户端就验不过。服务端已按此配置：

```csharp
using var ecdsa = ECDsa.Create();
ecdsa.ImportFromPem(publicKeyPem);

var parts = ticket.Split('.');
byte[] signedData = Encoding.ASCII.GetBytes(parts[0]);   // ① 签的是 base64url 字符串本身
byte[] signature  = Base64Url.DecodeFromChars(parts[1]); // ② Base64Url 解码
bool ok = ecdsa.VerifyData(signedData, signature, HashAlgorithmName.SHA256); // ③ 默认 P1363
```

1. **签名对象是 payload 的 base64url 字符串本身**，不是解码后的 JSON —— 避免序列化差异
2. **签名编码是 IEEE P1363（r‖s 定长 64 字节）**，不是 DER —— .NET 默认按 P1363 解析
3. **哈希算法 SHA-256**

---

## 安全须知

- **私钥只放服务端环境变量**，绝不进 Git、绝不放进客户端。`keys/` 和 `.env` 已在 `.gitignore` 里
- **正式软件必须硬编码公钥**，不要从服务端拉取（测试客户端为了方便才拉取，中间人可替换公钥）
- **重新生成密钥对会使所有已签发票据失效**，全部用户需重新激活
- 管理后台建议再套一层反向代理的 Basic Auth，或只在内网访问
- 收集设备指纹属个人信息处理，**只取哈希、告知用户、提供解绑途径**

---

## 诚实预期

**客户端授权没有绝对防破解。** 目标是让破解成本高于购买成本。

真正抗破解的是把价值放在服务端（云同步、在线功能），而不是靠客户端那几行 `if` 校验。桌面软件尤其如此 —— 所有本地校验最终都能被 patch 掉。

---

## 环境备注

本机 Git Bash 环境有两个坑，已在本仓库中处理：

- **8080 端口被沙箱代理占用**，本地开发固定用 8787
- .NET SDK 在缺失 Windows 环境变量时会报 `Value cannot be null. (Parameter 'path1')`，
  必须走 `client/build.sh`（用 `env -i` 提供完整环境变量），不要直接调 `dotnet`
