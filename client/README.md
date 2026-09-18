# 卡密授权测试客户端

用来验证授权服务端是否正常工作的桌面工具。同时也是一份**可直接抄进正式软件的参考实现**。

- .NET 10 + WPF，**零第三方 NuGet 依赖**（全部 BCL + Win32 P/Invoke）
- 完整演示：设备指纹采集 → 激活 → 离线验签 → 心跳续期 → 解绑

---

## 一、跑起来

```bash
# 构建
bash build.sh

# 构建并启动
bash build.sh run

# 发布单文件 exe
bash build.sh publish
```

> 本机 Git Bash 缺 Windows 环境变量会导致 .NET SDK 报
> `Value cannot be null. (Parameter 'path1')`，所以必须走 `build.sh`
> （它用 `env -i` 提供完整的 Windows 风格环境变量）。不要直接调 `dotnet`。

### 使用步骤

1. 先启动服务端：`node --env-file=.env dist/index.js`（默认 `http://localhost:8787`）
2. 打开服务端管理后台 `http://localhost:8787/admin`，粘贴 `ADMIN_TOKEN`，生成卡密
3. 打开本客户端，填**服务器地址**和**软件标识**（`license-tester`）
4. 粘贴卡密 → 点「激活」
5. 点「本地验签」——**不联网**验证票据真伪，这是客户端授权的信任根
6. 点「心跳续期」验证吊销链路

---

## 二、验证清单

按顺序做一遍，能覆盖整条授权链路：

| 步骤 | 预期结果 |
|---|---|
| 填错卡密激活 | 提示「卡密不存在」（1001） |
| 用别的软件的卡密 | 提示「该卡密不适用于本软件」（1006） |
| 正确卡密激活 | 成功，状态显示「✓ 授权有效（本地验签通过）」 |
| 同设备再点激活 | 幂等成功，**激活次数不增加** |
| 点「本地验签」 | 断网也能通过 |
| 点「心跳续期」 | 返回新票据，到期时间延后 |
| 后台封禁该卡密 | 再点心跳 → 提示「卡密已被封禁」（1002） |
| 后台解封 → 心跳 | 恢复正常 |
| 点「解绑本设备」 | 成功，本地票据被清除 |
| 解绑后再激活 | 成功（默认返还激活次数） |
| 后台查看卡密详情 | 能看到绑定设备与完整审计日志 |

---

## 三、三个必须对齐的验签细节

这是最容易踩的地方，错一个就验不过。服务端已经按这个配置好了：

```csharp
using var ecdsa = ECDsa.Create();
ecdsa.ImportFromPem(publicKeyPem);

var parts = ticket.Split('.');
byte[] signedData = Encoding.ASCII.GetBytes(parts[0]);   // ① 签的是 base64url 字符串本身
byte[] signature  = Base64Url.DecodeFromChars(parts[1]); // ② Base64Url 解码
bool ok = ecdsa.VerifyData(signedData, signature, HashAlgorithmName.SHA256); // ③ 默认 P1363
```

1. **签名对象是 payload 的 base64url 字符串本身**（的 ASCII 字节），不是解码后的 JSON。
   这样客户端不需要重新序列化 JSON，避免字段顺序/空白差异导致验签失败。
2. **签名编码是 IEEE P1363（r‖s 定长 64 字节）**，不是 DER。
   .NET `ECDsa.VerifyData` 默认按 P1363 解析；服务端对应配置了 `dsaEncoding: "ieee-p1363"`。
   如果你看到 `签名校验失败` 但票据明明是对的，八成是这里不一致。
3. **哈希算法 SHA-256**。

---

## 四、设备指纹

多源采集 + 容错，任何一项取不到就跳过，不让整个指纹生成失败：

| 来源 | 实现 | 变化时机 |
|---|---|---|
| MachineGuid | 注册表 `HKLM\SOFTWARE\Microsoft\Cryptography` | 重装系统 |
| 系统盘卷序列号 | `GetVolumeInformation` (P/Invoke) | 格式化 |
| 首张物理网卡 MAC | `NetworkInterface`（排序后取第一个，避免枚举顺序漂移） | 换网卡 |

最终只上传 **SHA-256 哈希**，**不上传任何原始硬件信息**。点「查看采集明细」可以看到各项原始值（仅本地展示）。

> ⚠️ 任一来源变化都会导致指纹变化，用户需要解绑后重新激活。
> 这正是 `max_unbinds` 存在的意义。

---

## 五、本地票据存储

位置：`%APPDATA%\LicenseTester\license.bin`

用 Windows DPAPI（`CryptProtectData`，P/Invoke）加密，密钥绑定当前用户——别人拷走这个文件在他机器上也解不开。

> DPAPI 只是提高门槛，不是真正的防线。
> 真正的防线是：**票据里绑定了设备指纹，且由服务端私钥签名**。
> 即使有人解开本地文件，票据也只能在本机使用。

---

## 六、⚠️ 测试客户端与正式软件的区别

本客户端为了方便，**从服务端拉取验签公钥**。这在正式软件里是**错误做法**：

> 中间人可以替换公钥，然后用伪造的私钥签发票据，客户端会全部验过。

**正式软件必须把公钥硬编码进客户端**：

```csharp
internal static class LicensePublicKey
{
    public const string KeyId = "cf2c428186b75c917c9ad2e1a3779beb";

    public const string Pem = """
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGHfBI4YStJeUMHWSuiy5U+F7H0oQ
bDuIBO/7aJKnpzp4WGsrHI7JJrb0pnb4eeedV6A+xI/ZyYF2qr1GvTRZsw==
-----END PUBLIC KEY-----
""";
}
```

（上面是示例，用 `npm run gen-keys` 生成你自己的。`keys/public.csharp.txt` 就是这个格式。）

公钥**可以公开分发**——它的作用就是让客户端验证票据真伪。

---

## 七、目录结构

```
LicenseTester.csproj
App.xaml / App.xaml.cs          应用入口
MainWindow.xaml / .xaml.cs      界面与交互逻辑
License/
  Models.cs                     服务端响应 DTO + 票据载荷
  DeviceFingerprint.cs          设备指纹采集（多源 + 容错）
  TicketVerifier.cs             票据离线验签（P1363）
  LicenseClient.cs              HTTP 客户端（HttpClient + System.Text.Json）
  TicketStore.cs                本地票据存储（DPAPI P/Invoke）
build.sh                        构建脚本（含 Windows 环境变量修正）
```

---

## 八、抄到正式软件里要注意什么

1. **公钥硬编码**，不要从服务端拉（见第六节）
2. **校验点分散**：启动时、关键功能入口、定时器各校验一次。单点校验一个 patch 就绕过
3. **时间回拨检测**：记录上次服务端时间，本地时间早于它超过 1 小时就判定回拨
4. **首次激活必须联网**，之后靠票据离线运行
5. **票据有效期建议 7 天 + 24 小时心跳**，兼顾离线容忍与吊销时效
6. **客户端混淆**（.NET 用 ConfuserEx / .NET Reactor）+ 程序集完整性自校验
7. **诚实预期**：本地校验最终都能被 patch 掉。真正抗破解的是把价值放在服务端
