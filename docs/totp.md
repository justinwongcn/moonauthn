# TOTP（2FA）接入

> 子包：`justinwongcn/moonauth/totp`
> 协议：RFC 6238（TOTP）/ RFC 4226（HOTP 基元），默认实现 `StandardTotpPrimitive`；高层门面 `TotpService`。

## 1. 定位

`totp` 子包把 2FA 的**密码学**内核做到位，且**零状态**：

- **做**：经注入的 `RandomSource` 生成密钥；产出 `otpauth://` URI；在漂移窗口内**恒定时间**校验口令；
  生成恢复码并给出待持久化哈希。
- **不做**：不落库、不建号、不发会话——密钥 / 恢复码明文 / 哈希都随返回值**交给调用方**。

门面**全部同步**（`TotpPrimitive` / `Clock` 都是同步 seam，纯本地 HMAC + 时间读取，无 I/O）。

## 2. 库内配置

```moonbit
let config = @totp.TotpConfig::new("moonauth-demo", "alice@example.com")
```

| 字段 | 说明 | 默认值 |
|---|---|---|
| `issuer` | 服务 / 平台名（`otpauth://` 的 `issuer`） | 构造必填 |
| `account` | 用户账号（`otpauth://` label 后半段） | 构造必填 |
| `digits` | 口令位数（RFC 允许 6 或 8） | `6` |
| `period` | 时间步长（秒） | `30` |
| `algorithm` | HMAC 算法名：`"SHA1"` / `"SHA256"` / `"SHA512"` | `"SHA1"` |
| `window` | 允许的时钟漂移步数（每步 = 一个 `period`） | `1` |

链式覆盖：`with_digits(Int)` / `with_period(Int)` / `with_algorithm(String)` / `with_window(Int)`。
`recommended_secret_bits()` 给出与所选算法输出宽度一致的推荐熵位数（SHA-1 → 160 / SHA-256 → 256 / SHA-512 → 512）。

## 3. 注册（enroll）

```moonbit
let svc = @totp.TotpService::new(config)   // 默认装配 StandardTotpPrimitive + SystemClock；可用 with_* 覆盖

let enrollment = svc.enroll()             // = enroll_with_bits(config.recommended_secret_bits())
// enrollment.secret : Bytes —— 原始共享密钥（保存它才能校验后续口令）
// enrollment.uri    : String —— otpauth://totp/... （渲染为二维码供认证器 App 扫描）
// svc.enroll_with_bits(160) 可用自定义熵位数
```

- 🔴 `enrollment.secret` 是**秘密**：只应展示给用户一次（扫码 / 抄写），**切勿**落日志或明文库。
- 密钥由**注入的** `RandomSource` 生成（`generate_secret(bits)` 返回**原始 `Bytes`**，长度 `ceil(bits/8)`）；
  随机源字节数不足时抛 `InvalidInput`，**绝不**静默截断或补零。

## 4. 🔴 密钥展示：Base32 与二维码**逐字符一致**

除了二维码，很多场景要让用户**手输**密钥。用

```moonbit
@totp.base32_encode(secret)   // Bytes -> String，RFC 4648 Base32（大写、无填充）
```

🔴 **它与 `otpauth_uri` 里的 `secret` 编码逐字符一致**（同走 `@otp.base32_encode_unpadded`），
故「展示给用户手输的密钥」**必然等于**「二维码里的密钥」（LIB-06 ① 的验收点）。

```text
secret(b"12345678901234567890")  ->  GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
uri.contains("secret=" + base32_encode(secret))  ==  true
```

## 5. 校验：恒定时间比较 + 漂移窗口

```moonbit
let ok = svc.verify(secret, code)              // 用注入时钟的「当前」时间 + config.window
let ok = svc.verify_at(secret, code, 59L)      // 指定时间戳（确定性测试 / 补偿历史漂移）
```

- 🔴 **恒定时间比较**：提交口令与期望口令之间用**逐字节异或累加**而非 `==`——`==` 会在首个不同字符处
  提前返回、逐位泄露「前 k 位正确」，攻击者可经时序侧信道逐位试探。异或累加对每一位都执行同样操作、
  无提前返回（长度不同仍立即返回，但 TOTP 口令长度固定，不构成泄漏）。
- **漂移窗口**：在 `at_unix` 的 `±window` 个时间步内逐一比对；`window = 0` 仅当前步有效。
  `window < 0` 抛 `InvalidInput`。窗口外 / 为空的时间戳（`at_unix − k·period < 0`）直接跳过。

## 6. 恢复码

```moonbit
let rec = svc.recovery_codes()          // 10 个；recovery_codes_with(n) 可指定数量
// rec.plaintext : Array[String]  —— 明文，仅展示一次
// rec.hashes    : Array[String]  —— 与 plaintext 一一对应的 hex(sha256(code))
```

- 🔴 **只持久化 `hashes`**；`plaintext` 展示一次后**必须丢弃**（库**只输出哈希、不含明文**的持久化路径）。
- 每个恢复码形如 `XXXX-XXXX`（两组、每组 4 位），字母表剔除易混的 `I` / `L` / `O` / `0` / `1`（共 30 个符号），
  互不重复。

## 7. 自测依据：RFC 6238 附录 B 向量

库内测试对 RFC 6238 附录 B 的官方 SHA-1 / SHA-256 / SHA-512 向量逐条断言（`totp/totp_test.mbt`）。
SHA-1 / 8 位 / 30 秒示例如下（种子为 ASCII `12345678901234567890`）：

| 时间戳 | 口令 |
|---|---|
| `59` | `94287082` |
| `1111111109` | `07081804` |
| `1111111111` | `14050471` |
| `1234567890` | `89005924` |
| `2000000000` | `69279037` |
| `20000000000` | `65353130` |

快速自验（`examples/bare-async` 即以固定种子 + 该向量离线核对）：

```moonbit
svc.verify_at(@contract.rfc6238_sha1_seed(), "94287082", 59L)   // -> true
```

Base32 编码另以 RFC 4648 §10 向量核对（`b"foobar"` → `MZXW6YTBOI` 等）。

## 8. 相关源码

- 配置：`totp/config.mbt`
- 门面（enroll / verify / recovery_codes）：`totp/facade.mbt`
- 默认原语（生成 / URI / 恒定时间校验 / 恢复码 / `base32_encode`）：`totp/primitive.mbt`
- 测试（RFC 6238 / RFC 4648 向量）：`totp/totp_test.mbt`
- 示例：`examples/bare-async/src/main.mbt`
