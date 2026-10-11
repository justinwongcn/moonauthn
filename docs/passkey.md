# Passkey（WebAuthn）接入

> 子包：`justinwongcn/moonauth/passkey`
> 协议：W3C WebAuthn Level 2 的**服务端**校验（注册 attestation / 登录 assertion），默认实现
> `StandardWebAuthnVerifier`；高层门面 `PasskeyService`。

## 1. 定位：库做什么 / 不做什么

`passkey` 子包把 WebAuthn 的**服务端**那一半做到位：

- **做**：生成 CSPRNG 挑战 + 经 `ChallengeStore` 做「一次性 + TTL」；产出浏览器 **options 数据结构**
  （`RegistrationOptions` / `AuthenticationOptions`）；对浏览器回传的 attestation / assertion 做
  **密码学校验**（`rpIdHash`、origin、challenge、UV、签名、`signCount` 回退）。
- **不做**：不运行浏览器、不产出浏览器可直接吞的 JSON/`ArrayBuffer`、不建号、不存凭据映射。

🔴 这一「边界」极易被误解为「调一下库就完事」，**务必先读 §4**。

## 2. 库内配置

```moonbit
let config = @passkey.PasskeyConfig::new("example.com", "Example", "https://example.com")
```

| 字段 | 说明 | 默认值 |
|---|---|---|
| `rp_id` | Relying Party ID（可注册域，如 `example.com`），与 `authenticatorData.rpIdHash` 绑定 | 构造必填 |
| `rp_name` | RP 展示名（写入浏览器创建选项，供用户识别） | 构造必填 |
| `expected_origin` | 期望的完整来源（如 `https://example.com`），与 `clientDataJSON.origin` **严格相等**比对 | 构造必填 |
| `require_user_verification` | 是否**强制** UV（`true` 时缺少 UV 标志的凭据被拒） | `false` |
| `challenge_ttl_seconds` | 挑战存活秒数（`ChallengeStore` 的 TTL） | `300`（5 分钟） |

链式覆盖：`with_user_verification(Bool)` / `with_challenge_ttl(Int)`。

`rp_id` 与 `expected_origin` 是 WebAuthn 的两条**绑定**依据，**缺一不可**：前者防跨站点，后者防跨来源
（含跨源 iframe）攻击。

## 3. 两步式流程（**不是一步**）

🔴 `begin_registration()` / `begin_authentication()` **只**返回一个 `PasskeyChallenge`（含 `challenge` /
`key` / `expires_at`），**不**返回浏览器 options。options 要**再调一次** `registration_options` /
`authentication_options` 组装。**不要**写成「`begin_*` 直接返回 options」。

### 3.1 注册（registration）

```moonbit
// 装配：默认 HTTP/存储/随机/时钟；可用 with_* 覆盖（测试注入固定随机源 / 固定时钟 / 失败存储）
let svc = @passkey.PasskeyService::new(config)

// ① 库：生成 CSPRNG 挑战并经 ChallengeStore 存储（一次性 + TTL）
let ch = svc.begin_registration()

// ② 库：由挑战 + 用户信息组装浏览器创建选项
let user = @passkey.UserInfo::{ id: b"user-handle-1", name: "alice@example.com", display_name: Some("Alice") }
let opts = svc.registration_options(
  ch,
  user,
  authenticator_selection=Some(@passkey.AuthenticatorSelection::passkey()),  // 见 §5：要真 passkey 必须给
)
// ③ 调用方：序列化 opts 为 JSON 发到前端；前端调 navigator.credentials.create()
// ④ 调用方：把 clientDataJSON / attestationObject 装进 @core.RegistrationInput
// ⑤ 库：收尾密码学校验
//    托管式（challenge 由库经 store 管理，多实例可共享 Redis）：
let reg = svc.finish_registration_stored(ch.key, registration_input)
//    或无状态式（调用方自管 challenge，注意 expected_challenge 要等于 ch.challenge）：
// let reg = svc.finish_registration(registration_input)
```

### 3.2 登录（authentication）

```moonbit
let ch = svc.begin_authentication()
let opts = svc.authentication_options(ch)            // 可再传 allow_credentials / user_verification / timeout
// ③④ 前端 navigator.credentials.get() → 把 authenticatorData / signature 等装进 @core.AssertionInput
let assertion = svc.finish_authentication_stored(ch.key, assertion_input)
```

### 3.3 托管式（`*_stored`）vs 无状态式（`finish_*`）

| | 挑战谁持有 | 适用 | 收尾方法 |
|---|---|---|---|
| **托管式** | 库经 `ChallengeStore`（`begin_*` 写入、`finish_*_stored` 取出，`take` 一次性） | 多实例部署（共享 Redis / DB） | `finish_registration_stored(key, input)` / `finish_authentication_stored(key, input)` |
| **无状态** | **调用方**（自己存 `ch.challenge` 并填进 `input.expected_challenge`） | 单机 / 自管会话 | `finish_registration(input)` / `finish_authentication(input)` |

> 两者**都**声明为 `async fn`（门面整体 async，调用方无需区分）；真正需要**同步**校验时可绕开门面，
> 直接用同步 seam `@passkey.StandardWebAuthnVerifier`。

## 4. 🔴 能力边界（**最容易误解的地方，务必读完**）

> **库产出的是 options 数据结构**；它**不**运行浏览器、**不**产出浏览器可直接吞的 JSON/ArrayBuffer。真实链路：
> ① 库 `begin_registration()` 生成 CSPRNG 挑战并存入 `ChallengeStore`；
> ② 库 `registration_options(ch, user)` 产出 `RegistrationOptions`；
> ③ **调用方**把 options **序列化为 JSON**（字段名按其 doc 的 **camelCase** 映射：`pubKeyCredParams` / `rpId` / `displayName` / `allowCredentials`…）发到前端；
> ④ **调用方**前端把 `challenge`（**base64url 字符串**）转为 `ArrayBuffer`，调 `navigator.credentials.create()` / `.get()`；
> ⑤ **调用方**把 `clientDataJSON` / `attestationObject`（或 assertion 的 `authenticatorData` / `signature`）装进 `@core.RegistrationInput` / `AssertionInput`（`expected_challenge = ch.challenge`）；
> ⑥ 库 `finish_*` 做密码学校验。
>
> → **库省掉的是「WebAuthn options 结构 + challenge 生成 + 校验」；JSON 序列化与 `ArrayBuffer` 转换仍在调用方。**

`RegistrationOptions` / `AuthenticationOptions` 各字段的浏览器 JSON 名（camelCase）写在
`passkey/types.mbt` 的字段 doc 里；例如 `pub_key_cred_params` → `pubKeyCredParams`、`rp` → `rp`、
`user.display_name` → `displayName`、`allow_credentials` → `allowCredentials`。

## 5. 🔴 拿到**真 passkey**（可发现凭据）的关键

**必须**用 `@passkey.AuthenticatorSelection::passkey()` 请求**可发现凭据**：

```moonbit
let sel = @passkey.AuthenticatorSelection::passkey()
// = { authenticator_attachment: Some("platform"), resident_key: Some("required"),
//     user_verification: Some("required"), require_resident_key: None }
```

- **不要以为默认就会拿到 passkey**——不给这组值（尤其 `resident_key = "required"`）拿到的只是
  **绑定式凭据**（不可发现，登录时必须由服务端先给出 `allowCredentials` 列表），并非真正的 passkey。
- 把它放进 `registration_options(..., authenticator_selection=Some(sel))`。
- 🔴 `authenticatorSelection` 在浏览器侧是**对象**（`AuthenticatorSelectionCriteria`），**不是字符串**。

## 6. 🔴 踩坑点

- 🔴 **`crossOrigin = true` 被拒**：`clientDataJSON.crossOrigin` 为 `true`（跨源 iframe）→ 抛
  `CrossOriginRejected`。该标志**不在**底层 `verify_client_data` 的检查范围内，本实现自解析以覆盖它。
- 🔴 **同一 challenge 二次使用被拒**：托管式 `take` 是**一次性**的——第二次取用返回 `None` → 抛
  `ChallengeNotFound`。注册 / 认证各 `begin_*` 一次、`finish_*` 一次，不可复用同一挑战。
- 🔴 **`signCount` 回退检测**：任一方非零且 `received <= stored` → 抛 `SignCountRegression(stored, received)`
  （可疑克隆）。例外面：**`stored = received = 0` 时跳过**（大量认证器恒报 0，计数器不可比）。
- 🔴 **`*_stored` 的存储故障会抛 `AuthError`，而不是「不存在」**：`ChallengeStore.take` 以
  `raise AuthError` 表达**基础设施故障**，以 `None` 表达**「不存在 / 已用 / 过期」**（成功语义）。
  门面**原样透传**存储抛出的错误——若把 `take` 的异常吞成 `None`，就会把「Redis 连接失败」误判为
  「挑战不存在」（≈ 把故障误报成重放 / 凭据失效）。**不要把两者混为一谈**。
- **挑战 TTL 默认 300s**：超时后 `take` 返回 `None` → `ChallengeNotFound`。
- **`expected_challenge` / `origin` / `type` 严格比对**：`clientDataJSON.challenge` 必须**严格等于**
  期望挑战，`origin` 必须**严格等于** `config.expected_origin`，`type` 必须为 `webauthn.create`（注册）/
  `webauthn.get`（登录），否则分别抛 `ChallengeMismatch` / `OriginMismatch` / `TypeMismatch`。
- **`with_clock` 不会重建 `store` 内部时钟**：若需存储也用新时钟，请显式
  `with_store(<用该 clock 构造的 store>)`。

## 7. 可直接抄的代码

**优先引用** [`examples/bare-async/src/main.mbt`](../examples/bare-async/src/main.mbt) 的 passkey 段——
它就是「`begin_registration()` → `registration_options(...)` + `AuthenticatorSelection::passkey()`」的最小可运行版本，
运行 `moon run examples/bare-async/src` 可见输出：

```text
[passkey] challenge          = bW9vbmF1dGgtYmFyZS1hc3luYy1zZWVkbW9vbmF1dGg
[passkey] store key          = pk:reg:6d6f...
[passkey] options.rp.id      = example.com
[passkey] options.user.name  = alice@example.com
[passkey] pubKeyCredParams   = n=1 type=public-key alg=-7
[passkey] authSel            = attachment=platform residentKey=required userVerification=required
```

`alg=-7` 即 ES256；`authSel` 三个值即 §5 的可发现凭据组合。完整验签断言集（注册 + 认证 + 负例）由
`@contract.run_webauthn(() => @passkey.StandardWebAuthnVerifier::new())` 给出（`12/12 passed`）。

## 8. 相关源码

- 配置：`passkey/config.mbt`
- 门面（两步式 / 托管式 / options 组装）：`passkey/facade.mbt`
- options / 用户实体 / 选择标准类型：`passkey/types.mbt`
- 默认验签器（`crossOrigin` / `signCount` / 映射 `AuthError`）：`passkey/verifier.mbt`
- 示例：`examples/bare-async/src/main.mbt`
