# 切换到官方 SDK

> 对应需求：**SDK-01 / SDK-05**。目标——官方 SDK 出现时，能**按能力粒度**、**尽量不改业务代码**地把
> 库的自实现替换为官方 SDK。

## 1. 为什么能「无痛切换」：一切都是 seam

库把每一个「会变的外部因素 / 可被官方 SDK 取代的能力」都抽成了一个**极窄的 `pub(open) trait`（seam）**。
默认实现只是**其中一种**实现；你的业务代码只依赖 **trait**，不依赖具体实现。

| 能力 | seam（trait） | 库默认实现 | 官方 SDK 可替代？ |
|---|---|---|---|
| 出站 HTTP | `@core.HttpClient` | `@core.AsyncHttpClient` | 是（换传输 / mock） |
| 随机源 | `@core.RandomSource` | `@rand.GetrandomSource` | 是（换 CSPRNG / 固定向量） |
| 时钟 | `@core.Clock` | `@core.SystemClock` | 是（换系统时钟 / 固定时钟） |
| 一次性存储 | `@core.ChallengeStore` | `@store_memory.MemoryChallengeStore` | 是（换 Redis / DB） |
| OAuth 授权码 | `@core.OAuthAuthCode` | `@oauth.StandardOAuthAuthCode` | 是（官方 OAuth 客户端） |
| `id_token` 验签 | `@core.IdTokenVerifier` | `@oidc.JwksIdTokenVerifier` | **是**（官方 OIDC 库） |
| WebAuthn 验签 | `@core.WebAuthnVerifier` | `@passkey.StandardWebAuthnVerifier` | **是**（官方 WebAuthn 库） |
| TOTP | `@core.TotpPrimitive` | `@totp.StandardTotpPrimitive` | **是**（官方 OTP 库） |
| 签名 | `@core.SecretSigner` | 由 `@mooncrypt` 支撑 | 是（官方密码学库） |
| 整个 provider | `@google.GoogleProvider` 等 10 个 | `Default…Provider` | 是（粗粒度整体替换） |

> 🔴 关键：trait 必须声明为 **`pub(open) trait`**，下游才能在**自己的包里**实现它。
> （普通 `pub trait` 是只读的，跨包无法 impl。）

## 2. 两种替换粒度

### 粒度 A：替换**某个能力**（推荐）

只替换 `id_token` 验签，其余照旧——用 `with_id_token` / `with_oauth` / `with_http` / `with_random` / `with_clock` / `with_signer`：

```moonbit
let provider = @google.DefaultGoogleProvider::new(config)
  ..with_id_token(official_id_token_verifier)   // 换验签
  ..with_oauth(official_oauth_client)           // 换换码
```

### 粒度 B：替换**整个 provider**（粗粒度）

直接实现 `<Name>Provider` trait，`Default…Provider` 只是其中一个实现：

```moonbit
struct MyGoogleProvider { /* ... */ }

impl @google.GoogleProvider for MyGoogleProvider with fn begin_auth(self, secrets) { /* ... */ }
impl @google.GoogleProvider for MyGoogleProvider with fn complete_auth(self, callback, expected) { /* ... */ }
```

对 `<Name>Provider` 泛型的业务代码（如 `fn drive(p : &@google.GoogleProvider) { ... }`）**无需改动**。

## 3. 端到端示例（**可直接编译运行**）

完整代码见 [`examples/switch-sdk/src/main.mbt`](../examples/switch-sdk/src/main.mbt)。核心是**跨包实现一个 seam**：

```moonbit
struct OfficialSdkIdTokenVerifier { tag : String }

impl @core.IdTokenVerifier for OfficialSdkIdTokenVerifier with fn verify(self, token, expect) {
  let _ = token
  let _ = expect
  {
    subject: "official-user-1",          // 官方 SDK 给出的 sub
    issuer: "https://issuer.example",
    audience: ["client-1"],
    expires_at: 0L, issued_at: 0L, nonce: None,
    email: Some("official@example.com"), email_verified: Some(true),
    raw: Map([("verified_by", self.tag)]),
  }
}

async fn main {
  let config = @contract.google_mock_config()
  let official : &@core.IdTokenVerifier = OfficialSdkIdTokenVerifier::{ tag: "official-sdk" }
  // 注入官方验签器，替换库默认的 JWKS 验签器：
  let provider = @google.DefaultGoogleProvider::new(config).with_id_token(official)

  let start = provider.begin_auth({ state: Some("st-c1"), code_verifier: Some("verifier-1"), nonce: Some("nonce-1") })
  let callback = @core.CallbackParams::from_query_string("code=auth-code-1&state=st-c1")
  let identity = provider.complete_auth(callback, start)
  println(identity.uid)                    // -> official-user-1
  println(identity.extra.get("verified_by")) // -> Some("official-sdk")
}
```

运行（已验证，输出如下）：

```bash
$ moon run examples/switch-sdk/src
[switch-sdk] uid          = official-user-1
[switch-sdk] email        = official@example.com
[switch-sdk] verified_by  = official-sdk
[switch-sdk] done：官方 SDK 已按能力粒度接管 id_token 验签
```

`uid` 与 `verified_by` 都来自官方适配器 —— 证明替换**真的生效**，且业务侧的 `begin_auth` / `complete_auth`
调用方式**一字未改**。

## 4. 契约测试保证「替换后行为一致」（SDK-04）

`contract/` 里的参数化契约对**任意实现**跑同一套断言：

```moonbit
@contract.run_id_token(() => official_id_token_verifier)   // 对官方 SDK 跑同一套 id_token 断言
@contract.run_oauth(() => official_oauth_client)
@contract.run_webauthn(() => official_webauthn_verifier)
@contract.run_totp(() => official_totp_primitive)
```

契约函数与固定向量解耦（依赖倒置）：你既可以对**库默认实现**跑一遍，也可以对**官方 SDK 适配器**跑一遍，
`pass` 结果一致即证明替换可行。

## 5. 已知差异 / 注意事项

- **`raise AuthError` 是唯一错误约定**：第三方错误类型**不得**出现在任何 `pub` 签名里；
  你的适配层必须在**边界处**把官方 SDK 的错误 `catch` 并转成 `AuthError`（映射见下）。
- **随机 / 时间必须走 seam**：🔴 若官方 SDK 的便捷函数**直接读系统随机 / 时间**，它会**绕过**注入的
  `RandomSource` / `Clock`，导致**确定性测试失效**、注入不可替换。适配时请显式接收并使用库的 seam
  （这是 T04 的实测教训：上游某些高层便捷函数会直读 `@env.rand` / `@env.now`）。
- **`async` 语气要对齐**：I/O 相关 seam（`HttpClient` / `ChallengeStore` / `OAuthAuthCode` / `IdTokenVerifier` /
  provider facade）是 `async fn`；纯计算 seam（`WebAuthnVerifier` / `TotpPrimitive` / `SecretSigner` / `Clock` /
  `RandomSource`）是同步 `fn`。适配层要保持一致。
- **官方 SDK 接口未知（PRD Q3）**：以上映射基于通用标准（OIDC / WebAuthn / RFC 6238）。真机适配层预期很薄；
  若官方接口形态特殊，只需改**适配层一个文件**，不影响库与业务。

### 错误映射建议

| 官方 SDK 错误 | 转成 `AuthError` |
|---|---|
| 网络 / 超时 | `Network(msg)` |
| 非 2xx | `HttpStatus(code, body)` |
| 签名/验签失败 | `SignatureInvalid` |
| token 过期 / 未生效 | `TokenExpired` / `TokenNotYetValid` |
| iss / aud 不符 | `IssuerMismatch` / `AudienceMismatch` |
| 业务错误码 | `ProviderError(code, msg)` |
| 解析失败 | `ParseError(msg)` |

（完整映射见 `core/error_map.mbt` 与架构文档 §4.3。）
