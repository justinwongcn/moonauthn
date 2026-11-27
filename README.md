# moonauth

**框架无关、不持有任何状态的第三方登录 / Passkey / 2FA 开源工具库**（MoonBit）。

`moonauth` 只封装十一个平台（含 Microsoft Entra ID）的第三方登录、WebAuthn（passkey）与 TOTP（2FA）的**协议与密码学细节**；
账号注册逻辑与所有状态由**你自己**实现。

> 🔴 **三句定位声明（务必先读）**
> - **库不建号**：不创建、不修改任何用户账号。
> - **库不存映射**：不保存 `uid ↔ 用户` 的对应关系（`ExternalIdentity` 交还给你，落库由你负责）。
> - **库不发会话**：不签发、不校验 session / token / cookie，不持有任何登录态。

---

## 目录

- [解决什么问题](#解决什么问题)
- [支持 target 矩阵](#支持-target-矩阵)
- [安装](#安装)
- [5 分钟快速开始（Google）](#5-分钟快速开始google)
- [子包一览](#子包一览)
- [示例](#示例)
- [可替换性（官方 SDK 切换）](#可替换性官方-sdk-切换)
- [平台文档](#平台文档)
- [开发与 CI](#开发与-ci)
- [许可证](#许可证)

---

## 解决什么问题

接入「微信 / QQ / 支付宝 / Google / Apple / X / GitHub / Discord / 钉钉 / 飞书」的第三方登录、passkey 与 2FA，是一件**协议细节极多、
极易踩坑、且与业务无关**的脏活：

- 微信授权 URL 的参数**顺序**被服务端强校验，且必须带 `#wechat_redirect`；
- QQ 的 token 端点默认 **form-encoded**（需 `fmt=json` 才回 JSON），`/oauth2.0/me` 默认返回 **JSONP**；
- 支付宝是**非标准 OAuth2**：RSA2 签名要求参数 key 按 **ASCII 升序**、去空值、原值不 URL 编码；
- Apple 的 client secret 是 **ES256 JWT**、回调走 **`response_mode=form_post`**、姓名**仅首次**返回；
- WebAuthn 的 `origin` / `rp_id_hash` / challenge 一次性、`signCount` 回退检测。

每个开发者都在重复踩同样的坑。`moonauth` 把它们**一次性、可测试地**做对。

**不解决什么**：账号怎么建、身份映射怎么存、会话怎么发、页面怎么画——那是业务，不是库的事。

## 支持 target 矩阵

| Target | 支持 | 说明 |
|---|---|---|
| `native` | ✅ | 首选目标；`moon build --target native` 全绿 |
| `js` | ✅ | `moon build --target js` 全绿 |
| `wasm-gc` | ❌ | **明确不支持**，原因见下 |

🔴 **为什么 `wasm-gc` 不支持**：库的 CSPRNG（passkey challenge / OAuth `state` 随机数）来自
`justinwongcn/experimental_crypto/getrandom`，而它只声明支持 `[js, native]`——

```
wasm-gc  ❌ 'justinwongcn/experimental_crypto/getrandom' supports [js, native]
```

随机数是 passkey challenge 与 OAuth state 的**安全必需件，不可绕过**，故 `wasm-gc` 不在支持范围内。
唯一的 `getrandom` 引用点是 `rand/` 子包（`GetrandomSource`）；其余子包只经 `RandomSource` seam 取随机数，
理论上可由调用方注入自定义 `RandomSource` 以在 `wasm-gc` 上跑「纯验签子集」（**未实测，P2**）。

## 安装

在模块的 `moon.mod` 里声明依赖：

```moonbit
name = "your/app"
version = "0.1.0"

import {
  "justinwongcn/moonauthn@0.1.1",
}
```

然后按需在包清单（`moon.pkg`）里 import 具体子包，例如只要 Google：

```moonbit
import {
  "justinwongcn/moonauthn/provider/google" @google,
}
```

> 子包彼此隔离（LIB-20）：只 import 你真正用到的那条链路即可，**不会**把其他平台拖进依赖图。

## 5 分钟快速开始（Google）

**① 组装配置**（`GoogleConfig::new` 已填好官方端点，无需手抄）：

```moonbit
let config = @google.GoogleConfig::new("YOUR_CLIENT_ID", "https://your.app/cb")
```

**② 开始授权**——`begin_auth` 返回一个 `AuthStart`（含 `url` / `state` / `code_verifier` / `nonce`）：

```moonbit
let secrets : @core.SuppliedSecrets = {
  state: None,          // 留空 → 由注入的 RandomSource 生成
  code_verifier: None,  // 留空 → PKCE verifier 自动生成
  nonce: None,          // 留空 → OIDC nonce 自动生成
}
let start = @google.begin_auth(config, secrets)
// 把浏览器 302 到 start.url；把 start 暂存在你的会话/缓存里（库不替你存）
println(start.url)
```

**③ 处理回调**——框架把回调 query 变成 `CallbackParams`，交给 `complete_auth` 拿回 `ExternalIdentity`：

```moonbit
let callback = @core.CallbackParams::from_query_string(code_and_state_from_query)
let identity = @google.complete_auth(config, callback, start)
// identity.uid / identity.email / identity.email_verified / identity.uid_kind ...
println(identity.uid)          // = Google 的 sub
```

**④ 落库——由你决定**：`identity` 是**纯数据**。`uid ↔ 你的用户` 的映射、账号创建、会话签发，
全部是你的业务代码；库到此为止。

> 完整可运行、**零网络零资质**（固定向量）的版本见 [`examples/minimal-google`](examples/minimal-google)
> 与 [`examples/bare-async`](examples/bare-async)。

## 子包一览

| 子包 | 能力 |
|---|---|
| `core` | 值类型（`ExternalIdentity` / `AuthStart` / `CallbackParams` …）、`AuthError`、能力 **seam**（trait）、字典序工具 |
| `rand` | `RandomSource` 默认实现 `GetrandomSource`（**唯一**接触 `getrandom` 的地方） |
| `oauth` | OAuth 2.0 授权码 + PKCE 默认实现（`StandardOAuthAuthCode`）、`base64url` 工具 |
| `oidc` | OIDC `id_token` 验签（`JwksIdTokenVerifier`，RS256/JWKS） |
| `passkey` | WebAuthn 验签（`StandardWebAuthnVerifier`）+ `PasskeyService`（challenge 一次性 + TTL） |
| `totp` | TOTP / 恢复码（`StandardTotpPrimitive` + `TotpService`） |
| `store-memory` | `ChallengeStore` 内存实现（`MemoryChallengeStore`） |
| `provider/google` `provider/apple` `provider/x` `provider/wechat` `provider/qq` `provider/alipay` `provider/github` `provider/discord` `provider/dingtalk` `provider/feishu` `provider/microsoft` | 十一个平台的 facade（`begin_auth` / `complete_auth` + 归一化），每个**相互隔离**；飞书内置 **Lark 国际版**端点预设（`with_lark()`，已按官方文档核实）；钉钉国际站端点**未能核实故不内置**（用 `with_endpoints` 配置，见其平台文档）；微信另含**小程序登录** `wechat_code2_session`（官方文档核实），支付宝身份键 `open_id` 优先（官方口径） |
| `contract` | 参数化契约测试骨架（SDK-04）+ 固定测试向量，**下游可复用** |

## 示例

| 示例 | 演示 |
|---|---|
| [`examples/minimal-google`](examples/minimal-google) | 只依赖 `provider/google` 的最小模块（LIB-20 隔离断言） |
| [`examples/bare-async`](examples/bare-async) | 裸 `async` handler：串起 **Google + passkey + TOTP**（mock/向量，零网络） |
| [`examples/moonback`](examples/moonback) | [`moonback`](https://mooncakes.io/docs/moonbitlang/moonback) **只做路由**，鉴权走库 |
| [`examples/switch-sdk`](examples/switch-sdk) | 只替换 `IdTokenVerifier`，验证业务代码不变、能力级替换生效 |

四个示例均不依赖真实资质或外部网络；其中 `moonback` 用一次性回环请求驱动真实路由，完成后自动关闭：

```bash
moon run examples/minimal-google/src --target native  # 最小引入与 LIB-20 隔离
moon run examples/bare-async/src --target native      # Google 身份 / passkey 12/12 / TOTP RFC 6238 向量
moon run examples/moonback/src --target native        # /healthz 与 /auth/google/callback（含 state 负例）
moon run examples/switch-sdk/src --target native      # 官方 SDK 适配器接管 id_token 验签
```

> 🔴 注意：`examples/*` 是**独立模块**（经工作区文件 `moon.work` 以**本地路径**解析库），
> 它们**不进**库本体的依赖图。

## 可替换性（官方 SDK 切换）

库对每个能力都定义了**极窄的 seam（`pub(open) trait`）**，官方 SDK 一旦出现，你可以**按能力粒度**替换，
而不必改动业务代码：

```moonbit
// 用官方 SDK 的验签替换库默认实现：实现 trait 即可
struct OfficialVerifier { /* ... */ }

impl @core.IdTokenVerifier for OfficialVerifier with fn verify(self, token, expect) {
  // 调官方 SDK……
}
```

详见 [`docs/switch-to-official-sdk.md`](docs/switch-to-official-sdk.md)（含**可直接编译运行**的端到端示例）。

## 平台文档

- [Google](docs/platforms/google.md)
- [Apple](docs/platforms/apple.md)
- [微信 WeChat](docs/platforms/wechat.md)
- [QQ](docs/platforms/qq.md)
- [支付宝 Alipay](docs/platforms/alipay.md)
- [X (Twitter)](docs/platforms/x.md)
- [GitHub](docs/platforms/github.md)
- [Discord](docs/platforms/discord.md)
- [钉钉 DingTalk（含国际站）](docs/platforms/dingtalk.md)
- [飞书 Feishu / Lark](docs/platforms/feishu.md)
- [Microsoft Entra ID](docs/platforms/microsoft.md)
- [Passkey（WebAuthn）](docs/passkey.md)
- [TOTP（2FA）](docs/totp.md)
- [从 v1「认证服务」迁移](docs/migration-from-v1-service.md)

## 开发与 CI

```bash
moon build --target native     # native 编译
moon build --target js         # js 编译
moon test  --target native     # 全量测试（native，含 vendored third_party 套件；Windows 本机有 2 个上游环境性用例失败）
moon test  --target js         # 全量测试（js，含 vendored third_party 套件；同上）
./ci/check.sh                  # 本地一键 CI：双 target 编译 + moonauth 自有包测试 + 隔离/泄漏断言 + 文档一致性
```

CI 逻辑集中在 [`ci/check.sh`](ci/check.sh)（**本机可直接运行**）；`.github/workflows/ci.yml` 只负责
`checkout` 后调用同一个脚本，两处行为一致。

## 许可证

Apache-2.0，见 [LICENSE](LICENSE)。本地 vendored 代码的来源与许可证说明见
[`third_party/moonbitlang-x/VENDORED.md`](third_party/moonbitlang-x/VENDORED.md)。
