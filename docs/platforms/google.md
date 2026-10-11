# Google 接入

> 子包：`justinwongcn/moonauth/provider/google`
> 协议：**OIDC + OAuth 2.0 授权码 + PKCE**，`id_token` 为 RS256 / JWKS。

## 1. 申请步骤

1. 打开 [Google Cloud Console](https://console.cloud.google.com/) → 新建（或选择）项目。
2. **API 和服务 → OAuth 同意屏幕**：填写应用名、支持邮箱、授权域；发布状态可为「测试」。
3. **凭据 → 创建凭据 → OAuth 客户端 ID**：类型选「Web 应用」。
4. 在「已获授权的重定向 URI」里**精确**登记你的回调地址，例如 `https://your.app/auth/google/callback`。
5. 记下 **Client ID** 与 **Client Secret**。

## 2. 库内配置

```moonbit
let config = @google.GoogleConfig::new("CLIENT_ID", "https://your.app/auth/google/callback")
```

`GoogleConfig::new(client_id, redirect_uri)` 已填好官方端点与默认 scope：

| 字段 | 默认值 |
|---|---|
| `authorization_endpoint` | `https://accounts.google.com/o/oauth2/v2/auth` |
| `token_endpoint` | `https://oauth2.googleapis.com/token` |
| `jwks_uri` | `https://www.googleapis.com/oauth2/v3/certs` |
| `issuer` | `https://accounts.google.com` |
| `scopes` | `["openid", "email", "profile"]` |
| `client_secret` | `None`（公共客户端可留空；机密客户端用 `with_client_secret`） |

链式覆盖（便于测试注入固定值）：

```moonbit
config
  ..with_client_secret("SECRET")
  ..with_scopes(["openid", "email"])
  ..with_endpoints(authz, token, jwks, issuer)   // 测试时指向 mock://
  ..with_http(client).with_clock(clock).with_random(random)
```

## 3. 用法

```moonbit
let config = @google.GoogleConfig::new("CLIENT_ID", "https://your.app/auth/google/callback")

// ① 开始授权
let start = @google.begin_auth(config, @core.SuppliedSecrets::{ state: None, code_verifier: None, nonce: None })
// ② 回调
let callback = @core.CallbackParams::from_query_string("code=...&state=...")
let identity = @google.complete_auth(config, callback, start)
```

`identity`（`ExternalIdentity`）：`uid = id_token.sub`、`uid_kind = Stable`、`email` / `email_verified`（归一为 `Bool`）、
`display_name = claim["name"]`、`avatar = claim["picture"]`、`extra = 全部 claim`。

## 4. 🔴 踩坑点

- **PKCE 不可省**：`begin_auth` 默认生成 `code_verifier` 并带 `code_challenge_method=S256`；`complete_auth` 会带上
  `start.code_verifier` 换 token。若你自带 verifier，请在 `SuppliedSecrets.code_verifier` 传入。
- **`state` 由库校验**：`complete_auth` 会比对回调 `state` 与 `start.state`，不符抛 `StateMismatch`
  （**在发起任何网络请求之前**）。
- **`nonce` 透传**：`begin_auth` 的 `nonce` 会写入 `id_token` 期望值，`complete_auth` 验签时比对，不符抛 `NonceMismatch`。
- **`email_verified` 是可选 claim**：缺失时库归一为 `false`（不是 `None`）。
- **`iss` 必须匹配**：`with_endpoints` 改了 issuer 后，验签会按新值比对；测试固定向量时勿忘同步。

## 5. 相关源码

- 配置：`provider/google/config.mbt`
- facade / 默认实现：`provider/google/facade.mbt`、`provider/google/backend.mbt`
- 归一化：`provider/google/claims.mbt`
- 契约：`contract/google_contract.mbt`
