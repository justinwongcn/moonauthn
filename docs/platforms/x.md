# X（Twitter）接入

> 子包：`justinwongcn/moonauthn/provider/x`
> 协议：标准 OAuth 2.0 授权码 + **PKCE**。

## 1. 申请步骤

1. 打开 [X Developer Portal](https://developer.x.com/) → 创建 Project 与 App。
2. 在 App 的 **User authentication settings** 里启用 **OAuth 2.0**。
3. **Type of App** 选 Web App / Automated App or Bot；填写 **Callback URI**（如 `https://your.app/auth/x/callback`）。
4. 勾选需要的 scopes（库默认 `tweet.read users.read offline.access`）。
5. 记下 **Client ID** 与 **Client Secret**。

## 2. 库内配置

```moonbit
let config = @x.XConfig::new("CLIENT_ID", "https://your.app/auth/x/callback")
```

| 字段 | 默认值 |
|---|---|
| `authorization_endpoint` | `https://twitter.com/i/oauth2/authorize` |
| `token_endpoint` | `https://api.twitter.com/2/oauth2/token` |
| `userinfo_endpoint` | `https://api.twitter.com/2/users/me` |
| `scopes` | `["tweet.read", "users.read", "offline.access"]` |
| `client_secret` | `None`（公共客户端可留空；机密客户端用 `with_client_secret`） |

链式覆盖：`with_client_secret` / `with_scopes` / `with_endpoints(authz, token, userinfo)` / `with_http` / `with_clock` / `with_random`。

## 3. 用法

```moonbit
let start = @x.begin_auth(config, @core.SuppliedSecrets::{ state: None, code_verifier: None, nonce: None })
let callback = @core.CallbackParams::from_query_string("code=...&state=...")
let identity = @x.complete_auth(config, callback, start)
```

`identity.uid` = `data.id`（**数值用户 ID**，X 用户的稳定主键）；`uid_kind = Stable`。
另可单用 `@x.x_identity(userinfo_json)` 做归一化。

## 4. 🔴 踩坑点

- **PKCE 必带**：`begin_auth` 默认生成 `code_verifier` 并带 `code_challenge_method=S256`；X 对公共客户端**强制** PKCE。
- 🔴 **主键用数值用户 ID，不要用 `@handle`**：`@handle` 可被用户改名/被他人抢注，
  而 `data.id` 是永久不变的数值 ID。库取 `data.id` 作为 `uid`。
- **`users.read` 必需**：少了它 `/2/users/me` 会拒绝，取不到身份。
- **`offline.access`** 才会下发 `refresh_token`；否则只有短期 `access_token`。
- **`userinfo_endpoint` 是 `/2/users/me`**：库以 `Authorization: Bearer <access_token>` 调用。
- **`state` 由库校验**：不符抛 `StateMismatch`。

## 5. 相关源码

- 配置：`provider/x/config.mbt`
- 默认实现：`provider/x/backend.mbt`
- 归一化：`provider/x/claims.mbt`
- facade：`provider/x/facade.mbt`
