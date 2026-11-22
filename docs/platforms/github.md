# GitHub 接入

> 子包：`justinwongcn/moonauthn/provider/github`
> 协议：GitHub OAuth App / GitHub App 授权码流程（**支持 PKCE**，2025-07 起）；无 `id_token`，身份经 REST API。

## 1. 申请步骤

1. GitHub → **Settings → Developer settings → OAuth Apps → New OAuth App**（或 GitHub App）。
2. 填 **Homepage URL** 与 **Authorization callback URL**（须与代码里 `redirect_uri` 完全一致）。
3. 获得 **Client ID**；点 **Generate a new client secret** 获得 **Client Secret**。
4. GitHub App 还需在应用设置里确认 **Request user authorization (OAuth) during installation** 等回调权限。

## 2. 库内配置

```moonbit
let config = @github.GitHubConfig::new("CLIENT_ID", "https://your.app/auth/github/callback")
  .with_client_secret("CLIENT_SECRET")
```

| 字段 | 默认值 |
|---|---|
| `authorization_endpoint` | `https://github.com/login/oauth/authorize` |
| `token_endpoint` | `https://github.com/login/oauth/access_token` |
| `user_info_endpoint` | `https://api.github.com/user` |
| `user_emails_endpoint` | `https://api.github.com/user/emails` |
| `scopes` | `["read:user", "user:email"]` |

链式覆盖：`with_client_secret(String)` / `with_scopes(Array[String])` / `with_endpoints(authz, token, user, emails)` / `with_http` / `with_clock` / `with_random`。

## 3. 用法

```moonbit
let start = @github.begin_auth(config, @core.SuppliedSecrets::{ state: None, code_verifier: None, nonce: None })
let callback = @core.CallbackParams::from_query_string("code=...&state=...")
let identity = @github.complete_auth(config, callback, start)
```

`identity.uid = id`（数值 → 字符串），`uid_kind = Stable`；`display_name = name ?? login`；
`avatar = avatar_url`；其余字段进 `extra`。

邮箱语义：`/user.email` 是公开邮箱（直接采用，`email_verified = false`）；
为 `null`（私有邮箱）时库自动补拉 `/user/emails`，选择规则：**首个 `primary && verified`
优先；没有主邮箱时回退首个 `verified=true`；只有未验证邮箱时不采用**（2026-11-17
按调研核对补齐回退档——GitHub 私密邮箱场景下列表常无 primary 项）。

## 4. 🔴 踩坑点

- 🔴 **`GET /user` 必须带 `User-Agent` 头**：GitHub API 对缺失 `User-Agent` 的请求一律
  403。库已固定发送 `User-Agent: moonauth`——若替换自定义 `HttpClient` 实现，必须保留。
- 🔴 **token 端点默认回 form-encoded**：`/login/oauth/access_token` 只有在请求带
  `Accept: application/json` 时才回 JSON。库默认换 token 走 `@oauth` seam，
  **seam 恰好固定发送该头**；若自写 token 交换，务必带上。
- 🔴 **私有邮箱是 `null`**：`/user.email` 常为 `null`（用户开了 Keep my email private）。
  库的补拉 `/user/emails` 是**可选增强**：未授予 `user:email` scope 时 GitHub 回非 2xx，
  **增强失败不失败登录**（`uid` 已成立，邮箱记 `None`）——这是有意取舍，勿在本库外重试。
- **PKCE**：GitHub 自 2025-07 起官方支持（OAuth App 与 GitHub App 均可），库默认
  全程启用 S256；`code_challenge_method` 无需自配。
- **回调参数**：成功回调给 `code` + `state`（无 `nonce`）；**失败回调**给
  `error` / `error_description` / `error_uri` / `state`。库在 state 校验通过后读取错误参数，
  归一为 `ProviderError`（`error_uri` 并入消息）——用户拒绝授权不会误报成 `missing_param`。
- **`allow_signup`**：授权 URL 的可选参数，经 `AuthorizeRequest.extra` 即可传
  （本库 facade 默认不带；需要时走 `GitHubProvider` trait 自定义 `begin_auth`）。

## 5. 相关源码

- 配置：`provider/github/config.mbt`
- 默认实现（骑 `@oauth` seam）：`provider/github/backend.mbt`
- `/user` 抓取 + 邮箱增强 + 归一化：`provider/github/user_info.mbt`
- trait（整体替换点）：`provider/github/provider_seam.mbt`
- facade：`provider/github/facade.mbt`
