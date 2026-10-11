# Discord 接入

> 子包：`justinwongcn/moonauth/provider/discord`
> 协议：Discord OAuth2 授权码流程（**支持 PKCE，仅 S256**）；无 `id_token`，身份经 REST API。

## 1. 申请步骤

1. 打开 [Discord Developer Portal](https://discord.com/developers/applications) → **New Application**。
2. 左侧 **OAuth2** 页复制 **Client ID** / **Client Secret**（Client Secret 点 **Reset Secret** 可重置）。
3. 在 **Redirects** 里添加回调地址（须与代码里 `redirect_uri` 完全一致）。

## 2. 库内配置

```moonbit
let config = @discord.DiscordConfig::new("CLIENT_ID", "https://your.app/auth/discord/callback")
  .with_client_secret("CLIENT_SECRET")
```

| 字段 | 默认值 |
|---|---|
| `authorization_endpoint` | `https://discord.com/oauth2/authorize` |
| `token_endpoint` | `https://discord.com/api/oauth2/token` |
| `user_info_endpoint` | `https://discord.com/api/users/@me` |
| `scopes` | `["identify", "email"]` |

链式覆盖：`with_client_secret(String)` / `with_scopes(Array[String])` / `with_endpoints(authz, token, me)` / `with_http` / `with_clock` / `with_random`。

## 3. 用法

```moonbit
let start = @discord.begin_auth(config, @core.SuppliedSecrets::{ state: None, code_verifier: None, nonce: None })
let callback = @core.CallbackParams::from_query_string("code=...&state=...")
let identity = @discord.complete_auth(config, callback, start)
```

`identity.uid = id`（字符串雪片号），`uid_kind = Stable`；`display_name = global_name ?? username`；
`email` / `email_verified` 需 `email` scope；其余字段进 `extra`。

头像语义：`/users/@me` 的 `avatar` 字段是**哈希**而非完整 URL，库按 Discord 规则拼
`https://cdn.discordapp.com/avatars/{id}/{hash}.png`（`a_` 前缀的动图哈希用 `.gif`）；
哈希为 `null` 时 `avatar = None`（默认头像下标公式需 64 位雪片运算，库不代算——
需要默认头像的调用方可在自己的服务端用 `extra.id` 自行计算）。

## 4. 🔴 踩坑点

- **PKCE 仅 S256**：Discord 只接受 `code_challenge_method=S256`（不接受 `plain`），
  库固定 S256，无配置面。
- **token 请求**：标准 form POST（`client_id` + `client_secret` + `grant_type` +
  `code` + `redirect_uri` + `code_verifier`）；库走 `@oauth` seam，错误体
  `{"error":"invalid_grant",...}` 归一为 `ProviderError`。
- **`email` scope**：`users/@me` 的 `email` / `verified` 字段只在授权含 `email`
  scope 时返回；缺 scope 时 `email = None`、`email_verified = false`。
- **雪片号是字符串**：`id` 在 JSON 里就是字符串（超 32 位），库按字符串原样采用，
  不要当数值转换。
- **`state` 必填**：`complete_auth` 会校验 `state`，不符抛 `StateMismatch`。

## 5. 相关源码

- 配置：`provider/discord/config.mbt`
- 默认实现（骑 `@oauth` seam）：`provider/discord/backend.mbt`
- `/users/@me` 抓取 + 头像拼 URL + 归一化：`provider/discord/user_info.mbt`
- trait（整体替换点）：`provider/discord/provider_seam.mbt`
- facade：`provider/discord/facade.mbt`
