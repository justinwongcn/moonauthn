# Apple 接入

> 子包：`justinwongcn/moonauth/provider/apple`
> 协议：OIDC，`id_token` 为 RS256；client secret 为 **ES256 JWT**；回调走 **`response_mode=form_post`**。

## 1. 申请步骤

1. 登录 [Apple Developer](https://developer.apple.com/account/) → **Certificates, Identifiers & Profiles**。
2. **Identifiers → Services IDs**：新建一个 Services ID（即 `client_id`），启用 **Sign In with Apple**。
3. 配置 **Return URLs**（回调）与 **Domains**。
4. **Keys → 新建 Key**：勾选 Sign In with Apple，下载 `.p8` 私钥（**仅能下载一次**），记下 **Key ID**。
5. 记下 **Team ID**（账号页右上角）与 **Services ID**。

## 2. 库内配置

```moonbit
let key : @core.SigningKey = @core.SigningKey::Pem(p8_private_key_pem)
let config = @apple.AppleConfig::new(
  "com.example.app",                 // client_id = Services ID
  "https://your.app/auth/apple/callback",
  "TEAM_ID",
  "KEY_ID",
  key,
)
```

| 字段 | 默认值 |
|---|---|
| `authorization_endpoint` | `https://appleid.apple.com/auth/authorize` |
| `token_endpoint` | `https://appleid.apple.com/auth/token` |
| `jwks_uri` | `https://appleid.apple.com/auth/keys` |
| `issuer` | `https://appleid.apple.com` |

链式覆盖：`with_scopes` / `with_endpoints(authz, token, jwks, issuer)` / `with_signer` / `with_http` / `with_clock` / `with_random`。

## 3. 用法

```moonbit
let start = @apple.begin_auth(config, @core.SuppliedSecrets::{ state: None, code_verifier: None, nonce: None })
// Apple 用 POST form 回调：body 为 application/x-www-form-urlencoded
let callback = @apple.apple_callback(post_body_string)
let identity = @apple.complete_auth(config, callback, start)

// 归一化工具
@apple.apple_is_private_email(claims)   // -> Bool
@apple.apple_user_name(user_json)       // 从首次授权的 user 字段解析姓名
```

## 4. 🔴 踩坑点

- **client secret 是 ES256 JWT，不是静态字符串**：库用你的 P-256 私钥**每次现签**一个短时效 JWT
  （`iss = Team ID`、`sub = client_id`、`aud = https://appleid.apple.com`、`exp = now + TTL`）。
  调用 `@apple.apple_client_secret(config)` 可单独取用；TTL 默认 `15777000` 秒（< 6 个月上限）。
- **回调是 `form_post`（POST body），不是 query**：`begin_auth` 会自动带 `response_mode=form_post`；
  解析用 `@apple.apple_callback(body)`（`CallbackParams::from_form_body`），**不要**去读 query。
- **`id_token` 验签 + `iss = https://appleid.apple.com`**：与其它 provider 相同走 `oidc`。
- **姓名只返回一次**：Apple 仅在**用户首次授权**时经 `user` 字段返回姓名（且是 JSON 字符串）。
  库**不缓存**它——`complete_auth` 在「本次回调带 `user`」时补入 `display_name`，其余情况为 `None`。
  **若你要保存姓名，必须在首次登录时自行落库**（这是业务职责）。
- **`is_private_email` 两形态**：Apple 可能返回布尔 `true` **或** 字符串 `"true"`。
  库内 `claims.raw` 统一为字符串视图，`apple_is_private_email` 判 `== "true"`，两形态都得到 `true`。
- **无 userinfo 端点**：所有身份信息都在 `id_token` 里，`AppleConfig` **没有** userinfo 端点。

## 5. 相关源码

- 配置：`provider/apple/config.mbt`
- 回调解析（form_post）：`provider/apple/parse.mbt`
- 默认实现 / ES256 secret：`provider/apple/backend.mbt`
- 归一化：`provider/apple/claims.mbt`
