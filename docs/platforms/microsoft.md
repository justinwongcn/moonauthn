# Microsoft Entra ID 接入

> 子包：`justinwongcn/moonauth/provider/microsoft`
> 协议：Microsoft identity platform **v2.0** + OIDC，`id_token` 为 RS256；PKCE S256 恒启用。
> 依据：调研文档 `docs/providers/microsoft.md`（2026-11-13 官方接口已核验）。

## 1. 申请步骤

1. 打开 [Microsoft Entra admin center](https://entra.microsoft.com/) → **应用注册 → 新注册**。
2. 填写显示名并选择**支持的账户类型**（决定可用 tenant，见 §3）。
3. **重定向 URI** 选「Web」类型并**精确**登记（不要选 `spa`——SPA 回调的 refresh token
   有 24 小时限制，属不同安全模型；本库首版面向 Web 机密客户端）。
4. **证书和密码 → 新建客户端密码**，记下 Value（即 `client_secret`；仅显示一次）。
5. 记下 **应用程序（客户端）ID**（`client_id`）与 **目录（租户）ID**（`tid`）。
6. 如需 refresh token，授权请求 scope 中包含 `offline_access`。

## 2. 库内配置

```moonbit
let config = @microsoft.MicrosoftConfig::new("CLIENT_ID", "https://your.app/auth/microsoft/callback")
  .with_client_secret("CLIENT_SECRET")
```

| 字段 | 默认值 |
|---|---|
| `tenant` | `common` |
| `authorization_endpoint` | `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize` |
| `token_endpoint` | `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` |
| `jwks_uri` | `https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys` |
| `issuer_template` | `https://login.microsoftonline.com/{tid}/v2.0`（`{tid}` = token 的 tid） |
| `scopes` | `["openid", "profile", "email"]` |
| `allowed_tenant_ids` | `[]`（不做白名单） |

链式覆盖：`with_tenant(String)` / `with_allowed_tenant_ids(Array[String])` /
`with_issuer_template(String)` / `with_client_secret(String)` / `with_scopes(Array[String])` /
`with_endpoints(authz, token, jwks)` / `with_http` / `with_clock` / `with_random`。

## 3. 用法

```moonbit
let start = @microsoft.begin_auth(config, @core.SuppliedSecrets::{ state: None, code_verifier: None, nonce: None })
// 回调（GET query）：code + state（+ session_state，后者不替代本库 state 校验）
let callback = @core.CallbackParams::from_query_string("code=...&state=...")
let identity = @microsoft.complete_auth(config, callback, start)
```

`identity.uid = sub`（pairwise，同一应用内稳定），`uid_kind = Stable`；
`display_name = name`（缺省回退 `preferred_username`）；`avatar` 恒 `None`
（v2.0 id_token 无头像声明）；`extra` 含 `tid` / `oid` / `groups` / `roles` 等全部声明
（字符串视图）——`tid` / `oid` 供租户策略与审计，**不可取代 `sub` 作主键**。

## 4. 🔴 踩坑点

- 🔴 **issuer 是 per-tenant 的，绝不静态匹配**：`common` / `organizations` 只是
  Discovery 元数据入口；每枚 ID Token 的 `iss` 都带**签发租户**的 tid
  （`https://login.microsoftonline.com/{tid}/v2.0`）。库在换 token 后从**未验签** claims
  取 `tid` → 租户白名单（如配置）→ 按 `issuer_template` 派生**精确 issuer** 再验签
  ——绝不做前缀 / 包含匹配。未验签的 `tid` 只用于选公钥 / 选 issuer，不参与身份语义。
- 🔴 **租户白名单**：`with_allowed_tenant_ids([...])` 非空时，token 的 `tid` 不在
  白名单（或缺失）→ `ProviderError("tenant_not_allowed", ...)`。白名单为空 = 接受任何
  能通过签名 / `aud` / `nonce` 校验的微软租户（多租户应用形态）。
- 🔴 **企业系统用显式 tenant-id 而非 `common`**：`common` 不构成安全边界
  （任何组织的账号都能走通流程）；`with_tenant("<tenant-id>")` 会同步重算三类端点。
- **回调错误参数**：失败回调带 `error` / `error_description` / `error_codes` / `state`。
  库在 state 校验通过后读取，归一为 `ProviderError`（`AADSTS*` 细节在
  `error_description` 里随消息透传给调用方诊断；对外再由调用方抽象）。
- **限流**：token 端点可能返回 429 + `Retry-After`；本库归一为 `HttpStatus(429, body)`
  （`AuthError` 无 `provider_unavailable` 分支——26 分支冻结），调用方按 `Retry-After`
  自行退避，不要立即重试。
- **没有统一 revoke 端点**：Microsoft identity platform 无 Google/Apple 等价的 token
  revoke；本地登出 = 删会话 + 停用本地 token + 标记 credential（组织会话失效属 Graph
  `revokeSignInSessions` 管理能力，勿作为普通登出步骤）。
- **`email` 不可信**：id_token 的 `email` 可选且不保证已验证；缺失时允许无邮箱账号，
  邮箱相同**不自动合并**。`preferred_username` 是可变登录名，不是主键。
- **`session_state` 不替代 state 校验**：回调可能带 `session_state`（微软自身的会话
  标记），本库的 `state` 一次性事务校验与其无关。
- **PKCE 恒启用（S256）**：调研口径为「推荐」；库默认恒发送，`nonce` 恒发送
  （调研口径为必填）。
- **刷新轮换**：请求 `offline_access` 才有 refresh token；返回新值必须替换旧值
  （旧值即使暂时可用也应丢弃）。刷新属应用层职责（本库零状态）。

## 5. 相关源码

- 配置（tenant / issuer 模板 / 白名单）：`provider/microsoft/config.mbt`
- 默认实现（tid → per-tenant issuer 派生）：`provider/microsoft/backend.mbt`
- 归一化：`provider/microsoft/claims.mbt`
- trait（整体替换点）：`provider/microsoft/provider_seam.mbt`
- facade：`provider/microsoft/facade.mbt`
