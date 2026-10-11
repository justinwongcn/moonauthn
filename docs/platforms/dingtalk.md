# 钉钉接入

> 子包：`justinwongcn/moonauth/provider/dingtalk`
> 协议：钉钉 v2 OAuth2（扫码 / 网页授权）；token 端点要求 **JSON 请求体**（驼峰字段）；用户信息走 **自定义鉴权头**。

## 1. 申请步骤

1. 打开 [钉钉开放平台](https://open.dingtalk.com/) → **应用开发 → 创建应用**。
2. 应用详情 → **凭证与基础信息**：获得 **Client ID**（即 AppKey）与 **Client Secret**（即 AppSecret）。
3. **登录与分享 → 回调地址**：配置回调域名（须与代码里 `redirect_uri` 一致）。
4. 开通权限：**个人手机号信息 / 个人邮箱信息** 等按需申请（未开通时 `users/me` 不返回对应字段）。

## 2. 库内配置（默认覆盖国内站端点）

| 字段 | 默认值 |
|---|---|
| `authorization_endpoint` | `https://login.dingtalk.com/oauth2/auth` |
| `token_endpoint` | `https://api.dingtalk.com/v1.0/oauth2/userAccessToken` |
| `user_info_endpoint` | `https://api.dingtalk.com/v1.0/contact/users/me` |
| `scopes` | `["openid"]` |

链式覆盖：`with_scopes(Array[String])` / `with_endpoints(authz, token, me)` / `with_http` / `with_clock` / `with_random`。

### 🔴 国际站（DingTalk Global）：**库不内置端点预设**

钉钉国际站是独立部署、凭据与国内站互不通用（官方文档可查其 API 域名为
`api.dingtalk.io`，其余端点未核实）。截至 2026-10，
国际站 OAuth2 的**具体端点路径未能从官方文档核实**（官方帮助页仅能确认
`api.dingtalk.io` 是其 API 域名），按「**不实现未经核实的功能**」原则，库不做
推测性预设。国际站应用请：

1. 以钉钉国际站官方文档给出的授权 / token / 用户信息端点为准；
2. 用 `with_endpoints(authorization, token, user_info)` 显式配置后照常使用
   （协议报文与国内站同构，库内流程不受影响）。

## 3. 用法

```moonbit
let config = @dingtalk.DingTalkConfig::new(
  "CLIENT_ID",
  "CLIENT_SECRET",
  "https://your.app/auth/dingtalk/callback",
)
let start = @dingtalk.begin_auth(config, @core.SuppliedSecrets::{ state: None, code_verifier: None, nonce: None })
let callback = @core.CallbackParams::from_query_string("authCode=...&state=...")
let identity = @dingtalk.complete_auth(config, callback, start)
```

> 钉钉 v2 回调的授权码参数名可能是 `authCode`（扫码）或 `code`（网页授权）——
> 取到后以 `code` 传给 `complete_auth` 的回调参数即可。

`identity.uid = unionId`（跨应用稳定），`uid_kind = Stable`；仅拿到 `openId`
（应用内标识）时降级 `Degraded`（微信 unionid 同款语义）。`display_name = nick`、
`avatar = avatarUrl`；其余字段进 `extra`。

单独可用的解析函数：

```moonbit
@dingtalk.dingtalk_parse_token(body)   // 解析 {"expireIn":...,"accessToken":"..."}
@dingtalk.dingtalk_identity(user_json) // users/me 响应 JSON 文本 -> 身份
```

## 4. 🔴 踩坑点

- 🔴 **换 token 是 JSON 请求体**：`POST /v1.0/oauth2/userAccessToken` 的请求体是
  `{"clientId":...,"clientSecret":...,"code":...,"grantType":"authorization_code"}`
  （**驼峰字段**，非 OAuth2 标准的 form）。库自实现该调用（授权 URL 组装仍复用
  `@oauth` seam）。响应同为驼峰：`{"expireIn":...,"accessToken":"..."}`。
- 🔴 **用户信息鉴权在自定义头**：`GET /v1.0/contact/users/me` 用
  `x-acs-dingtalk-access-token: <userAccessToken>`，**不是** `Authorization: Bearer`。
- 🔴 **`unionId` 默认不返回**：`users/me` 需带 `unionId=true` 请求参数才返回
  跨应用稳定的 `unionId`；缺省时只有应用内的 `openId`。库已固定追加该参数。
- **错误体**：v1.0 错误为非 2xx + `{"code":"...","message":"..."}` → 库归一为
  `ProviderError(code, message)`。
- **PKCE**：钉钉 v2 授权端点支持 `code_challenge`（S256），库默认全程启用；
  换 token 时以 `codeVerifier` 字段随 JSON 体上送。
- **`state` 必填**：`complete_auth` 会校验 `state`，不符抛 `StateMismatch`。

## 5. 相关源码

- 配置（国内站端点常量；国际站用 `with_endpoints` 配置，见 §2）：`provider/dingtalk/config.mbt`
- 默认实现 + token / userinfo 抓取：`provider/dingtalk/facade.mbt`
- token 解析 + 身份归一：`provider/dingtalk/parse.mbt`
