# 飞书接入（含国际版 Lark）

> 子包：`justinwongcn/moonauth/provider/feishu`
> 协议：飞书 / Lark 新版 OAuth 2.0（`/authen/v2/oauth/token`）；token 端点要求 **JSON 请求体**（snake_case 字段）；userinfo 响应套 `{code,msg,data}` 信封壳。

## 1. 申请步骤

1. 打开 [飞书开放平台](https://open.feishu.cn/)（国际版为 [Lark Developer](https://open.larksuite.com/)）→ **开发者后台 → 创建企业自建应用**。
2. **凭证与基础信息**：获得 **App ID** 与 **App Secret**。
3. **安全设置 → 重定向 URL**：配置回调地址（须与代码里 `redirect_uri` 一致）。
4. **权限管理**：开通「获取用户基本信息」（`获取用户 user ID` 等）并**发布版本**使权限生效。

## 2. 飞书（国内）与 Lark（国际版）

| 端点 | 飞书（默认） | Lark（`with_lark()` 预设） |
|---|---|---|
| 授权 | `https://accounts.feishu.cn/open-apis/authen/v1/authorize` | `https://accounts.larksuite.com/open-apis/authen/v1/authorize` |
| 换 token | `https://open.feishu.cn/open-apis/authen/v2/oauth/token` | `https://open.larksuite.com/open-apis/authen/v2/oauth/token` |
| 用户信息 | `https://open.feishu.cn/open-apis/authen/v1/user_info` | `https://open.larksuite.com/open-apis/authen/v1/user_info` |

🔴 **两套部署的凭据体系完全隔离**：飞书应用凭据请求 `larksuite.com` 会报
「app 不存在」，反之亦然——应用在哪个平台创建，就用哪套端点。跨国应用需在
两个开放平台**分别创建应用**。路径若与官方更新不同，用 `with_endpoints` 覆盖即可。

## 3. 库内配置

```moonbit
let config = @feishu.FeishuConfig::new(
  "APP_ID",
  "APP_SECRET",
  "https://your.app/auth/feishu/callback",
)
// 国际版 Lark：追加 .with_lark()
```

| 字段 | 默认值 |
|---|---|
| `authorization_endpoint` | `https://accounts.feishu.cn/open-apis/authen/v1/authorize` |
| `token_endpoint` | `https://open.feishu.cn/open-apis/authen/v2/oauth/token` |
| `user_info_endpoint` | `https://open.feishu.cn/open-apis/authen/v1/user_info` |
| `scopes` | `[]`（飞书 API 权限按应用在开放平台配置，OAuth scope 可不传） |

链式覆盖：`with_lark()` / `with_scopes(Array[String])` / `with_endpoints(authz, token, me)` / `with_http` / `with_clock` / `with_random`。

## 4. 用法

```moonbit
let start = @feishu.begin_auth(config, @core.SuppliedSecrets::{ state: None, code_verifier: None, nonce: None })
let callback = @core.CallbackParams::from_query_string("code=...&state=...")
let identity = @feishu.complete_auth(config, callback, start)
```

`identity.uid = union_id`（同一开发者主体下跨应用稳定），`uid_kind = Stable`；
仅拿到 `open_id`（应用内标识）时降级 `Degraded`（微信 unionid 同款语义）。
`display_name = name`、`avatar = avatar_url`；其余字段进 `extra`。

单独可用的解析函数：

```moonbit
@feishu.feishu_parse_token(body)   // v2 token 顶层 {"access_token":"..."}
@feishu.feishu_identity(user_json) // user_info 响应 JSON 文本（信封壳内解） -> 身份
```

## 5. 🔴 踩坑点

- 🔴 **换 token 是 JSON 请求体**：`POST /authen/v2/oauth/token` 的请求体是
  `{"grant_type":"authorization_code","client_id":...,"client_secret":...,"code":...,
  "redirect_uri":...}`（**snake_case 字段**，非 OAuth2 标准的 form）。库自实现该调用
  （授权 URL 组装仍复用 `@oauth` seam）。PKCE 时以 `code_verifier` 字段随体上送。
- 🔴 **userinfo 响应套信封壳**：`user_info` 回 `{"code":0,"msg":"success","data":{...}}`——
  用户字段在 `data` 里；`code != 0` 是**业务错误**（HTTP 仍 200），库按 `code` 归一为
  `ProviderError`。token v2 顶层无信封，`access_token` 直接在顶层。
- **错误体两套**：token 端点（v2 遵循 OAuth2 标准）非 2xx 时是
  `{"error":"invalid_grant","error_description":"..."}`；userinfo 是信封 `code/msg`。
  库分别归一，均落 `ProviderError`。
- **权限未发布 = 拿不到字段**：`user_info` 返回的字段受应用**权限 + 版本发布**控制，
  未开通 / 未发布时字段缺失（不是报错）——`email` 缺失即 `email = None`。
- **PKCE**：飞书新版 OAuth 支持 `code_challenge`（S256），库默认全程启用。
- **`state` 必填**：`complete_auth` 会校验 `state`，不符抛 `StateMismatch`。

## 6. 相关源码

- 配置（含飞书 / Lark 端点常量与 `with_lark` 预设）：`provider/feishu/config.mbt`
- 默认实现 + token / userinfo 抓取：`provider/feishu/facade.mbt`
- token 解析 + 信封解包 + 身份归一：`provider/feishu/parse.mbt`
