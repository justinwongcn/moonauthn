# QQ 接入

> 子包：`justinwongcn/moonauthn/provider/qq`
> 协议：QQ 互联 OAuth 2.0；token 端点默认 form-encoded；`/oauth2.0/me` 返回 **JSONP**。

## 1. 申请步骤

1. 打开 [QQ 互联](https://connect.qq.com/) → **应用管理 → 创建应用**（网站应用）。
2. 填写网站信息、上传资料，提交**审核**。
3. 审核通过后获得 **APP ID** 与 **APP Key**。
4. 在应用详情里配置**回调地址**（须与代码里 `redirect_uri` 完全一致）。
5. 如需 `unionid`，在「获取 unionid」处申请。

## 2. 库内配置

```moonbit
let config = @qq.QQConfig::new("APPID", "APPKEY", "https://your.app/auth/qq/callback")
```

| 字段 | 默认值 |
|---|---|
| `authorization_endpoint` | `https://graph.qq.com/oauth2.0/authorize` |
| `token_endpoint` | `https://graph.qq.com/oauth2.0/token` |
| `openid_endpoint` | `https://graph.qq.com/oauth2.0/me` |
| `userinfo_endpoint` | `https://graph.qq.com/user/get_user_info` |
| `scope` | `get_user_info` |

链式覆盖：`with_scope(String)` / `with_endpoints(authz, token, openid, userinfo)` / `with_http` / `with_clock` / `with_random`。

## 3. 用法

```moonbit
let start = @qq.begin_auth(config, @core.SuppliedSecrets::{ state: None, code_verifier: None, nonce: None })
let callback = @core.CallbackParams::from_query_string("code=...&state=...")
let identity = @qq.complete_auth(config, callback, start)
```

> QQ 回调直接给 query（`code` + `state`），用 `@core.CallbackParams::from_query_string` 即可。

单独可用的解析函数：

```moonbit
@qq.qq_parse_token(body)      // 优先 JSON（fmt=json），失败回退 form-encoded
@qq.qq_unwrap_jsonp(body)     // 剥掉 callback( {...} ); 外壳
@qq.qq_parse_openid(body, expected_client_id)  // 解析 JSONP 的 me 响应 -> openid（含 client_id 绑定校验）
@qq.qq_identity(userinfo_json, openid)
```

`identity.uid = openid`，`uid_kind = Stable`。

## 4. 🔴 踩坑点

- 🔴 **token 端点默认 form-encoded**：`/oauth2.0/token` 默认返回 `access_token=...&expires_in=...`。
  库**优先请求 `fmt=json`** 拿 JSON；若上游仍回 form（或某些错误路径），**自动回退** `application/x-www-form-urlencoded` 解析。
  **解析不依赖 `content-type`**——按响应对待，两种形态都能吃。
- 🔴 **`/oauth2.0/me` 返回 JSONP**：形如 `callback( {"openid":"..."} );`，带固定 callback 名与**尾部 `;`**。
  必须**防御性剥壳**（取第一个 `(` 与第一个 `)` 之间）才能当 JSON 解析；错误分支为
  `callback( {"error":N,"error_description":"..."} );`，剥壳后按 `error` 字段归一为 `ProviderError`。
- 🔴 **`client_id` 绑定校验**：`me` 响应携带该 access_token 所属
  应用的 `client_id`。库在 `qq_parse_openid` 中**出现即校验**：与配置 appid 不一致（或非字符串）
  → `ProviderError("client_id_mismatch", ...)`——防止他应用的 openid 混入本应用身份绑定。
  响应**缺失** `client_id` 时无法校验、放行（QQ 部分响应形态历史上有缺省）；需要更强保证的
  调用方可在拿到 openid 后自行复核。
- **业务错误用 `error` / `ret` 表达**：
  - token 端点错误用 `error` + `error_description`；
  - `get_user_info` 用 `ret`（`0` = 成功）。
  两者 HTTP 状态通常仍是 200，库按字段判定。
- **`state` 必填**：`complete_auth` 会校验 `state`，不符抛 `StateMismatch`。
- **`refresh_token` 一次性**：QQ 的 `refresh_token` 用一次即失效，重试前请确认轮换逻辑。

## 5. 相关源码

- 配置：`provider/qq/config.mbt`
- 双格式 + JSONP 剥壳：`provider/qq/parse.mbt`
- facade：`provider/qq/facade.mbt`
