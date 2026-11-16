# 微信（WeChat）接入

> 子包：`justinwongcn/moonauth/provider/wechat`
> 协议：微信开放平台 / 公众号网页授权（`snsapi_login` / `snsapi_userinfo`）+ **小程序登录**（`code2Session`）。

## 1. 申请步骤

1. 打开[微信开放平台](https://open.weixin.qq.com/) → **管理中心 → 网站应用 → 创建网站应用**。
2. 填写应用信息并提交**审核**（网站应用需企业资质，审核周期以官方为准）。
3. 审核通过后获得 **AppID** 与 **AppSecret**（`secret`）。
4. 在应用详情里设置**授权回调域**（注意：只填**域名**，不带协议与路径，例如 `your.app`）。
5. 若要拿到 `unionid`（跨应用统一用户标识），需把该应用**绑定到同一个开放平台账号**。

## 2. 库内配置

```moonbit
let config = @wechat.WeChatConfig::new("AppID", "AppSecret", "https://your.app/auth/wechat/callback")
```

| 字段 | 默认值 |
|---|---|
| `authorization_endpoint` | `https://open.weixin.qq.com/connect/qrconnect` |
| `token_endpoint` | `https://api.weixin.qq.com/sns/oauth2/access_token` |
| `userinfo_endpoint` | `https://api.weixin.qq.com/sns/userinfo` |
| `code2_session_endpoint` | `https://api.weixin.qq.com/sns/jscode2session` |
| `scope` | `snsapi_login` |

链式覆盖：`with_scope(String)` / `with_endpoints(authz, token, userinfo)` / `with_code2_session_endpoint(String)` / `with_http` / `with_clock` / `with_random`。

## 3. 用法

```moonbit
let start = @wechat.begin_auth(config, @core.SuppliedSecrets::{ state: None, code_verifier: None, nonce: None })
// 302 到 start.url（注意结尾的 #wechat_redirect，见下）
let callback = @wechat.wechat_callback("code=...&state=...")
let identity = @wechat.complete_auth(config, callback, start)
```

`identity.uid` = `unionid`（有则）否则 `openid`；`uid_kind` = `Stable`（有 `unionid`）/ `Degraded`（仅 `openid`）。

单独可用的工具函数：

```moonbit
@wechat.wechat_authorize_url(config, state)   // 拼授权 URL（严格顺序）
@wechat.wechat_parse_token(body)              // 解析 token 响应 -> WeChatToken
// 归一身份：第 3 参 fallback_unionid 传入「token 响应里的 unionid」，
// 用于 userinfo 未带 unionid 时兜底（见下方三层兜底链）。
@wechat.wechat_identity(userinfo_json, fallback_openid, fallback_unionid=token.unionid)
```

> `fallback_unionid` 为**可选参数**（`fallback_unionid? : String?`，默认 `None`）。
> 因此旧写法 `@wechat.wechat_identity(userinfo_json, fallback_openid)` **仍能编译**——
> 但那样会**丢掉 token 侧的 `unionid`**，触发下面 🔴 的「低估为 `Degraded`」陷阱。
> **推荐始终传第三个参数**：`fallback_unionid = token.unionid`。

### 小程序登录（`code2Session`，2026-11-17 新增）

小程序链路与网站扫码完全不同：**无浏览器回调、无 `state`、无 refresh token**。小程序端
`wx.login()` 取得临时 `code`（约 5 分钟有效）后交服务端直接换身份。端点与响应已按官方
文档核实（2026-11-17）：`GET /sns/jscode2session?appid=&secret=&js_code=&grant_type=authorization_code`，
官方注明**只能在服务端调用**。

```moonbit
// 小程序端把 wx.login() 的 code 发给你的服务端后：
let result = @wechat.wechat_code2_session(config, js_code)
let identity = result.identity      // provider = "wechat"，与网站链路同一归一口径
let session_key = result.session_key // 微信会话密钥，服务端专用
```

- **身份主键与网站链路完全一致**：`unionid` 优先（`Stable`）→ `openid` 兜底（`Degraded`）。
  同一开放平台账号下的网站 + 小程序可用 `unionid` 关联同一用户；缺 `unionid` 时由调用方
  依据 `Degraded` 决定绑定策略。
- 🔴 **`session_key` 是微信的会话密钥（解密用户数据用），不是登录态**：只允许保存在服务端，
  绝不返回小程序前端 / 浏览器，不写入日志；每次 `code2Session` 都返回**新的** `session_key`
  （自动轮换，怀疑泄露时重新登录即可）；不需要解密用户数据时可完全不持久化。
  库把它放**专用字段**返回，**不进** `identity.extra`——避免调用方把 `extra` 当普通元数据
  记录时意外落日志。
- **错误口径**：先查 `errcode`（`40029` code 无效 / `40226` 高风险用户拦截 / `45011` 分钟级
  频控 / `-1` 系统繁忙），非零即 `ProviderError`——HTTP 仍可能是 200。
- 小程序登录不返回 refresh token，不存在刷新链路。

## 4. 🔴 踩坑点（微信是**顺序强校验**的重灾区）

- 🔴 **端点与 scope 必须配套切换（混用即 10016）**：微信有两套互不兼容的授权入口——
  - `connect/qrconnect`（**开放平台网站应用**，PC 扫码登录）只接受 `scope = snsapi_login`——**库默认组合**，与上文「网站应用」申请路径对应；
  - `connect/oauth2/authorize`（**公众号网页授权**，微信内 H5）只接受 `snsapi_base` / `snsapi_userinfo`。
  两套体系交叉（如公众号端点配 `snsapi_login`）会被网关以 `errcode=10016`（invalid scope）拒绝且不提示原因。
  公众号场景请一并切换：`with_endpoints("https://open.weixin.qq.com/connect/oauth2/authorize", token, userinfo).with_scope("snsapi_userinfo")`。
- 🔴 **授权 URL 参数顺序必须逐字节一致**：
  `appid` → `redirect_uri` → `response_type` → `scope` → `state` → `#wechat_redirect`。
  库用**字符串模板**拼接（`provider/wechat/url.mbt`），**绝不**用 `Map` 迭代——迭代顺序不确定会导致校验失败。
- 🔴 **末尾必须带 `#wechat_redirect`**：它在 `#` 之后，属于 fragment，不是普通 query 参数；漏了就授权失败。
- 🔴 **`unionid` 三级兜底链**：`userinfo.unionid` → `token.unionid` → 无（`openid` + `Degraded`）：
  - `userinfo.unionid` 有值 → `uid = unionid`、`uid_kind = Stable`（同一开放平台账号下跨应用一致）；
  - 否则取 **token 响应里的 `unionid`**（即 `wechat_identity` 的第 3 参 `fallback_unionid`；`complete_auth` 默认已传入）→ 同样 `Stable`；
  - 两处都无 → `uid = openid`、`uid_kind = Degraded`。**降级是成功的登录，不是错误**——调用方据此决定是否接受绑定。
- 🔴 **微信的 `unionid` 可能只在 token 响应里，userinfo 不带**：
  若只认 `userinfo.unionid`（即旧的两参写法 `wechat_identity(userinfo_json, fallback_openid)`），
  会把**本可 `Stable` 的身份低估为 `Degraded`**。下游会看到「我明明绑了开放平台账号，为什么拿 `Degraded`」这种
  **极难排查**的现象。故**务必把 token 的 `unionid` 经 `fallback_unionid` 传入**（`complete_auth` 已默认这么做）。
- **userinfo 字段会缺省**：自 2021 年起 `nickname` / `headimgurl` 可能**不再返回**；库把它们设为 `None`，不报错。
- **错误体 HTTP 仍可能是 200**：微信错误形如 `{"errcode":N,"errmsg":"..."}`，且 **HTTP 状态可能仍是 200**。
  库**先查 `errcode`** 归一为 `ProviderError`，**不依赖 HTTP 状态码**。

## 5. 相关源码

- 严格顺序授权 URL：`provider/wechat/url.mbt`
- 配置：`provider/wechat/config.mbt`
- token / userinfo 解析：`provider/wechat/parse.mbt`、`provider/wechat/userinfo.mbt`
- 小程序登录：`provider/wechat/miniprogram.mbt`
- facade：`provider/wechat/facade.mbt`
