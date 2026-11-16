//! moonauth / provider/wechat —— 装配点 `WeChatConfig`（SDK-02）。
//!
//! 微信「网站应用 / 移动应用」网页授权（OAuth2 Authorization Code）特点：
//! - **无 PKCE、无 OIDC id_token**；token / userinfo 端点均为 **GET + query**；
//! - 授权 URL 的参数**顺序严格固定**（`url.mbt` 用字符串模板拼，禁止 Map 迭代）；
//! - 身份主键：`unionid` 优先、`openid` 兜底（后者降级，见 `userinfo.mbt`）。
//!
//! 🔴 本包不 import 其余任何 provider（LIB-20 隔离），也不依赖 `oauth` / `oidc`
//! ——微信整条链路（组 URL / 换 token / 取用户）自成一体。

///|
/// 默认授权端点（**开放平台网站应用扫码登录**，`#wechat_redirect` 由 `url.mbt` 追加）。
///
/// 🔴 端点与 scope **必须配套**：`connect/qrconnect`（开放平台网站应用）配
/// `snsapi_login`（默认组合，PC 扫码登录）；`connect/oauth2/authorize`（公众号网页授权，
/// 微信内 H5）只接受 `snsapi_base` / `snsapi_userinfo`——两套体系混用会被网关以
/// 10016（invalid scope）拒绝。公众号场景请 `with_endpoints(..)` + `with_scope("snsapi_userinfo")`
/// 一并切换（见 `docs/platforms/wechat.md`）。
let default_authorization_endpoint : String = "https://open.weixin.qq.com/connect/qrconnect"

///|
/// 默认 token 端点。
let default_token_endpoint : String = "https://api.weixin.qq.com/sns/oauth2/access_token"

///|
/// 默认用户信息端点。
let default_userinfo_endpoint : String = "https://api.weixin.qq.com/sns/userinfo"

///|
/// 默认小程序登录凭证校验端点（`code2Session`，官方注明**仅服务端**可调用）。
///
/// 端点经官方文档核实（2026-11-17）：
/// `GET https://api.weixin.qq.com/sns/jscode2session`，返回 `openid` /
/// `session_key` / 条件 `unionid` / `errcode`、`errmsg`。
let default_code2_session_endpoint : String = "https://api.weixin.qq.com/sns/jscode2session"

///|
/// 默认授权作用域（PC 扫码登录用 `snsapi_login`；公众号内网页用 `snsapi_userinfo`）。
let default_scope : String = "snsapi_login"

///|
/// 微信的**装配点**。
pub struct WeChatConfig {
  appid : String
  secret : String
  redirect_uri : String
  scope : String
  authorization_endpoint : String
  token_endpoint : String
  userinfo_endpoint : String
  /// 小程序 `code2Session` 端点（`wechat_code2_session` 使用）。
  code2_session_endpoint : String
  http : &@core.HttpClient
  clock : &@core.Clock
  random : &@core.RandomSource
}

///|
/// 以「appid + secret + redirect_uri」构造，其余取默认。
pub fn WeChatConfig::new(
  appid : String,
  secret : String,
  redirect_uri : String,
) -> WeChatConfig {
  let http : &@core.HttpClient = @core.AsyncHttpClient::new()
  let clock : &@core.Clock = @core.SystemClock::new()
  let random : &@core.RandomSource = @rand.GetrandomSource::new()
  {
    appid,
    secret,
    redirect_uri,
    scope: default_scope,
    authorization_endpoint: default_authorization_endpoint,
    token_endpoint: default_token_endpoint,
    userinfo_endpoint: default_userinfo_endpoint,
    code2_session_endpoint: default_code2_session_endpoint,
    http,
    clock,
    random,
  }
}

///|
/// 注入出站 HTTP（返回新实例）。
pub fn WeChatConfig::with_http(
  self : WeChatConfig,
  http : &@core.HttpClient,
) -> WeChatConfig {
  { ..self, http }
}

///|
/// 注入时钟（返回新实例）。
pub fn WeChatConfig::with_clock(
  self : WeChatConfig,
  clock : &@core.Clock,
) -> WeChatConfig {
  { ..self, clock }
}

///|
/// 注入随机源（返回新实例）。
pub fn WeChatConfig::with_random(
  self : WeChatConfig,
  random : &@core.RandomSource,
) -> WeChatConfig {
  { ..self, random }
}

///|
/// 覆盖 scope（返回新实例）。
pub fn WeChatConfig::with_scope(self : WeChatConfig, scope : String) -> WeChatConfig {
  { ..self, scope }
}

///|
/// 覆盖三个端点（返回新实例）。
pub fn WeChatConfig::with_endpoints(
  self : WeChatConfig,
  authorization_endpoint : String,
  token_endpoint : String,
  userinfo_endpoint : String,
) -> WeChatConfig {
  { ..self, authorization_endpoint, token_endpoint, userinfo_endpoint }
}

///|
/// 覆盖小程序 `code2Session` 端点（返回新实例）。
pub fn WeChatConfig::with_code2_session_endpoint(
  self : WeChatConfig,
  code2_session_endpoint : String,
) -> WeChatConfig {
  { ..self, code2_session_endpoint }
}
