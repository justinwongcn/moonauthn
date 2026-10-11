//! moonauth / provider/qq —— 装配点 `QQConfig`（SDK-02）。
//!
//! QQ 互联（QQ Connect）OAuth2 特点：
//! - token 端点默认回 **form-encoded 文本**；带 `fmt=json` 才回 JSON（本库优先 JSON、
//!   失败回退 form）；
//! - `GET /oauth2.0/me` 返回 **JSONP**（`callback( {...} );`，含错误码分支）；
//! - 身份主键取 `openid`（与 appid 绑定，稳定）。
//!
//! 🔴 本包不 import 其余任何 provider（LIB-20 隔离）。

///|
/// 默认授权端点。
let default_authorization_endpoint : String = "https://graph.qq.com/oauth2.0/authorize"

///|
/// 默认 token 端点。
let default_token_endpoint : String = "https://graph.qq.com/oauth2.0/token"

///|
/// 默认 openid 端点（JSONP）。
let default_openid_endpoint : String = "https://graph.qq.com/oauth2.0/me"

///|
/// 默认用户信息端点。
let default_userinfo_endpoint : String = "https://graph.qq.com/user/get_user_info"

///|
/// 默认 scope。
let default_scope : String = "get_user_info"

///|
/// QQ 的**装配点**。
pub struct QQConfig {
  appid : String
  appsecret : String
  redirect_uri : String
  scope : String
  authorization_endpoint : String
  token_endpoint : String
  openid_endpoint : String
  userinfo_endpoint : String
  http : &@core.HttpClient
  clock : &@core.Clock
  random : &@core.RandomSource
}

///|
/// 以「appid + appsecret + redirect_uri」构造，其余取默认。
pub fn QQConfig::new(
  appid : String,
  appsecret : String,
  redirect_uri : String,
) -> QQConfig {
  let http : &@core.HttpClient = @core.AsyncHttpClient::new()
  let clock : &@core.Clock = @core.SystemClock::new()
  let random : &@core.RandomSource = @rand.GetrandomSource::new()
  {
    appid,
    appsecret,
    redirect_uri,
    scope: default_scope,
    authorization_endpoint: default_authorization_endpoint,
    token_endpoint: default_token_endpoint,
    openid_endpoint: default_openid_endpoint,
    userinfo_endpoint: default_userinfo_endpoint,
    http,
    clock,
    random,
  }
}

///|
/// 注入出站 HTTP（返回新实例）。
pub fn QQConfig::with_http(self : QQConfig, http : &@core.HttpClient) -> QQConfig {
  { ..self, http }
}

///|
/// 注入时钟（返回新实例）。
pub fn QQConfig::with_clock(self : QQConfig, clock : &@core.Clock) -> QQConfig {
  { ..self, clock }
}

///|
/// 注入随机源（返回新实例）。
pub fn QQConfig::with_random(self : QQConfig, random : &@core.RandomSource) -> QQConfig {
  { ..self, random }
}

///|
/// 覆盖 scope（返回新实例）。
pub fn QQConfig::with_scope(self : QQConfig, scope : String) -> QQConfig {
  { ..self, scope }
}

///|
/// 覆盖四个端点（返回新实例）。
pub fn QQConfig::with_endpoints(
  self : QQConfig,
  authorization_endpoint : String,
  token_endpoint : String,
  openid_endpoint : String,
  userinfo_endpoint : String,
) -> QQConfig {
  {
    ..self,
    authorization_endpoint,
    token_endpoint,
    openid_endpoint,
    userinfo_endpoint,
  }
}
