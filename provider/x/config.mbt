//! moonauth / provider/x —— 装配点 `XConfig`（SDK-02）。
//!
//! X（Twitter）OAuth2 的特点：
//! - 标准 OAuth2 Authorization Code + **PKCE（S256，必需）**，**无 OIDC id_token**；
//! - 身份经 **`GET /2/users/me`** 获取，主键取返回的**数值用户 ID**（`data.id`），
//!   而非 `@handle`（`username` 可改，数值 id 稳定，故 `uid_kind = Stable`）。
//!
//! 🔴 本包不 import 其余任何 provider（LIB-20 隔离）。

///|
/// 默认授权端点。
let default_authorization_endpoint : String = "https://twitter.com/i/oauth2/authorize"

///|
/// 默认 token 端点。
let default_token_endpoint : String = "https://api.twitter.com/2/oauth2/token"

///|
/// 默认用户信息端点。
let default_userinfo_endpoint : String = "https://api.twitter.com/2/users/me"

///|
/// 默认 scopes（读用户 + 读推文 + 刷新令牌）。
let default_scopes : Array[String] = ["tweet.read", "users.read", "offline.access"]

///|
/// X 的**装配点**。
pub struct XConfig {
  client_id : String
  /// 公开客户端可留 `None`（纯 PKCE）；机密客户端设置之。
  client_secret : String?
  redirect_uri : String
  scopes : Array[String]
  authorization_endpoint : String
  token_endpoint : String
  userinfo_endpoint : String
  http : &@core.HttpClient
  clock : &@core.Clock
  random : &@core.RandomSource
}

///|
/// 以「client_id + redirect_uri」构造，其余取默认。
pub fn XConfig::new(client_id : String, redirect_uri : String) -> XConfig {
  let http : &@core.HttpClient = @core.AsyncHttpClient::new()
  let clock : &@core.Clock = @core.SystemClock::new()
  let random : &@core.RandomSource = @rand.GetrandomSource::new()
  {
    client_id,
    client_secret: None,
    redirect_uri,
    scopes: default_scopes.copy(),
    authorization_endpoint: default_authorization_endpoint,
    token_endpoint: default_token_endpoint,
    userinfo_endpoint: default_userinfo_endpoint,
    http,
    clock,
    random,
  }
}

///|
/// 注入出站 HTTP（返回新实例）。
pub fn XConfig::with_http(self : XConfig, http : &@core.HttpClient) -> XConfig {
  { ..self, http }
}

///|
/// 注入时钟（返回新实例）。
pub fn XConfig::with_clock(self : XConfig, clock : &@core.Clock) -> XConfig {
  { ..self, clock }
}

///|
/// 注入随机源（返回新实例）。
pub fn XConfig::with_random(self : XConfig, random : &@core.RandomSource) -> XConfig {
  { ..self, random }
}

///|
/// 设置 client secret（返回新实例）。
pub fn XConfig::with_client_secret(
  self : XConfig,
  client_secret : String,
) -> XConfig {
  { ..self, client_secret: Some(client_secret) }
}

///|
/// 覆盖 scopes（返回新实例）。
pub fn XConfig::with_scopes(self : XConfig, scopes : Array[String]) -> XConfig {
  { ..self, scopes }
}

///|
/// 覆盖端点（返回新实例）。
pub fn XConfig::with_endpoints(
  self : XConfig,
  authorization_endpoint : String,
  token_endpoint : String,
  userinfo_endpoint : String,
) -> XConfig {
  { ..self, authorization_endpoint, token_endpoint, userinfo_endpoint }
}
