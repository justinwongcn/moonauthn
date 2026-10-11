//! moonauth / provider/google —— 装配点 `GoogleConfig`（SDK-02）。
//!
//! **单一装配点**：一次构造即拿到「可用默认值」的完整配置——默认端点、默认能力 seam
//! （`AsyncHttpClient` / `SystemClock` / `GetrandomSource`）、默认 scopes；随后可用
//! `with_*` 覆盖任意一项（注入 Mock / 自定义实现 / 换端点）。
//!
//! 🔴 `GoogleConfig` 只持有**基础 I/O seam**（`HttpClient` / `Clock` / `RandomSource`）。
//! 组合能力 seam（`OAuthAuthCode` / `IdTokenVerifier`）由 `DefaultGoogleProvider::new`
//! **据这些基础 seam 现场组装**——这样一次 `with_http` 能同时作用到换 token 与 JWKS 抓取，
//! 不会出现「注入了 Mock，但某条子 seam 仍走真实网络」的裂缝。
//!
//! 🔴 本包不 import 其余任何 provider（LIB-20 隔离）。

///|
/// 默认授权端点（Google OAuth2 v2，与 `contract` 包中的固定端点一致）。
let default_authorization_endpoint : String = "https://accounts.google.com/o/oauth2/v2/auth"

///|
/// 默认 token 端点。
let default_token_endpoint : String = "https://oauth2.googleapis.com/token"

///|
/// 默认 JWKS 端点。
let default_jwks_uri : String = "https://www.googleapis.com/oauth2/v3/certs"

///|
/// 默认 issuer（`id_token.iss`）。
let default_issuer : String = "https://accounts.google.com"

///|
/// 默认 scopes（OIDC + 常用 profile）。
let default_scopes : Array[String] = ["openid", "email", "profile"]

///|
/// Google 登录的**装配点**。
///
/// 字段分三类：
/// - **身份**：`client_id` / `client_secret?` / `redirect_uri` / `scopes`；
/// - **端点**：`authorization_endpoint` / `token_endpoint` / `jwks_uri` / `issuer`；
/// - **基础 I/O seam**：`http` / `clock` / `random`。
pub struct GoogleConfig {
  client_id : String
  /// 机密切换（Web 后端）；纯公开客户端（PKCE）可留 `None`。
  client_secret : String?
  redirect_uri : String
  scopes : Array[String]
  authorization_endpoint : String
  token_endpoint : String
  jwks_uri : String
  issuer : String
  http : &@core.HttpClient
  clock : &@core.Clock
  random : &@core.RandomSource
}

///|
/// 以「client_id + redirect_uri」构造，其余全部取默认值。
///
/// 默认基础 seam：`AsyncHttpClient` + `SystemClock` + `GetrandomSource`。
pub fn GoogleConfig::new(
  client_id : String,
  redirect_uri : String,
) -> GoogleConfig {
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
    jwks_uri: default_jwks_uri,
    issuer: default_issuer,
    http,
    clock,
    random,
  }
}

///|
/// 注入出站 HTTP 实现（返回新实例）。
pub fn GoogleConfig::with_http(
  self : GoogleConfig,
  http : &@core.HttpClient,
) -> GoogleConfig {
  { ..self, http }
}

///|
/// 注入时钟（返回新实例）。
pub fn GoogleConfig::with_clock(
  self : GoogleConfig,
  clock : &@core.Clock,
) -> GoogleConfig {
  { ..self, clock }
}

///|
/// 注入随机源（返回新实例）。
pub fn GoogleConfig::with_random(
  self : GoogleConfig,
  random : &@core.RandomSource,
) -> GoogleConfig {
  { ..self, random }
}

///|
/// 设置 client secret（返回新实例）。
pub fn GoogleConfig::with_client_secret(
  self : GoogleConfig,
  client_secret : String,
) -> GoogleConfig {
  { ..self, client_secret: Some(client_secret) }
}

///|
/// 覆盖 scopes（返回新实例）。
pub fn GoogleConfig::with_scopes(
  self : GoogleConfig,
  scopes : Array[String],
) -> GoogleConfig {
  { ..self, scopes }
}

///|
/// 覆盖四类端点（返回新实例）——测试用固定向量 / 私有部署时使用。
pub fn GoogleConfig::with_endpoints(
  self : GoogleConfig,
  authorization_endpoint : String,
  token_endpoint : String,
  jwks_uri : String,
  issuer : String,
) -> GoogleConfig {
  {
    ..self,
    authorization_endpoint,
    token_endpoint,
    jwks_uri,
    issuer,
  }
}
