//! moonauth / provider/discord —— 装配点 `DiscordConfig`（SDK-02）。
//!
//! Discord OAuth2 授权码流程特点：
//! - **支持 PKCE**（仅 `S256`，见 Discord 开发者文档 OAuth2 章）；
//! - token 端点是标准 form POST（client_id + client_secret 进 body），
//!   `@oauth.StandardOAuthAuthCode::exchange` 可直接骑；
//! - 用户信息经 `GET /users/@me`（`Authorization: Bearer`），`id` 是**字符串**雪片号；
//! - `avatar` 是哈希而非完整 URL，需按 Discord 规则拼 CDN 地址（见 `user_info.mbt`）。
//!
//! 🔴 `DiscordConfig` 只持有**基础 I/O seam**（`HttpClient` / `Clock` / `RandomSource`）；
//! 组合能力 seam（`OAuthAuthCode`）由 `DefaultDiscordProvider::new` 据基础 seam 现场组装。
//!
//! 🔴 本包不 import 其余任何 provider（LIB-20 隔离）。

///|
/// 默认授权端点。
let default_authorization_endpoint : String = "https://discord.com/oauth2/authorize"

///|
/// 默认 token 端点。
let default_token_endpoint : String = "https://discord.com/api/oauth2/token"

///|
/// 默认用户信息端点。
let default_user_info_endpoint : String = "https://discord.com/api/users/@me"

///|
/// 默认 scopes（身份 + 邮箱）。
let default_scopes : Array[String] = ["identify", "email"]

///|
/// Discord 登录的**装配点**。
pub struct DiscordConfig {
  client_id : String
  /// 机密切换（Web 后端）；纯公开客户端（PKCE）可留 `None`。
  client_secret : String?
  redirect_uri : String
  scopes : Array[String]
  authorization_endpoint : String
  token_endpoint : String
  user_info_endpoint : String
  http : &@core.HttpClient
  clock : &@core.Clock
  random : &@core.RandomSource
}

///|
/// 以「client_id + redirect_uri」构造，其余全部取默认值。
///
/// 默认基础 seam：`AsyncHttpClient` + `SystemClock` + `GetrandomSource`。
pub fn DiscordConfig::new(
  client_id : String,
  redirect_uri : String,
) -> DiscordConfig {
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
    user_info_endpoint: default_user_info_endpoint,
    http,
    clock,
    random,
  }
}

///|
/// 注入出站 HTTP 实现（返回新实例）。
pub fn DiscordConfig::with_http(
  self : DiscordConfig,
  http : &@core.HttpClient,
) -> DiscordConfig {
  { ..self, http }
}

///|
/// 注入时钟（返回新实例）。
pub fn DiscordConfig::with_clock(
  self : DiscordConfig,
  clock : &@core.Clock,
) -> DiscordConfig {
  { ..self, clock }
}

///|
/// 注入随机源（返回新实例）。
pub fn DiscordConfig::with_random(
  self : DiscordConfig,
  random : &@core.RandomSource,
) -> DiscordConfig {
  { ..self, random }
}

///|
/// 设置 client secret（返回新实例）。
pub fn DiscordConfig::with_client_secret(
  self : DiscordConfig,
  client_secret : String,
) -> DiscordConfig {
  { ..self, client_secret: Some(client_secret) }
}

///|
/// 覆盖 scopes（返回新实例）。
pub fn DiscordConfig::with_scopes(
  self : DiscordConfig,
  scopes : Array[String],
) -> DiscordConfig {
  { ..self, scopes }
}

///|
/// 覆盖三类端点（返回新实例）——测试用固定向量 / 私有部署时使用。
pub fn DiscordConfig::with_endpoints(
  self : DiscordConfig,
  authorization_endpoint : String,
  token_endpoint : String,
  user_info_endpoint : String,
) -> DiscordConfig {
  { ..self, authorization_endpoint, token_endpoint, user_info_endpoint }
}
