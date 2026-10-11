//! moonauth / provider/github —— 装配点 `GitHubConfig`（SDK-02）。
//!
//! GitHub OAuth App / GitHub App 的授权码流程（2025-07 起官方支持 PKCE）：
//! - token 端点默认回 **form-encoded 文本**；请求带 `Accept: application/json` 才回 JSON
//!   （`@oauth.StandardOAuthAuthCode::exchange` 恰好固定发送该头，故 token 交换可直接骑 seam）；
//! - `GET /user` **必须带 `User-Agent`**，否则 GitHub API 回 403（见 `user_info.mbt`）；
//! - 私有邮箱在 `/user` 里是 `null`，需二次 `GET /user/emails` 取 primary 邮箱。
//!
//! 🔴 `GitHubConfig` 只持有**基础 I/O seam**（`HttpClient` / `Clock` / `RandomSource`）；
//! 组合能力 seam（`OAuthAuthCode`）由 `DefaultGitHubProvider::new` 据基础 seam 现场组装。
//!
//! 🔴 本包不 import 其余任何 provider（LIB-20 隔离）。

///|
/// 默认授权端点。
let default_authorization_endpoint : String = "https://github.com/login/oauth/authorize"

///|
/// 默认 token 端点。
let default_token_endpoint : String = "https://github.com/login/oauth/access_token"

///|
/// 默认用户信息端点（`uid = id` 的来源）。
let default_user_info_endpoint : String = "https://api.github.com/user"

///|
/// 默认邮箱列表端点（`/user.email` 为 null 时的可选增强）。
let default_user_emails_endpoint : String = "https://api.github.com/user/emails"

///|
/// 默认 scopes（读用户 + 读邮箱）。
let default_scopes : Array[String] = ["read:user", "user:email"]

///|
/// GitHub 登录的**装配点**。
pub struct GitHubConfig {
  client_id : String
  /// 机密切换（Web 后端）；纯公开客户端（PKCE）可留 `None`。
  client_secret : String?
  redirect_uri : String
  scopes : Array[String]
  authorization_endpoint : String
  token_endpoint : String
  user_info_endpoint : String
  user_emails_endpoint : String
  http : &@core.HttpClient
  clock : &@core.Clock
  random : &@core.RandomSource
}

///|
/// 以「client_id + redirect_uri」构造，其余全部取默认值。
///
/// 默认基础 seam：`AsyncHttpClient` + `SystemClock` + `GetrandomSource`。
pub fn GitHubConfig::new(
  client_id : String,
  redirect_uri : String,
) -> GitHubConfig {
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
    user_emails_endpoint: default_user_emails_endpoint,
    http,
    clock,
    random,
  }
}

///|
/// 注入出站 HTTP 实现（返回新实例）。
pub fn GitHubConfig::with_http(
  self : GitHubConfig,
  http : &@core.HttpClient,
) -> GitHubConfig {
  { ..self, http }
}

///|
/// 注入时钟（返回新实例）。
pub fn GitHubConfig::with_clock(self : GitHubConfig, clock : &@core.Clock) -> GitHubConfig {
  { ..self, clock }
}

///|
/// 注入随机源（返回新实例）。
pub fn GitHubConfig::with_random(
  self : GitHubConfig,
  random : &@core.RandomSource,
) -> GitHubConfig {
  { ..self, random }
}

///|
/// 设置 client secret（返回新实例）。
pub fn GitHubConfig::with_client_secret(
  self : GitHubConfig,
  client_secret : String,
) -> GitHubConfig {
  { ..self, client_secret: Some(client_secret) }
}

///|
/// 覆盖 scopes（返回新实例）。
pub fn GitHubConfig::with_scopes(self : GitHubConfig, scopes : Array[String]) -> GitHubConfig {
  { ..self, scopes }
}

///|
/// 覆盖四类端点（返回新实例）——测试用固定向量 / 私有部署时使用。
pub fn GitHubConfig::with_endpoints(
  self : GitHubConfig,
  authorization_endpoint : String,
  token_endpoint : String,
  user_info_endpoint : String,
  user_emails_endpoint : String,
) -> GitHubConfig {
  {
    ..self,
    authorization_endpoint,
    token_endpoint,
    user_info_endpoint,
    user_emails_endpoint,
  }
}
