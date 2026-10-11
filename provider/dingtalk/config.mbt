//! moonauth / provider/dingtalk —— 装配点 `DingTalkConfig`（SDK-02）。
//!
//! 钉钉 v2 扫码 / 网页授权登录（`/v1.0/oauth2/*`）特点：
//! - token 端点要求 **JSON 请求体**（`clientId` / `clientSecret` / `grantType`，驼峰字段），
//!   与 OAuth2 标准的 form POST 不同 → **换 token 自实现**，不骑 `@oauth` seam 的
//!   `exchange`；授权 URL 组装仍是标准形态（client_id / redirect_uri / response_type /
//!   scope / state / PKCE），**复用** seam 的 `begin`（含 percent-encode 与字典序保证）；
//! - 取用户信息用**自定义头** `x-acs-dingtalk-access-token`（不是 `Authorization`）；
//! - **国内站与国际站**：协议报文完全同构，只有域名不同。默认国内站
//!   （`*.dingtalk.com`），`with_global()` 一键切国际站（`*.dingtalk.io`）；
//!   两套凭据不互通，应用在哪个站创建就用哪套端点。
//!
//! 🔴 本包不 import 其余任何 provider（LIB-20 隔离）。

///|
/// 默认授权端点（国内站）。
let default_authorization_endpoint : String = "https://login.dingtalk.com/oauth2/auth"

///|
/// 默认 token 端点（国内站）。
let default_token_endpoint : String = "https://api.dingtalk.com/v1.0/oauth2/userAccessToken"

///|
/// 默认用户信息端点（国内站）。
let default_user_info_endpoint : String = "https://api.dingtalk.com/v1.0/contact/users/me"

///|
/// 国际站授权端点（`with_global()` 预设用；路径与国内站同构）。
let global_authorization_endpoint : String = "https://login.dingtalk.io/oauth2/auth"

///|
/// 国际站 token 端点（`with_global()` 预设用）。
let global_token_endpoint : String = "https://api.dingtalk.io/v1.0/oauth2/userAccessToken"

///|
/// 国际站用户信息端点（`with_global()` 预设用）。
let global_user_info_endpoint : String = "https://api.dingtalk.io/v1.0/contact/users/me"

///|
/// 默认 scopes（钉钉 v2 授权的基础 scope）。
let default_scopes : Array[String] = ["openid"]

///|
/// 钉钉登录的**装配点**。
pub struct DingTalkConfig {
  client_id : String
  /// 钉钉 v2 换 token **必填** `clientSecret`（机密应用模型）。
  client_secret : String
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
/// 以「client_id + client_secret + redirect_uri」构造，其余全部取默认值（**国内站**）。
///
/// 默认基础 seam：`AsyncHttpClient` + `SystemClock` + `GetrandomSource`。
pub fn DingTalkConfig::new(
  client_id : String,
  client_secret : String,
  redirect_uri : String,
) -> DingTalkConfig {
  let http : &@core.HttpClient = @core.AsyncHttpClient::new()
  let clock : &@core.Clock = @core.SystemClock::new()
  let random : &@core.RandomSource = @rand.GetrandomSource::new()
  {
    client_id,
    client_secret,
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
/// 切换到**国际站**（DingTalk Global，`*.dingtalk.io`）端点预设（返回新实例）。
///
/// 🔴 两套部署的凭据体系完全隔离：国际站应用必须用国际站端点，反之亦然。
/// 特殊部署（如专属域名）用 `with_endpoints` 覆盖。
pub fn DingTalkConfig::with_global(self : DingTalkConfig) -> DingTalkConfig {
  {
    ..self,
    authorization_endpoint: global_authorization_endpoint,
    token_endpoint: global_token_endpoint,
    user_info_endpoint: global_user_info_endpoint,
  }
}

///|
/// 注入出站 HTTP 实现（返回新实例）。
pub fn DingTalkConfig::with_http(
  self : DingTalkConfig,
  http : &@core.HttpClient,
) -> DingTalkConfig {
  { ..self, http }
}

///|
/// 注入时钟（返回新实例）。
pub fn DingTalkConfig::with_clock(
  self : DingTalkConfig,
  clock : &@core.Clock,
) -> DingTalkConfig {
  { ..self, clock }
}

///|
/// 注入随机源（返回新实例）。
pub fn DingTalkConfig::with_random(
  self : DingTalkConfig,
  random : &@core.RandomSource,
) -> DingTalkConfig {
  { ..self, random }
}

///|
/// 覆盖 scopes（返回新实例）。
pub fn DingTalkConfig::with_scopes(
  self : DingTalkConfig,
  scopes : Array[String],
) -> DingTalkConfig {
  { ..self, scopes }
}

///|
/// 覆盖三类端点（返回新实例）——测试用固定向量 / 专属域名部署时使用。
pub fn DingTalkConfig::with_endpoints(
  self : DingTalkConfig,
  authorization_endpoint : String,
  token_endpoint : String,
  user_info_endpoint : String,
) -> DingTalkConfig {
  { ..self, authorization_endpoint, token_endpoint, user_info_endpoint }
}
