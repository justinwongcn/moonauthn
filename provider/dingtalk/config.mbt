//! moonauth / provider/dingtalk —— 装配点 `DingTalkConfig`（SDK-02）。
//!
//! 钉钉 v2 扫码 / 网页授权登录（`/v1.0/oauth2/*`）特点：
//! - token 端点要求 **JSON 请求体**（`clientId` / `clientSecret` / `grantType`，驼峰字段），
//!   与 OAuth2 标准的 form POST 不同 → **换 token 自实现**，不骑 `@oauth` seam 的
//!   `exchange`；授权 URL 组装仍是标准形态（client_id / redirect_uri / response_type /
//!   scope / state / PKCE），**复用** seam 的 `begin`（含 percent-encode 与字典序保证）；
//! - 取用户信息用**自定义头** `x-acs-dingtalk-access-token`（不是 `Authorization`）。
//!
//! 🔴 **国际站不内置预设**：钉钉国际站（`*.dingtalk.io`）的 OAuth2 具体端点路径
//! 未能从官方文档核实（截至 2026-10），按「诚实优先」原则**不做推测实现**——
//! 国际站应用请以官方文档给出的端点为准，用 `with_endpoints` 配置。
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
  // 拷贝：调用方后续改数组不得穿透进配置（与 `new()` 对默认值的处理一致）。
  { ..self, scopes: scopes.copy() }
}

///|
/// 覆盖三类端点（返回新实例）——测试用固定向量 / **国际站与专属域名部署**时使用
///（国际站端点见 `config.mbt` 头注释的「诚实优先」说明）。
pub fn DingTalkConfig::with_endpoints(
  self : DingTalkConfig,
  authorization_endpoint : String,
  token_endpoint : String,
  user_info_endpoint : String,
) -> DingTalkConfig {
  { ..self, authorization_endpoint, token_endpoint, user_info_endpoint }
}
