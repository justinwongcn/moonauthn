//! moonauth / provider/feishu —— 装配点 `FeishuConfig`（SDK-02）。
//!
//! 飞书 / Lark 的网页授权登录（新版 OAuth 2.0）特点：
//! - token 端点（`/authen/v2/oauth/token`）要求 **JSON 请求体**（snake_case 字段），
//!   与 OAuth2 标准的 form POST 不同 → **换 token 自实现**；授权 URL 组装仍是标准
//!   形态（client_id / redirect_uri / response_type / scope / state / PKCE），
//!   **复用** `@oauth` seam 的 `begin`（含 percent-encode 与字典序保证）；
//! - **飞书（国内）与 Lark（国际）**：API 路径完全同构，只有域名不同。默认飞书
//!   （`*.feishu.cn`），`with_lark()` 一键切 Lark（`*.larksuite.com`）；
//!   🔴 两套部署的**凭据体系完全隔离**——飞书应用的凭据请求 Lark 域名会报
//!   「app 不存在」，反之亦然；跨国应用需在两个开放平台分别创建应用；
//! - userinfo 响应套 `{code, msg, data}` 信封壳（`data` 里才是用户字段）。
//!
//! 🔴 本包不 import 其余任何 provider（LIB-20 隔离）。

///|
/// 默认授权端点（飞书，国内）。
let default_authorization_endpoint : String =
  "https://accounts.feishu.cn/open-apis/authen/v1/authorize"

///|
/// 默认 token 端点（飞书，国内）。
let default_token_endpoint : String = "https://open.feishu.cn/open-apis/authen/v2/oauth/token"

///|
/// 默认用户信息端点（飞书，国内）。
let default_user_info_endpoint : String = "https://open.feishu.cn/open-apis/authen/v1/user_info"

///|
/// Lark（国际版）授权端点（`with_lark()` 预设用；路径与飞书同构）。
let lark_authorization_endpoint : String =
  "https://accounts.larksuite.com/open-apis/authen/v1/authorize"

///|
/// Lark（国际版）token 端点（`with_lark()` 预设用）。
let lark_token_endpoint : String = "https://open.larksuite.com/open-apis/authen/v2/oauth/token"

///|
/// Lark（国际版）用户信息端点（`with_lark()` 预设用）。
let lark_user_info_endpoint : String = "https://open.larksuite.com/open-apis/authen/v1/user_info"

///|
/// 默认 scopes（空：飞书的 API 权限在开放平台按应用配置，OAuth scope 可不传）。
let default_scopes : Array[String] = []

///|
/// 飞书登录的**装配点**（国内与国际版共用，见 `with_lark`）。
pub struct FeishuConfig {
  app_id : String
  app_secret : String
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
/// 以「app_id + app_secret + redirect_uri」构造，其余全部取默认值（**飞书国内站**）。
///
/// 默认基础 seam：`AsyncHttpClient` + `SystemClock` + `GetrandomSource`。
pub fn FeishuConfig::new(
  app_id : String,
  app_secret : String,
  redirect_uri : String,
) -> FeishuConfig {
  let http : &@core.HttpClient = @core.AsyncHttpClient::new()
  let clock : &@core.Clock = @core.SystemClock::new()
  let random : &@core.RandomSource = @rand.GetrandomSource::new()
  {
    app_id,
    app_secret,
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
/// 切换到 **Lark（国际版，`*.larksuite.com`）** 端点预设（返回新实例）。
///
/// 🔴 两套部署的凭据体系完全隔离：飞书应用凭据请求 Lark 域名会报错，反之亦然。
/// 特殊部署（如自建域名代理）用 `with_endpoints` 覆盖。
pub fn FeishuConfig::with_lark(self : FeishuConfig) -> FeishuConfig {
  {
    ..self,
    authorization_endpoint: lark_authorization_endpoint,
    token_endpoint: lark_token_endpoint,
    user_info_endpoint: lark_user_info_endpoint,
  }
}

///|
/// 注入出站 HTTP 实现（返回新实例）。
pub fn FeishuConfig::with_http(self : FeishuConfig, http : &@core.HttpClient) -> FeishuConfig {
  { ..self, http }
}

///|
/// 注入时钟（返回新实例）。
pub fn FeishuConfig::with_clock(self : FeishuConfig, clock : &@core.Clock) -> FeishuConfig {
  { ..self, clock }
}

///|
/// 注入随机源（返回新实例）。
pub fn FeishuConfig::with_random(
  self : FeishuConfig,
  random : &@core.RandomSource,
) -> FeishuConfig {
  { ..self, random }
}

///|
/// 覆盖 scopes（返回新实例）。
pub fn FeishuConfig::with_scopes(self : FeishuConfig, scopes : Array[String]) -> FeishuConfig {
  // 拷贝：调用方后续改数组不得穿透进配置（与 `new()` 对默认值的处理一致）。
  { ..self, scopes: scopes.copy() }
}

///|
/// 覆盖三类端点（返回新实例）——测试用固定向量 / 自建域名时使用。
pub fn FeishuConfig::with_endpoints(
  self : FeishuConfig,
  authorization_endpoint : String,
  token_endpoint : String,
  user_info_endpoint : String,
) -> FeishuConfig {
  { ..self, authorization_endpoint, token_endpoint, user_info_endpoint }
}
