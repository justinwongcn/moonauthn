//! moonauth / provider/microsoft —— 装配点 `MicrosoftConfig`（SDK-02）。
//!
//! Microsoft Entra ID v2.0 授权码流程（OIDC）。与 Google 的关键差异：
//!
//! 🔴 **issuer 是 per-tenant 的**：Discovery 的 issuer 模板为
//! `https://login.microsoftonline.com/{tenantid}/v2.0`——`common` / `organizations`
//! 只是元数据入口，实际签发的每枚 ID Token 的 `iss` 都带**签发租户**的 tid。
//! 故本包不做静态 issuer 匹配，而是在换 token 后从**未验签** claims 中取 `tid`：
//! ① `allowed_tenant_ids` 非空时先做租户白名单（不命中即 `ProviderError`）；
//! ② 以 `issuer_template`（默认官方形态，含 `{tid}` 占位符）派生出**精确 issuer**，
//!    交给 `oidc` 验签（签名必须对真实微软 JWKS 验证 + `aud` 匹配 + `nonce` 一致）。
//!    未验签的 `tid` 只用于「选择用哪把公钥 / 哪个 issuer」，不参与任何身份语义。
//!
//! 🔴 本包不 import 其余任何 provider（LIB-20 隔离）。
//!
//! 端点 / JWKS 按**配置 tenant** 展开（`common` 的 keys 端点可服务多租户验签）；
//! tenant 取值：`common` / `organizations` / `consumers` / `<tenant-id>` / `<domain>`。

///|
/// 默认 issuer 模板（`{tid}` 占位符会被 token 的 `tid` 替换——官方 per-tenant 形态）。
let default_issuer_template : String = "https://login.microsoftonline.com/{tid}/v2.0"

///|
/// 端点模板（按配置 `tenant` 展开）。
let default_authorize_template : String =
  "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"

///|
let default_token_template : String =
  "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"

///|
let default_jwks_template : String =
  "https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys"

///|
/// 默认 scopes（OIDC 最小集；需要 refresh token 时由调用方追加 `offline_access`）。
let default_scopes : Array[String] = ["openid", "profile", "email"]

///|
/// 模板展开：`{tenant}` / `{tid}` 占位符替换。
fn expand_placeholder(template : String, placeholder : String, value : String) -> String {
  template.replace(old=placeholder, new=value)
}

///|
/// Microsoft Entra ID 登录的**装配点**。
pub struct MicrosoftConfig {
  client_id : String
  /// 机密切换（Web 后端必填）；纯公开客户端（PKCE）可留 `None`。
  client_secret : String?
  redirect_uri : String
  scopes : Array[String]
  /// tenant 策略（默认 `common`；生产建议显式 tenant-id）。
  tenant : String
  /// 允许的租户 ID 白名单（比对 token 的 `tid`）。空数组 = 不做白名单
  /// （签名验证 + 精确 issuer 匹配仍然生效）。
  allowed_tenant_ids : Array[String]
  /// issuer 模板（`{tid}` 占位符）。测试可用固定 issuer 覆盖。
  issuer_template : String
  authorization_endpoint : String
  token_endpoint : String
  jwks_uri : String
  http : &@core.HttpClient
  clock : &@core.Clock
  random : &@core.RandomSource
}

///|
/// 以「client_id + redirect_uri」构造；tenant 默认 `common`，端点按模板展开。
///
/// 默认基础 seam：`AsyncHttpClient` + `SystemClock` + `GetrandomSource`。
pub fn MicrosoftConfig::new(
  client_id : String,
  redirect_uri : String,
) -> MicrosoftConfig {
  let http : &@core.HttpClient = @core.AsyncHttpClient::new()
  let clock : &@core.Clock = @core.SystemClock::new()
  let random : &@core.RandomSource = @rand.GetrandomSource::new()
  {
    client_id,
    client_secret: None,
    redirect_uri,
    scopes: default_scopes.copy(),
    tenant: "common",
    allowed_tenant_ids: [],
    issuer_template: default_issuer_template,
    authorization_endpoint: expand_placeholder(default_authorize_template, "{tenant}", "common"),
    token_endpoint: expand_placeholder(default_token_template, "{tenant}", "common"),
    jwks_uri: expand_placeholder(default_jwks_template, "{tenant}", "common"),
    http,
    clock,
    random,
  }
}

///|
/// 注入出站 HTTP 实现（返回新实例）。
pub fn MicrosoftConfig::with_http(
  self : MicrosoftConfig,
  http : &@core.HttpClient,
) -> MicrosoftConfig {
  { ..self, http }
}

///|
/// 注入时钟（返回新实例）。
pub fn MicrosoftConfig::with_clock(
  self : MicrosoftConfig,
  clock : &@core.Clock,
) -> MicrosoftConfig {
  { ..self, clock }
}

///|
/// 注入随机源（返回新实例）。
pub fn MicrosoftConfig::with_random(
  self : MicrosoftConfig,
  random : &@core.RandomSource,
) -> MicrosoftConfig {
  { ..self, random }
}

///|
/// 设置 client secret（返回新实例）——Web 后端机密客户端必填。
pub fn MicrosoftConfig::with_client_secret(
  self : MicrosoftConfig,
  client_secret : String,
) -> MicrosoftConfig {
  { ..self, client_secret: Some(client_secret) }
}

///|
/// 覆盖 scopes（返回新实例）。需要 refresh token 时在此追加 `offline_access`。
pub fn MicrosoftConfig::with_scopes(
  self : MicrosoftConfig,
  scopes : Array[String],
) -> MicrosoftConfig {
  { ..self, scopes }
}

///|
/// 设置 tenant 策略（返回新实例）——`authorize` / `token` / JWKS 端点按新 tenant
/// 重新展开。**生产建议用显式 tenant-id 而非 `common`**（`common` 不构成安全边界）。
pub fn MicrosoftConfig::with_tenant(
  self : MicrosoftConfig,
  tenant : String,
) -> MicrosoftConfig {
  {
    ..self,
    tenant,
    authorization_endpoint: expand_placeholder(default_authorize_template, "{tenant}", tenant),
    token_endpoint: expand_placeholder(default_token_template, "{tenant}", tenant),
    jwks_uri: expand_placeholder(default_jwks_template, "{tenant}", tenant),
  }
}

///|
/// 设置租户 ID 白名单（返回新实例）。非空时，token 的 `tid` 必须命中，否则
/// `ProviderError("tenant_not_allowed", ...)`。
pub fn MicrosoftConfig::with_allowed_tenant_ids(
  self : MicrosoftConfig,
  allowed_tenant_ids : Array[String],
) -> MicrosoftConfig {
  { ..self, allowed_tenant_ids }
}

///|
/// 覆盖 issuer 模板（返回新实例）——`{tid}` 占位符替换为 token 的 `tid`；
/// 不含 `{tid}` 时 issuer 即为该固定值（测试 / 单租户精确 issuer 场景）。
pub fn MicrosoftConfig::with_issuer_template(
  self : MicrosoftConfig,
  issuer_template : String,
) -> MicrosoftConfig {
  { ..self, issuer_template }
}

///|
/// 覆盖三类端点（返回新实例）——测试用固定向量时使用。
pub fn MicrosoftConfig::with_endpoints(
  self : MicrosoftConfig,
  authorization_endpoint : String,
  token_endpoint : String,
  jwks_uri : String,
) -> MicrosoftConfig {
  { ..self, authorization_endpoint, token_endpoint, jwks_uri }
}
