//! moonauth / provider/alipay —— 装配点 `AlipayConfig`（SDK-02）。
//!
//! 支付宝开放平台（openapi）特点：
//! - 所有网关调用走 `https://openapi.alipay.com/gateway.do`，**统一签名 + POST 表单**；
//! - 签名算法 **RSA2（SHA256withRSA）**，用应用私钥签、支付宝公钥验；
//! - 🔴 签名串要求参数 `key` 按 **ASCII 升序** 拼接、**值为原始值（不 URL 编码）**
//!   ——排序必须用 `@core.sort_lexicographic` / `@core.sorted_keys`（见 `sign.mbt`）。
//!
//! 🔴 本包不 import 其余任何 provider（LIB-20 隔离）。

///|
/// 默认网关端点。
let default_gateway_endpoint : String = "https://openapi.alipay.com/gateway.do"

///|
/// 默认授权端点（`publicAppAuthorize.htm`）。
let default_authorize_endpoint : String = "https://openauth.alipay.com/oauth2/publicAppAuthorize.htm"

///|
/// 默认 scope（获取用户信息）。
let default_scope : String = "auth_user"

///|
/// 支付宝的**装配点**。
pub struct AlipayConfig {
  app_id : String
  /// 应用**私钥**（RSA PKCS#1 / PKCS#8 的 DER 或 PEM），用于 RSA2 签名。
  private_key : @core.SigningKey
  /// 授权回调地址。
  redirect_uri : String
  /// 签名能力 seam（默认 `MooncryptSecretSigner`）。
  signer : &@core.SecretSigner
  gateway_endpoint : String
  authorize_endpoint : String
  scope : String
  http : &@core.HttpClient
  clock : &@core.Clock
  random : &@core.RandomSource
}

///|
/// 以「app_id + 应用私钥 + redirect_uri」构造，其余取默认。
pub fn AlipayConfig::new(
  app_id : String,
  private_key : @core.SigningKey,
  redirect_uri : String,
) -> AlipayConfig {
  let signer : &@core.SecretSigner = @oauth.MooncryptSecretSigner::new()
  let http : &@core.HttpClient = @core.AsyncHttpClient::new()
  let clock : &@core.Clock = @core.SystemClock::new()
  let random : &@core.RandomSource = @rand.GetrandomSource::new()
  {
    app_id,
    private_key,
    redirect_uri,
    signer,
    gateway_endpoint: default_gateway_endpoint,
    authorize_endpoint: default_authorize_endpoint,
    scope: default_scope,
    http,
    clock,
    random,
  }
}

///|
/// 注入出站 HTTP（返回新实例）。
pub fn AlipayConfig::with_http(
  self : AlipayConfig,
  http : &@core.HttpClient,
) -> AlipayConfig {
  { ..self, http }
}

///|
/// 注入时钟（返回新实例）。
pub fn AlipayConfig::with_clock(
  self : AlipayConfig,
  clock : &@core.Clock,
) -> AlipayConfig {
  { ..self, clock }
}

///|
/// 注入随机源（返回新实例）。
pub fn AlipayConfig::with_random(
  self : AlipayConfig,
  random : &@core.RandomSource,
) -> AlipayConfig {
  { ..self, random }
}

///|
/// 替换签名能力 seam（返回新实例）。
pub fn AlipayConfig::with_signer(
  self : AlipayConfig,
  signer : &@core.SecretSigner,
) -> AlipayConfig {
  { ..self, signer }
}

///|
/// 覆盖网关 / 授权端点与 scope（返回新实例）。
pub fn AlipayConfig::with_endpoints(
  self : AlipayConfig,
  gateway_endpoint : String,
  authorize_endpoint : String,
  scope : String,
) -> AlipayConfig {
  { ..self, gateway_endpoint, authorize_endpoint, scope }
}
