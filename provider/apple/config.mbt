//! moonauth / provider/apple —— 装配点 `AppleConfig`（SDK-02）。
//!
//! Apple「Sign in with Apple」与标准 OIDC 的差异：
//! - 回调以 **`response_mode=form_post`** 回传（浏览器 POST 表单到 `redirect_uri`）；
//! - `client_secret` **不是静态字符串**，而是用你的 P-256 私钥现场签发的 **ES256 JWT**
//!   （`iss=team_id, sub=client_id, aud=https://appleid.apple.com`，`exp` 现签）；
//! - `id_token` 用 **RS256** 验签，`iss=https://appleid.apple.com`；
//! - 姓名（`user`）只在**首次授权**返回。
//!
//! 因此 `AppleConfig` 比其它 provider 多持有「签名身份」：`team_id` / `key_id` /
//! `signing_key` / `signer`。
//!
//! 🔴 本包不 import 其余任何 provider（LIB-20 隔离）。

///|
/// 默认授权端点。
let default_authorization_endpoint : String = "https://appleid.apple.com/auth/authorize"

///|
/// 默认 token 端点。
let default_token_endpoint : String = "https://appleid.apple.com/auth/token"

///|
/// 默认 JWKS 端点。
let default_jwks_uri : String = "https://appleid.apple.com/auth/keys"

///|
/// 默认 issuer。
let default_issuer : String = "https://appleid.apple.com"

///|
/// Apple 的**装配点**。
pub struct AppleConfig {
  /// Service ID / App Bundle ID（`id_token.aud`）。
  client_id : String
  redirect_uri : String
  /// Apple Team ID（client secret JWT 的 `iss`）。
  team_id : String
  /// Apple Key ID（client secret JWT 头的 `kid`）。
  key_id : String
  /// P-256 私钥（用于签发 ES256 client secret）。
  signing_key : @core.SigningKey
  /// 签名能力 seam（默认 `MooncryptSecretSigner`）。
  signer : &@core.SecretSigner
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
/// 构造装配点：`client_id`（Service ID）+ `redirect_uri` + Apple 签名身份三件套。
///
/// 🔴 Apple **必须**提供 P-256 私钥：没有它无法签发 ES256 client secret，就换不到 token。
pub fn AppleConfig::new(
  client_id : String,
  redirect_uri : String,
  team_id : String,
  key_id : String,
  signing_key : @core.SigningKey,
) -> AppleConfig {
  let signer : &@core.SecretSigner = @oauth.MooncryptSecretSigner::new()
  let http : &@core.HttpClient = @core.AsyncHttpClient::new()
  let clock : &@core.Clock = @core.SystemClock::new()
  let random : &@core.RandomSource = @rand.GetrandomSource::new()
  {
    client_id,
    redirect_uri,
    team_id,
    key_id,
    signing_key,
    signer,
    scopes: ["name", "email"],
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
/// 注入出站 HTTP（返回新实例）。
pub fn AppleConfig::with_http(
  self : AppleConfig,
  http : &@core.HttpClient,
) -> AppleConfig {
  { ..self, http }
}

///|
/// 注入时钟（返回新实例）。
pub fn AppleConfig::with_clock(
  self : AppleConfig,
  clock : &@core.Clock,
) -> AppleConfig {
  { ..self, clock }
}

///|
/// 注入随机源（返回新实例）。
pub fn AppleConfig::with_random(
  self : AppleConfig,
  random : &@core.RandomSource,
) -> AppleConfig {
  { ..self, random }
}

///|
/// 替换签名能力 seam（返回新实例）。
pub fn AppleConfig::with_signer(
  self : AppleConfig,
  signer : &@core.SecretSigner,
) -> AppleConfig {
  { ..self, signer }
}

///|
/// 覆盖 scopes（返回新实例）。
pub fn AppleConfig::with_scopes(
  self : AppleConfig,
  scopes : Array[String],
) -> AppleConfig {
  { ..self, scopes }
}

///|
/// 覆盖四类端点（返回新实例）——测试用固定向量时使用。
pub fn AppleConfig::with_endpoints(
  self : AppleConfig,
  authorization_endpoint : String,
  token_endpoint : String,
  jwks_uri : String,
  issuer : String,
) -> AppleConfig {
  {
    ..self,
    authorization_endpoint,
    token_endpoint,
    jwks_uri,
    issuer,
  }
}
