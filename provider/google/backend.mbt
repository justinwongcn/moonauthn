//! moonauth / provider/google —— 默认实现 `DefaultGoogleProvider`（**组合能力 seam**）。
//!
//! 组合方式：把两件事都建立在**同一组基础 I/O seam** 之上——
//! - `@oauth.StandardOAuthAuthCode`（组 URL + 换 token），接 `config.http`；
//! - `@oidc.JwksIdTokenVerifier`（验 `id_token`），接 `config.http` + `config.clock`。
//!
//! 因而一次 `GoogleConfig::with_http` 即同时覆盖换 token 与 JWKS 抓取，
//! 不存在「某条子 seam 漏走真实网络」的裂缝。
//!
//! 两个能力 seam 亦可在 backend 层单独替换（`with_oauth` / `with_id_token`），
//! 供「只想换其中一个能力」的场景使用；「整provider 替换」则走 `GoogleProvider` trait。

///|
/// Google 的默认实现（组合能力 seam）。
pub struct DefaultGoogleProvider {
  config : GoogleConfig
  oauth : &@core.OAuthAuthCode
  id_token : &@core.IdTokenVerifier
}

///|
/// 由装配点构造默认实现：据 `config` 的**基础 seam** 现场组装两个能力 seam。
pub fn DefaultGoogleProvider::new(
  config : GoogleConfig,
) -> DefaultGoogleProvider {
  let oauth : &@core.OAuthAuthCode = @oauth.StandardOAuthAuthCode::new()
    .with_http(config.http)
  let id_token : &@core.IdTokenVerifier = @oidc.JwksIdTokenVerifier::new_with_http(
    config.http,
  )
    .with_clock(config.clock)
  { config, oauth, id_token }
}

///|
/// 替换换 token 的能力 seam（返回新实例）。
pub fn DefaultGoogleProvider::with_oauth(
  self : DefaultGoogleProvider,
  oauth : &@core.OAuthAuthCode,
) -> DefaultGoogleProvider {
  { ..self, oauth }
}

///|
/// 替换验 id_token 的能力 seam（返回新实例）。
pub fn DefaultGoogleProvider::with_id_token(
  self : DefaultGoogleProvider,
  id_token : &@core.IdTokenVerifier,
) -> DefaultGoogleProvider {
  { ..self, id_token }
}

///|
/// 只读取出内部配置（诊断 / 测试用）。
pub fn DefaultGoogleProvider::config(
  self : DefaultGoogleProvider,
) -> GoogleConfig {
  self.config
}

///|
/// 实现 `GoogleProvider`：`begin_auth`。
pub impl GoogleProvider for DefaultGoogleProvider with fn begin_auth(self, secrets) {
  let state = match secrets.state {
    Some(v) => v
    None => random_token(self.config.random, 16)
  }
  let nonce = match secrets.nonce {
    Some(v) => v
    None => random_token(self.config.random, 16)
  }
  let verifier = match secrets.code_verifier {
    Some(v) => v
    None => @oauth.generate_code_verifier(self.config.random)
  }
  let challenge = @oauth.s256_challenge(verifier)
  let req : @core.AuthorizeRequest = {
    authorization_endpoint: self.config.authorization_endpoint,
    client_id: self.config.client_id,
    redirect_uri: self.config.redirect_uri,
    scopes: self.config.scopes,
    state,
    nonce: Some(nonce),
    code_challenge: Some(challenge),
    code_challenge_method: Some("S256"),
    response_mode: None,
    extra: Map([]),
  }
  let start = self.oauth.begin(req)
  {
    url: start.url,
    state: start.state,
    code_verifier: Some(verifier),
    nonce: start.nonce,
  }
}

///|
/// 实现 `GoogleProvider`：`complete_auth`。
pub impl GoogleProvider for DefaultGoogleProvider with fn complete_auth(
  self,
  callback,
  expected,
) {
  let code = match callback.get("code") {
    Some(c) => c
    None => raise @core.MissingParam("code")
  }
  let state = match callback.get("state") {
    Some(s) => s
    None => raise @core.MissingParam("state")
  }
  if state != expected.state {
    raise @core.StateMismatch
  }
  let token = self.oauth.exchange({
    token_endpoint: self.config.token_endpoint,
    client_id: self.config.client_id,
    client_secret: self.config.client_secret,
    code,
    redirect_uri: self.config.redirect_uri,
    code_verifier: expected.code_verifier,
    extra: Map([]),
  })
  let id_token = match token.id_token {
    Some(t) => t
    None => raise @core.MissingParam("id_token")
  }
  let claims = self.id_token.verify(id_token, {
    issuers: [self.config.issuer],
    audiences: [self.config.client_id],
    nonce: expected.nonce,
    jwks_uri: Some(self.config.jwks_uri),
    leeway_seconds: Some(60),
    algorithms: ["RS256"],
  })
  google_identity(claims)
}

///|
/// 显式把 trait 方法提升为常规方法，避免隐式提升的弃用告警。
pub extend DefaultGoogleProvider with GoogleProvider::{begin_auth, complete_auth}

///|
/// 生成一段 URL-safe 随机令牌（state / nonce 用）：`base64url(N 随机字节)`。
///
/// 复用 `@oauth.base64url_encode`，随机源只经注入的 `RandomSource` seam。
fn random_token(random : &@core.RandomSource, n : Int) -> String raise @core.AuthError {
  @oauth.base64url_encode(@core.RandomSource::bytes(random, n))
}
