//! moonauth / provider/x —— 默认实现 `DefaultXProvider`（**组合能力 seam**）。
//!
//! 组合 `@oauth.StandardOAuthAuthCode`（组 URL / 换 token）；身份另经 `/2/users/me` 获取。

///|
/// X 的默认实现。
pub struct DefaultXProvider {
  config : XConfig
  oauth : &@core.OAuthAuthCode
}

///|
/// 由装配点构造默认实现。
pub fn DefaultXProvider::new(config : XConfig) -> DefaultXProvider {
  let oauth : &@core.OAuthAuthCode = @oauth.StandardOAuthAuthCode::new()
    .with_http(config.http)
  { config, oauth }
}

///|
/// 只读取出内部配置。
pub fn DefaultXProvider::config(self : DefaultXProvider) -> XConfig {
  self.config
}

///|
/// 实现 `XProvider`：`begin_auth`（PKCE S256）。
pub impl XProvider for DefaultXProvider with fn begin_auth(self, secrets) {
  let state = match secrets.state {
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
    nonce: None,
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
    nonce: None,
  }
}

///|
/// 实现 `XProvider`：`complete_auth`。
pub impl XProvider for DefaultXProvider with fn complete_auth(
  self,
  callback,
  expected,
) {
  let state = match callback.get("state") {
    Some(s) => s
    None => raise @core.MissingParam("state")
  }
  if state != expected.state {
    raise @core.StateMismatch
  }
  let code = match callback.get("code") {
    Some(c) => c
    None => raise @core.MissingParam("code")
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
  let body = self.fetch_userinfo(token.access_token)
  x_identity(body)
}

///|
/// 显式把 trait 方法提升为常规方法，避免隐式提升的弃用告警。
pub extend DefaultXProvider with XProvider::{begin_auth, complete_auth}

///|
/// `GET /2/users/me`（Bearer access token）。
async fn DefaultXProvider::fetch_userinfo(
  self : DefaultXProvider,
  access_token : String,
) -> String raise @core.AuthError {
  let resp = self.config.http.send({
    method: @core.HttpMethod::Get,
    url: self.config.userinfo_endpoint,
    headers: Map([
      ("Authorization", "Bearer " + access_token),
      ("Accept", "application/json"),
    ]),
    body: None,
  })
  if resp.status < 200 || resp.status >= 300 {
    raise @core.HttpStatus(resp.status, resp.body)
  }
  resp.body
}

///|
/// 生成一段 URL-safe 随机令牌（state 用）。
fn random_token(random : &@core.RandomSource, n : Int) -> String raise @core.AuthError {
  @oauth.base64url_encode(@core.RandomSource::bytes(random, n))
}
