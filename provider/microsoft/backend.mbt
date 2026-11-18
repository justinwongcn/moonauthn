//! moonauth / provider/microsoft —— 默认实现 `DefaultMicrosoftProvider`
//! （**组合能力 seam**，与 google 同构）。
//!
//! 组合方式：把两件事都建立在**同一组基础 I/O seam** 之上——
//! - `@oauth.StandardOAuthAuthCode`（组 URL + 换 token），接 `config.http`；
//! - `@oidc.JwksIdTokenVerifier`（验 `id_token`，RS256 + per-tenant JWKS），
//!   接 `config.http` + `config.clock`。
//!
//! 🔴 **per-tenant issuer 派生**（与 Google 的唯一结构性差异）：换 token 后从
//! **未验签** claims 取 `tid` → 租户白名单（如配置）→ 按 `issuer_template`
//! 派生出**精确 issuer** 再验签。安全锚点：签名必须对真实微软 JWKS 验证、
//! `aud` 必须等于 client_id、`nonce` 必须一致——伪造 `tid` 只会导向「用错误
//! 租户的公钥验签失败」，构不成绕过。

///|
/// Microsoft 的默认实现（组合能力 seam）。
pub struct DefaultMicrosoftProvider {
  config : MicrosoftConfig
  oauth : &@core.OAuthAuthCode
  id_token : &@core.IdTokenVerifier
}

///|
/// 由装配点构造默认实现：据 `config` 的**基础 seam** 现场组装两个能力 seam。
pub fn DefaultMicrosoftProvider::new(
  config : MicrosoftConfig,
) -> DefaultMicrosoftProvider {
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
pub fn DefaultMicrosoftProvider::with_oauth(
  self : DefaultMicrosoftProvider,
  oauth : &@core.OAuthAuthCode,
) -> DefaultMicrosoftProvider {
  { ..self, oauth }
}

///|
/// 替换验 id_token 的能力 seam（返回新实例）。
pub fn DefaultMicrosoftProvider::with_id_token(
  self : DefaultMicrosoftProvider,
  id_token : &@core.IdTokenVerifier,
) -> DefaultMicrosoftProvider {
  { ..self, id_token }
}

///|
/// 只读取出内部配置（诊断 / 测试用）。
pub fn DefaultMicrosoftProvider::config(
  self : DefaultMicrosoftProvider,
) -> MicrosoftConfig {
  self.config
}

///|
/// 实现 `MicrosoftProvider`：`begin_auth`。
///
/// `nonce` 必发（调研契约：ID Token 重放防护）；PKCE S256 推荐，恒启用。
pub impl MicrosoftProvider for DefaultMicrosoftProvider with fn begin_auth(
  self,
  secrets,
) {
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
/// 实现 `MicrosoftProvider`：`complete_auth`。
///
/// 顺序契约：校验 `state` → 回调错误参数（`error` / `error_description` /
/// `error_codes`，AADSTS 细节随 description 原样透传给调用方诊断）→ 换 token →
/// 从未验签 claims 取 `tid` → 租户白名单 → per-tenant issuer 验签 → 归一身份。
pub impl MicrosoftProvider for DefaultMicrosoftProvider with fn complete_auth(
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
  match callback.provider_error() {
    Some(e) => raise e
    None => ()
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
  let id_token = match token.id_token {
    Some(t) => t
    None => raise @core.MissingParam("id_token")
  }
  // 🔴 未验签 claims：**只**用于取 `tid`（选择 issuer / 租户白名单），不参与
  // 身份语义——身份一律来自随后验签通过的 claims。
  let unverified = @jwt.claims_unverified(id_token[:]) catch {
    _ => raise @core.ParseError("moonauth: microsoft id_token is not decodable")
  }
  let tid = match unverified.get("tid") {
    Some(String(s)) => if s.length() > 0 { Some(s) } else { None }
    _ => None
  }
  if self.config.allowed_tenant_ids.length() > 0 {
    let allowed = match tid {
      Some(t) => self.config.allowed_tenant_ids.contains(t)
      None => false
    }
    if !allowed {
      raise @core.ProviderError(
        "tenant_not_allowed",
        "moonauth: microsoft id_token tid " + tid.unwrap_or("<missing>") +
        " is not in the allowed tenant list",
      )
    }
  }
  // 🔴 issuer 精确派生：`{tid}` 占位符 → token 的 tid；不含 `{tid}` 的模板
  // （测试 / 单租户）直接作为固定 issuer。绝不做前缀 / 包含匹配。
  let issuer = match tid {
    Some(t) => expand_placeholder(self.config.issuer_template, "{tid}", t)
    None =>
      if self.config.issuer_template.contains("{tid}") {
        raise @core.InvalidInput(
          "moonauth: microsoft id_token is missing tid but the issuer template requires it",
        )
      } else {
        self.config.issuer_template
      }
  }
  let claims = self.id_token.verify(id_token, {
    issuers: [issuer],
    audiences: [self.config.client_id],
    nonce: expected.nonce,
    jwks_uri: Some(self.config.jwks_uri),
    leeway_seconds: Some(60),
    algorithms: ["RS256"],
  })
  microsoft_identity(claims)
}

///|
/// 显式把 trait 方法提升为常规方法，避免隐式提升的弃用告警。
pub extend DefaultMicrosoftProvider with MicrosoftProvider::{begin_auth, complete_auth}

///|
/// 生成一段 URL-safe 随机令牌（state / nonce 用）：`base64url(N 随机字节)`。
///
/// 复用 `@oauth.base64url_encode`，随机源只经注入的 `RandomSource` seam。
fn random_token(random : &@core.RandomSource, n : Int) -> String raise @core.AuthError {
  @oauth.base64url_encode(@core.RandomSource::bytes(random, n))
}
