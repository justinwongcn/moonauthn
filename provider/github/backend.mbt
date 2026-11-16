//! moonauth / provider/github —— 默认实现 `DefaultGitHubProvider`（**组合能力 seam**）。
//!
//! 组合方式：把授权 URL 组装与 token 交换都建立在**同一组基础 I/O seam** 之上——
//! `@oauth.StandardOAuthAuthCode`（组 URL + 换 token），接 `config.http`。GitHub 无
//! `id_token`（非 OIDC），故不需要 `@oidc`；用户身份经 `GET /user` REST API 获取
//! （见 `user_info.mbt`）。
//!
//! 因而一次 `GitHubConfig::with_http` 即同时覆盖换 token 与 userinfo 抓取，
//! 不存在「某条子 seam 漏走真实网络」的裂缝。

///|
/// GitHub 的默认实现（组合能力 seam）。
pub struct DefaultGitHubProvider {
  config : GitHubConfig
  oauth : &@core.OAuthAuthCode
}

///|
/// 由装配点构造默认实现：据 `config` 的**基础 seam** 现场组装能力 seam。
pub fn DefaultGitHubProvider::new(config : GitHubConfig) -> DefaultGitHubProvider {
  let oauth : &@core.OAuthAuthCode = @oauth.StandardOAuthAuthCode::new().with_http(
    config.http,
  )
  { config, oauth }
}

///|
/// 替换授权 / 换 token 的能力 seam（返回新实例）。
pub fn DefaultGitHubProvider::with_oauth(
  self : DefaultGitHubProvider,
  oauth : &@core.OAuthAuthCode,
) -> DefaultGitHubProvider {
  { ..self, oauth }
}

///|
/// 只读取出内部配置（诊断 / 测试用）。
pub fn DefaultGitHubProvider::config(self : DefaultGitHubProvider) -> GitHubConfig {
  self.config
}

///|
/// 实现 `GitHubProvider`：`begin_auth`。
///
/// GitHub 自 2025-07 起官方支持 PKCE（S256）；`nonce` 无 OIDC 语义，恒为 `None`。
pub impl GitHubProvider for DefaultGitHubProvider with fn begin_auth(self, secrets) {
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
  { url: start.url, state: start.state, code_verifier: Some(verifier), nonce: None }
}

///|
/// 实现 `GitHubProvider`：`complete_auth`。
///
/// 顺序契约：校验 `state` → 回调错误参数（GitHub 失败回调携带
/// `error` / `error_description` / `error_uri`）→ 换 token → `GET /user` →
/// 归一身份。`/user.email` 为 `null`（私有邮箱）时补拉一次 `/user/emails`
/// （可选增强，见 `user_info.mbt`）。
pub impl GitHubProvider for DefaultGitHubProvider with fn complete_auth(
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
  let user = github_fetch_user(self.config, token.access_token)
  github_identity(self.config, token.access_token, user)
}

///|
/// 显式把 trait 方法提升为常规方法，避免隐式提升的弃用告警。
pub extend DefaultGitHubProvider with GitHubProvider::{begin_auth, complete_auth}

///|
/// 生成一段 URL-safe 随机令牌（state 用）：`base64url(N 随机字节)`。
///
/// 复用 `@oauth.base64url_encode`，随机源只经注入的 `RandomSource` seam。
fn random_token(random : &@core.RandomSource, n : Int) -> String raise @core.AuthError {
  @oauth.base64url_encode(@core.RandomSource::bytes(random, n))
}
