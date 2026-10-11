//! moonauth / provider/feishu —— provider trait（**整体替换点**）+ 默认实现 + facade。

///|
/// 飞书登录的**整体替换点**（SDK-01）。
pub(open) trait FeishuProvider {
  /// 生成授权跳转。
  async fn begin_auth(
    Self,
    secrets : @core.SuppliedSecrets,
  ) -> @core.AuthStart raise @core.AuthError
  /// 处理回调——校验 `state` → 换 `user_access_token`（JSON 体）→ 取用户信息 → 归一身份。
  async fn complete_auth(
    Self,
    callback : @core.CallbackParams,
    expected : @core.AuthStart,
  ) -> @core.ExternalIdentity raise @core.AuthError
}

///|
/// 飞书的默认实现。
///
/// 持有 `@oauth` seam 只为**组授权 URL**（飞书授权端点是标准参数形态，复用 seam 的
/// percent-encode / 字典序 / PKCE 组装）；换 token 因 JSON 体自实现（见 `config.mbt`
/// 头注释）。
pub struct DefaultFeishuProvider {
  config : FeishuConfig
  oauth : &@core.OAuthAuthCode
}

///|
/// 由装配点构造默认实现：据 `config` 的**基础 seam** 现场组装能力 seam。
pub fn DefaultFeishuProvider::new(config : FeishuConfig) -> DefaultFeishuProvider {
  let oauth : &@core.OAuthAuthCode = @oauth.StandardOAuthAuthCode::new().with_http(
    config.http,
  )
  { config, oauth }
}

///|
/// 替换授权 URL 组装的能力 seam（返回新实例）。
pub fn DefaultFeishuProvider::with_oauth(
  self : DefaultFeishuProvider,
  oauth : &@core.OAuthAuthCode,
) -> DefaultFeishuProvider {
  { ..self, oauth }
}

///|
/// 只读取出内部配置（诊断 / 测试用）。
pub fn DefaultFeishuProvider::config(self : DefaultFeishuProvider) -> FeishuConfig {
  self.config
}

///|
/// 实现 `FeishuProvider`：`begin_auth`。
///
/// 飞书新版 OAuth 支持 PKCE（`S256`）；`nonce` 无 OIDC id_token 语义，恒为 `None`。
pub impl FeishuProvider for DefaultFeishuProvider with fn begin_auth(self, secrets) {
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
    client_id: self.config.app_id,
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
/// 实现 `FeishuProvider`：`complete_auth`。
///
/// 流程：校验 `state` → 换 `user_access_token` → 取用户信息 → 归一身份。
pub impl FeishuProvider for DefaultFeishuProvider with fn complete_auth(
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
  let access_token = feishu_fetch_token(self.config, code, expected.code_verifier)
  let body = feishu_fetch_userinfo(self.config, access_token)
  feishu_identity(body)
}

///|
/// 显式把 trait 方法提升为常规方法，避免隐式提升的弃用告警。
pub extend DefaultFeishuProvider with FeishuProvider::{begin_auth, complete_auth}

///|
/// 生成授权跳转（装配点 + 默认实现）。
pub async fn begin_auth(
  config : FeishuConfig,
  secrets : @core.SuppliedSecrets,
) -> @core.AuthStart raise @core.AuthError {
  let provider = DefaultFeishuProvider::new(config)
  FeishuProvider::begin_auth(provider, secrets)
}

///|
/// 处理回调并归一身份（装配点 + 默认实现）。
pub async fn complete_auth(
  config : FeishuConfig,
  callback : @core.CallbackParams,
  expected : @core.AuthStart,
) -> @core.ExternalIdentity raise @core.AuthError {
  let provider = DefaultFeishuProvider::new(config)
  FeishuProvider::complete_auth(provider, callback, expected)
}

///|
/// 换 `user_access_token`：`POST /authen/v2/oauth/token`，**JSON 请求体**（snake_case 字段）。
async fn feishu_fetch_token(
  config : FeishuConfig,
  code : String,
  code_verifier : String?,
) -> String raise @core.AuthError {
  let body_map : Map[String, String] = Map([
    ("grant_type", "authorization_code"),
    ("client_id", config.app_id),
    ("client_secret", config.app_secret),
    ("code", code),
    ("redirect_uri", config.redirect_uri),
  ])
  match code_verifier {
    Some(v) => body_map["code_verifier"] = v
    None => ()
  }
  // 经 `@json.to_json` 走标准转义（字段全为字符串）。
  let body = @json.to_json(body_map).stringify()
  let resp = config.http.send({
    method: @core.HttpMethod::Post,
    url: config.token_endpoint,
    headers: Map([
      ("Content-Type", "application/json"),
      ("Accept", "application/json"),
    ]),
    body: Some(body),
  })
  if resp.status < 200 || resp.status >= 300 {
    feishu_raise_http_error(resp)
  }
  feishu_parse_token(resp.body)
}

///|
/// 取用户信息：`GET /authen/v1/user_info`，`Authorization: Bearer` 鉴权。
async fn feishu_fetch_userinfo(
  config : FeishuConfig,
  access_token : String,
) -> String raise @core.AuthError {
  let resp = config.http.send({
    method: @core.HttpMethod::Get,
    url: config.user_info_endpoint,
    headers: Map([
      ("Authorization", "Bearer " + access_token),
      ("Accept", "application/json"),
    ]),
    body: None,
  })
  if resp.status < 200 || resp.status >= 300 {
    feishu_raise_http_error(resp)
  }
  resp.body
}

///|
/// 生成一段 URL-safe 随机令牌（state 用）：`base64url(N 随机字节)`。
///
/// 复用 `@oauth.base64url_encode`，随机源只经注入的 `RandomSource` seam。
fn random_token(random : &@core.RandomSource, n : Int) -> String raise @core.AuthError {
  @oauth.base64url_encode(@core.RandomSource::bytes(random, n))
}
