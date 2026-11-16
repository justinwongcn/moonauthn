//! moonauth / provider/apple —— 默认实现 `DefaultAppleProvider`（**组合能力 seam**）+ ES256 client secret。
//!
//! 组合 `@oauth.StandardOAuthAuthCode`（组 URL / 换 token）+ `@oidc.JwksIdTokenVerifier`
//! （RS256 验 `id_token`）+ `@core.SecretSigner`（现签 ES256 client secret），
//! 全部建立在 `config` 的同一组基础 I/O seam 之上。

///|
/// ES256 client secret 的有效期（秒）。Apple 规定上限约 6 个月，取 15777000（≈ 182.6 天）。
let apple_client_secret_ttl : Int64 = 15777000L

///|
/// Apple 的默认实现（组合能力 seam）。
pub struct DefaultAppleProvider {
  config : AppleConfig
  oauth : &@core.OAuthAuthCode
  id_token : &@core.IdTokenVerifier
}

///|
/// 由装配点构造默认实现。
pub fn DefaultAppleProvider::new(
  config : AppleConfig,
) -> DefaultAppleProvider {
  let oauth : &@core.OAuthAuthCode = @oauth.StandardOAuthAuthCode::new()
    .with_http(config.http)
  let id_token : &@core.IdTokenVerifier = @oidc.JwksIdTokenVerifier::new_with_http(
    config.http,
  )
    .with_clock(config.clock)
  { config, oauth, id_token }
}

///|
/// 只读取出内部配置。
pub fn DefaultAppleProvider::config(
  self : DefaultAppleProvider,
) -> AppleConfig {
  self.config
}

///|
/// 实现 `AppleProvider`：`begin_auth`（`response_mode=form_post` + PKCE）。
pub impl AppleProvider for DefaultAppleProvider with fn begin_auth(self, secrets) {
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
    response_mode: Some("form_post"),
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
/// 实现 `AppleProvider`：`complete_auth`。
///
/// 顺序契约：校验 `state` → 回调错误字段（`form_post` 失败回调经 body 传
/// `error` / `error_description`）→ 才轮到 `id_token` / `code`。
pub impl AppleProvider for DefaultAppleProvider with fn complete_auth(
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
  let id_token = match callback.get("id_token") {
    Some(t) => t
    None => raise @core.MissingParam("id_token")
  }
  let code = match callback.get("code") {
    Some(c) => c
    None => raise @core.MissingParam("code")
  }
  // 换 token：client_secret 现签 ES256 JWT。
  let secret = apple_client_secret(self.config)
  let _token = self.oauth.exchange({
    token_endpoint: self.config.token_endpoint,
    client_id: self.config.client_id,
    client_secret: Some(secret),
    code,
    redirect_uri: self.config.redirect_uri,
    code_verifier: expected.code_verifier,
    extra: Map([]),
  })
  // 验 id_token（RS256，iss = apple）。
  let claims = self.id_token.verify(id_token, {
    issuers: [self.config.issuer],
    audiences: [self.config.client_id],
    nonce: expected.nonce,
    jwks_uri: Some(self.config.jwks_uri),
    leeway_seconds: Some(60),
    algorithms: ["RS256"],
  })
  let mut identity = apple_identity(claims)
  // 姓名只在首次授权返回：能从 `user` 解析就补上（绝不缓存）。
  match callback.get("user") {
    Some(user_json) =>
      match apple_user_name(user_json) {
        Some(name) => identity = { ..identity, display_name: Some(name) }
        None => ()
      }
    None => ()
  }
  identity
}

///|
/// 显式把 trait 方法提升为常规方法，避免隐式提升的弃用告警。
pub extend DefaultAppleProvider with AppleProvider::{begin_auth, complete_auth}

///|
/// 现签 Apple **ES256 client secret**（`iss`=team_id，`sub`=client_id，`aud`=apple，
/// `iat`=now，`exp`=now+TTL）。
///
/// 🔴 每次调用都**按当前时钟现签**（不缓存）——Apple 拒绝过期的 client secret，
/// 「现签」避免长期保存带来的轮换 / 时钟漂移问题。
/// 返回 JOSE 紧凑格式：`base64url(header).base64url(payload).base64url(signature)`，
/// 签名是 **raw `r ‖ s`（64 字节）**，与 JOSE ES256 线格式一致。
pub fn apple_client_secret(config : AppleConfig) -> String raise @core.AuthError {
  let now = config.clock.now_unix()
  // 🔴 对**用户配置值**（`key_id` / `team_id` / `client_id`）做 JSON 转义：这些值来自
  // 配置，含 `"` 或 `\` 时若不转义会产出**非法 JSON**、静默得到一个畸形 JWT。
  let header = "{\"alg\":\"ES256\",\"kid\":\"" +
    json_escape(config.key_id) +
    "\",\"typ\":\"JWT\"}"
  let payload = "{\"iss\":\"" +
    json_escape(config.team_id) +
    "\",\"iat\":" +
    now.to_string() +
    ",\"exp\":" +
    (now + apple_client_secret_ttl).to_string() +
    ",\"aud\":\"https://appleid.apple.com\",\"sub\":\"" +
    json_escape(config.client_id) +
    "\"}"
  let signing_input = @oauth.base64url_encode(@utf8.encode(header)) +
    "." +
    @oauth.base64url_encode(@utf8.encode(payload))
  let sig = @core.SecretSigner::sign(
    config.signer,
    @core.SignAlg::ES256,
    config.signing_key,
    @utf8.encode(signing_input),
  )
  signing_input + "." + @oauth.base64url_encode(sig)
}

///|
/// 生成一段 URL-safe 随机令牌（state / nonce 用）。
fn random_token(random : &@core.RandomSource, n : Int) -> String raise @core.AuthError {
  @oauth.base64url_encode(@core.RandomSource::bytes(random, n))
}

///|
/// 把字符串转义为 JSON 字符串字面量的**内容**（不含两侧引号）。
///
/// 覆盖 `"`、`\` 与 U+0000..U+001F 控制字符（后者用 `\u00XX`）；非 ASCII 字节
/// （UTF-8 续字节，值 > 0x7F）原样透传（JSON 允许裸 UTF-8）。用途：让 `AppleConfig`
/// 里任意 `key_id` / `team_id` / `client_id` 都不会破坏 client secret 的 JSON 结构。
///
/// 私有：仅在本包内使用，不含任何第三方类型逃逸（SDK-03）。
fn json_escape(s : String) -> String {
  let bytes = @utf8.encode(s)
  let out : Array[Byte] = []
  let hex = @utf8.encode("0123456789abcdef")
  for b in bytes {
    let c = b.to_int()
    if c == 0x22 {
      // `"`
      out.push(b'\\')
      out.push(b'"')
    } else if c == 0x5C {
      // `\`
      out.push(b'\\')
      out.push(b'\\')
    } else if c == 0x08 {
      out.push(b'\\')
      out.push(b'b')
    } else if c == 0x0C {
      out.push(b'\\')
      out.push(b'f')
    } else if c == 0x0A {
      out.push(b'\\')
      out.push(b'n')
    } else if c == 0x0D {
      out.push(b'\\')
      out.push(b'r')
    } else if c == 0x09 {
      out.push(b'\\')
      out.push(b't')
    } else if c < 0x20 {
      out.push(b'\\')
      out.push(b'u')
      out.push(b'0')
      out.push(b'0')
      out.push(hex[(c >> 4) & 0x0F])
      out.push(hex[c & 0x0F])
    } else {
      out.push(b)
    }
  }
  @utf8.decode_lossy(Bytes::from_array(out))
}
