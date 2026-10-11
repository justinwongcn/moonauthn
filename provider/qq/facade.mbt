//! moonauth / provider/qq —— provider trait（**整体替换点**）+ 默认实现 + facade。

///|
/// QQ 登录的**整体替换点**（SDK-01）。
pub(open) trait QQProvider {
  /// 生成授权跳转。
  async fn begin_auth(
    Self,
    secrets : @core.SuppliedSecrets,
  ) -> @core.AuthStart raise @core.AuthError
  /// 处理回调——校验 `state` → 换 token → 取 openid（JSONP）→ 取用户信息 → 归一身份。
  async fn complete_auth(
    Self,
    callback : @core.CallbackParams,
    expected : @core.AuthStart,
  ) -> @core.ExternalIdentity raise @core.AuthError
}

///|
/// QQ 的默认实现。
pub struct DefaultQQProvider {
  config : QQConfig
}

///|
/// 由装配点构造默认实现。
pub fn DefaultQQProvider::new(config : QQConfig) -> DefaultQQProvider {
  { config, }
}

///|
/// 只读取出内部配置。
pub fn DefaultQQProvider::config(self : DefaultQQProvider) -> QQConfig {
  self.config
}

///|
/// 实现 `QQProvider`：`begin_auth`。
pub impl QQProvider for DefaultQQProvider with fn begin_auth(self, secrets) {
  let state = match secrets.state {
    Some(v) => v
    None => qq_random_state(self.config.random)
  }
  let url = self.config.authorization_endpoint +
    "?response_type=code" +
    "&client_id=" +
    self.config.appid +
    "&redirect_uri=" +
    qq_percent_encode(self.config.redirect_uri) +
    "&state=" +
    state +
    "&scope=" +
    self.config.scope
  { url, state, code_verifier: None, nonce: None }
}

///|
/// 实现 `QQProvider`：`complete_auth`。
pub impl QQProvider for DefaultQQProvider with fn complete_auth(
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
  let access_token = qq_fetch_token(self.config, code)
  let openid = qq_fetch_openid(self.config, access_token)
  let body = qq_fetch_userinfo(self.config, access_token, openid)
  qq_identity(body, openid)
}

///|
/// 显式把 trait 方法提升为常规方法，避免隐式提升的弃用告警。
pub extend DefaultQQProvider with QQProvider::{begin_auth, complete_auth}

///|
/// 生成授权跳转（装配点 + 默认实现）。
pub async fn begin_auth(
  config : QQConfig,
  secrets : @core.SuppliedSecrets,
) -> @core.AuthStart raise @core.AuthError {
  let provider = DefaultQQProvider::new(config)
  QQProvider::begin_auth(provider, secrets)
}

///|
/// 处理回调并归一身份（装配点 + 默认实现）。
pub async fn complete_auth(
  config : QQConfig,
  callback : @core.CallbackParams,
  expected : @core.AuthStart,
) -> @core.ExternalIdentity raise @core.AuthError {
  let provider = DefaultQQProvider::new(config)
  QQProvider::complete_auth(provider, callback, expected)
}

///|
/// 换 token（带 `fmt=json`，失败回退 form-encoded）。
async fn qq_fetch_token(config : QQConfig, code : String) -> String raise @core.AuthError {
  let url = config.token_endpoint +
    "?grant_type=authorization_code" +
    "&client_id=" +
    config.appid +
    "&client_secret=" +
    config.appsecret +
    "&code=" +
    qq_percent_encode(code) +
    "&redirect_uri=" +
    qq_percent_encode(config.redirect_uri) +
    "&fmt=json"
  let body = qq_get(config, url)
  qq_parse_token(body)
}

///|
/// 取 openid（JSONP）。
async fn qq_fetch_openid(config : QQConfig, access_token : String) -> String raise @core.AuthError {
  let url = config.openid_endpoint + "?access_token=" + access_token
  let body = qq_get(config, url)
  qq_parse_openid(body)
}

///|
/// 取用户信息。
async fn qq_fetch_userinfo(
  config : QQConfig,
  access_token : String,
  openid : String,
) -> String raise @core.AuthError {
  let url = config.userinfo_endpoint +
    "?access_token=" +
    access_token +
    "&oauth_consumer_key=" +
    config.appid +
    "&openid=" +
    openid
  qq_get(config, url)
}

///|
/// 发一个 GET 并把非 2xx 归一为 `HttpStatus`。
async fn qq_get(config : QQConfig, url : String) -> String raise @core.AuthError {
  let resp = config.http.send({
    method : @core.HttpMethod::Get,
    url,
    headers : Map([("Accept", "application/json")]),
    body : None,
  })
  if resp.status < 200 || resp.status >= 300 {
    raise @core.HttpStatus(resp.status, resp.body)
  }
  resp.body
}

///|
/// 生成十六进制随机 `state`（16 字节 CSPRNG → 32 个十六进制字符）。
fn qq_random_state(random : &@core.RandomSource) -> String raise @core.AuthError {
  let bytes = @core.RandomSource::bytes(random, 16)
  let hex = @utf8.encode("0123456789abcdef")
  let out : Array[Byte] = []
  for b in bytes {
    let v = b.to_int()
    out.push(hex[(v >> 4) & 0x0F])
    out.push(hex[v & 0x0F])
  }
  @utf8.decode_lossy(Bytes::from_array(out))
}

///|
/// `application/x-www-form-urlencoded` 百分号编码（空格 → `%20`）。
fn qq_percent_encode(s : String) -> String {
  let bytes = @utf8.encode(s)
  let out : Array[Byte] = []
  let hex = @utf8.encode("0123456789ABCDEF")
  for b in bytes {
    let c = b.to_int()
    if qq_is_unreserved(c) {
      out.push(b)
    } else {
      out.push(b'%')
      out.push(hex[(c >> 4) & 0x0F])
      out.push(hex[c & 0x0F])
    }
  }
  @utf8.decode_lossy(Bytes::from_array(out))
}

///|
/// 是否为 RFC 3986 非保留字符。
fn qq_is_unreserved(c : Int) -> Bool {
  (c >= 65 && c <= 90) ||
  (c >= 97 && c <= 122) ||
  (c >= 48 && c <= 57) ||
  c == 45 ||
  c == 95 ||
  c == 46 ||
  c == 126
}
