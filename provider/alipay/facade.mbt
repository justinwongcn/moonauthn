//! moonauth / provider/alipay —— provider trait（**整体替换点**）+ 默认实现 + facade。

///|
/// 支付宝登录的**整体替换点**（SDK-01）。
pub(open) trait AlipayProvider {
  /// 生成授权跳转（`publicAppAuthorize.htm`）。
  async fn begin_auth(
    Self,
    secrets : @core.SuppliedSecrets,
  ) -> @core.AuthStart raise @core.AuthError
  /// 处理回调——校验 `state` → 换 token → 取用户信息 → 归一身份。
  async fn complete_auth(
    Self,
    callback : @core.CallbackParams,
    expected : @core.AuthStart,
  ) -> @core.ExternalIdentity raise @core.AuthError
}

///|
/// 支付宝的默认实现。
pub struct DefaultAlipayProvider {
  config : AlipayConfig
}

///|
/// 由装配点构造默认实现。
pub fn DefaultAlipayProvider::new(config : AlipayConfig) -> DefaultAlipayProvider {
  { config, }
}

///|
/// 只读取出内部配置。
pub fn DefaultAlipayProvider::config(
  self : DefaultAlipayProvider,
) -> AlipayConfig {
  self.config
}

///|
/// 实现 `AlipayProvider`：`begin_auth`。
pub impl AlipayProvider for DefaultAlipayProvider with fn begin_auth(self, secrets) {
  let state = match secrets.state {
    Some(v) => v
    None => alipay_random_state(self.config.random)
  }
  // 🔴 动态值一律编码：state 可能由调用方自带（SuppliedSecrets），不编码会被
  // `&`/`#` 截断甚至注入 query（支付宝对畸形 query 只回笼统签名错误）。
  let url = self.config.authorize_endpoint +
    "?app_id=" +
    alipay_percent_encode(self.config.app_id) +
    "&scope=" +
    alipay_percent_encode(self.config.scope) +
    "&redirect_uri=" +
    alipay_percent_encode(self.config.redirect_uri) +
    "&state=" +
    alipay_percent_encode(state)
  { url, state, code_verifier: None, nonce: None }
}

///|
/// 实现 `AlipayProvider`：`complete_auth`。
pub impl AlipayProvider for DefaultAlipayProvider with fn complete_auth(
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
  let code = match callback.get("auth_code") {
    Some(c) => c
    None =>
      match callback.get("code") {
        Some(c) => c
        None => raise @core.MissingParam("auth_code")
      }
  }
  let token = alipay_fetch_token(self.config, code)
  let access_token = match token.get("access_token") {
    Some(t) =>
      if t.length() > 0 {
        t
      } else {
        raise @core.ParseError("moonauth: alipay token response has empty access_token")
      }
    None => raise @core.ParseError("moonauth: alipay token response missing access_token")
  }
  let fallback_user_id = match token.get("user_id") {
    Some(u) => u
    None => ""
  }
  let userinfo = alipay_fetch_userinfo(self.config, access_token)
  alipay_identity(userinfo, fallback_user_id)
}

///|
/// 显式把 trait 方法提升为常规方法，避免隐式提升的弃用告警。
pub extend DefaultAlipayProvider with AlipayProvider::{begin_auth, complete_auth}

///|
/// 生成授权跳转（装配点 + 默认实现）。
pub async fn begin_auth(
  config : AlipayConfig,
  secrets : @core.SuppliedSecrets,
) -> @core.AuthStart raise @core.AuthError {
  let provider = DefaultAlipayProvider::new(config)
  AlipayProvider::begin_auth(provider, secrets)
}

///|
/// 处理回调并归一身份（装配点 + 默认实现）。
pub async fn complete_auth(
  config : AlipayConfig,
  callback : @core.CallbackParams,
  expected : @core.AuthStart,
) -> @core.ExternalIdentity raise @core.AuthError {
  let provider = DefaultAlipayProvider::new(config)
  AlipayProvider::complete_auth(provider, callback, expected)
}

///|
/// 生成十六进制随机 `state`。
fn alipay_random_state(random : &@core.RandomSource) -> String raise @core.AuthError {
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
