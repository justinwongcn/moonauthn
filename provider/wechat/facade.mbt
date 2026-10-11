//! moonauth / provider/wechat —— provider trait（**整体替换点**）+ 默认实现 + facade。
//!
//! 微信整条链路自成一体：组 URL 用 `url.mbt` 的严格顺序模板；换 token / 取用户信息
//! 用 `GET + query`；身份归一在 `userinfo.mbt`。

///|
/// 微信登录的**整体替换点**（SDK-01）。
pub(open) trait WeChatProvider {
  /// 生成授权跳转（无 PKCE）。
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
/// 微信的默认实现。
pub struct DefaultWeChatProvider {
  config : WeChatConfig
}

///|
/// 由装配点构造默认实现。
pub fn DefaultWeChatProvider::new(config : WeChatConfig) -> DefaultWeChatProvider {
  { config, }
}

///|
/// 只读取出内部配置。
pub fn DefaultWeChatProvider::config(self : DefaultWeChatProvider) -> WeChatConfig {
  self.config
}

///|
/// 实现 `WeChatProvider`：`begin_auth`。
pub impl WeChatProvider for DefaultWeChatProvider with fn begin_auth(self, secrets) {
  let state = match secrets.state {
    Some(v) => v
    None => wechat_random_state(self.config.random)
  }
  let url = wechat_authorize_url(self.config, state)
  { url, state, code_verifier: None, nonce: None }
}

///|
/// 实现 `WeChatProvider`：`complete_auth`。
pub impl WeChatProvider for DefaultWeChatProvider with fn complete_auth(
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
  let token = wechat_fetch_token(self.config, code)
  let body = wechat_fetch_userinfo(self.config, token.access_token, token.openid)
  // unionid 兜底链：userinfo.unionid → token.unionid → openid(Degraded)。
  wechat_identity(body, token.openid, fallback_unionid=token.unionid)
}

///|
/// 显式把 trait 方法提升为常规方法，避免隐式提升的弃用告警。
pub extend DefaultWeChatProvider with WeChatProvider::{begin_auth, complete_auth}

///|
/// 生成授权跳转（装配点 + 默认实现）。
pub async fn begin_auth(
  config : WeChatConfig,
  secrets : @core.SuppliedSecrets,
) -> @core.AuthStart raise @core.AuthError {
  let provider = DefaultWeChatProvider::new(config)
  WeChatProvider::begin_auth(provider, secrets)
}

///|
/// 处理回调并归一身份（装配点 + 默认实现）。
pub async fn complete_auth(
  config : WeChatConfig,
  callback : @core.CallbackParams,
  expected : @core.AuthStart,
) -> @core.ExternalIdentity raise @core.AuthError {
  let provider = DefaultWeChatProvider::new(config)
  WeChatProvider::complete_auth(provider, callback, expected)
}

///|
/// 用授权码换 token（`GET /sns/oauth2/access_token`）。
pub async fn wechat_fetch_token(
  config : WeChatConfig,
  code : String,
) -> WeChatToken raise @core.AuthError {
  let url = config.token_endpoint +
    "?appid=" +
    config.appid +
    "&secret=" +
    config.secret +
    "&code=" +
    wechat_percent_encode(code) +
    "&grant_type=authorization_code"
  let resp = config.http.send({
    method : @core.HttpMethod::Get,
    url,
    headers : Map([("Accept", "application/json")]),
    body : None,
  })
  if resp.status < 200 || resp.status >= 300 {
    raise @core.HttpStatus(resp.status, resp.body)
  }
  wechat_parse_token(resp.body)
}

///|
/// 生成十六进制随机 `state`（`n` 字节 CSPRNG → `2n` 个十六进制字符）。
fn wechat_random_state(random : &@core.RandomSource) -> String raise @core.AuthError {
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
