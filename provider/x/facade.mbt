//! moonauth / provider/x —— facade：面向业务代码的**单一入口**（SDK-02）。

///|
/// 生成授权跳转（PKCE S256）。
pub async fn begin_auth(
  config : XConfig,
  secrets : @core.SuppliedSecrets,
) -> @core.AuthStart raise @core.AuthError {
  let provider = DefaultXProvider::new(config)
  XProvider::begin_auth(provider, secrets)
}

///|
/// 处理回调并归一身份。
pub async fn complete_auth(
  config : XConfig,
  callback : @core.CallbackParams,
  expected : @core.AuthStart,
) -> @core.ExternalIdentity raise @core.AuthError {
  let provider = DefaultXProvider::new(config)
  XProvider::complete_auth(provider, callback, expected)
}
