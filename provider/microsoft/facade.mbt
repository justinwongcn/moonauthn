//! moonauth / provider/microsoft —— facade：面向业务代码的**单一入口**。
//!
//! 业务代码通常只需两步：
//! ```text
//! let start    = begin_auth(config, SuppliedSecrets::default())  // 跳转
//! let identity = complete_auth(config, callback, start)          // 回调落身份
//! ```
//!
//! 需要替换整 provider 时，直接对 `MicrosoftProvider` trait 泛型编程。

///|
/// 生成授权跳转（装配点 + 默认实现）。
pub async fn begin_auth(
  config : MicrosoftConfig,
  secrets : @core.SuppliedSecrets,
) -> @core.AuthStart raise @core.AuthError {
  let provider = DefaultMicrosoftProvider::new(config)
  MicrosoftProvider::begin_auth(provider, secrets)
}

///|
/// 处理回调并归一身份（装配点 + 默认实现）。
pub async fn complete_auth(
  config : MicrosoftConfig,
  callback : @core.CallbackParams,
  expected : @core.AuthStart,
) -> @core.ExternalIdentity raise @core.AuthError {
  let provider = DefaultMicrosoftProvider::new(config)
  MicrosoftProvider::complete_auth(provider, callback, expected)
}
