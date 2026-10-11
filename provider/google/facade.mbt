//! moonauth / provider/google —— facade：面向业务代码的**单一入口**。
//!
//! 业务代码通常只需两步：
//! ```text
//! let start   = begin_auth(config, SuppliedSecrets::default())   // 跳转
//! let identity = complete_auth(config, callback, start)          // 回调落身份
//! ```
//!
//! 这两个自由函数是「装配点 + 默认实现」的薄封装（SDK-02 单一装配点）。
//! 需要替换整provider 时，直接对 `GoogleProvider` trait 泛型编程，绕开本层即可。

///|
/// 生成授权跳转（装配点 + 默认实现）。
///
/// `secrets` 中缺省的临时态由库经 `RandomSource` 生成；全部提供即得到确定性结果。
pub async fn begin_auth(
  config : GoogleConfig,
  secrets : @core.SuppliedSecrets,
) -> @core.AuthStart raise @core.AuthError {
  let provider = DefaultGoogleProvider::new(config)
  GoogleProvider::begin_auth(provider, secrets)
}

///|
/// 处理回调并归一身份（装配点 + 默认实现）。
pub async fn complete_auth(
  config : GoogleConfig,
  callback : @core.CallbackParams,
  expected : @core.AuthStart,
) -> @core.ExternalIdentity raise @core.AuthError {
  let provider = DefaultGoogleProvider::new(config)
  GoogleProvider::complete_auth(provider, callback, expected)
}
