//! moonauth / provider/discord —— facade：面向业务代码的**单一入口**。
//!
//! 业务代码通常只需两步：
//! ```text
//! let start   = begin_auth(config, SuppliedSecrets::default())   // 跳转
//! let identity = complete_auth(config, callback, start)          // 回调落身份
//! ```
//!
//! 这两个自由函数是「装配点 + 默认实现」的薄封装（SDK-02 单一装配点）。
//! 需要替换整 provider 时，直接对 `DiscordProvider` trait 泛型编程，绕开本层即可。

///|
/// 生成授权跳转（装配点 + 默认实现）。
///
/// `secrets` 中缺省的临时态由库经 `RandomSource` 生成；全部提供即得到确定性结果。
pub async fn begin_auth(
  config : DiscordConfig,
  secrets : @core.SuppliedSecrets,
) -> @core.AuthStart raise @core.AuthError {
  let provider = DefaultDiscordProvider::new(config)
  DiscordProvider::begin_auth(provider, secrets)
}

///|
/// 处理回调并归一身份（装配点 + 默认实现）。
pub async fn complete_auth(
  config : DiscordConfig,
  callback : @core.CallbackParams,
  expected : @core.AuthStart,
) -> @core.ExternalIdentity raise @core.AuthError {
  let provider = DefaultDiscordProvider::new(config)
  DiscordProvider::complete_auth(provider, callback, expected)
}
