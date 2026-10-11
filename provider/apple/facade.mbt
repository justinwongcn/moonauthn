//! moonauth / provider/apple —— facade：面向业务代码的**单一入口**（SDK-02）。
//!
//! 典型用法：
//! ```text
//! let start    = begin_auth(config, SuppliedSecrets::default())
//! // 浏览器 form_post 回调体 → 交给 apple_callback 解析
//! let callback = apple_callback(request_body)
//! let identity = complete_auth(config, callback, start)
//! ```

///|
/// 生成授权跳转（`response_mode=form_post`）。
pub async fn begin_auth(
  config : AppleConfig,
  secrets : @core.SuppliedSecrets,
) -> @core.AuthStart raise @core.AuthError {
  let provider = DefaultAppleProvider::new(config)
  AppleProvider::begin_auth(provider, secrets)
}

///|
/// 处理 `form_post` 回调并归一身份。
pub async fn complete_auth(
  config : AppleConfig,
  callback : @core.CallbackParams,
  expected : @core.AuthStart,
) -> @core.ExternalIdentity raise @core.AuthError {
  let provider = DefaultAppleProvider::new(config)
  AppleProvider::complete_auth(provider, callback, expected)
}
