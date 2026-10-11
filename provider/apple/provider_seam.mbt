//! moonauth / provider/apple —— **整体替换点** `AppleProvider`（SDK-01）。

///|
/// Apple 登录的**整体替换点**。
pub(open) trait AppleProvider {
  /// 生成授权跳转（`response_mode=form_post`）；缺省临时态由 `RandomSource` 生成。
  async fn begin_auth(
    Self,
    secrets : @core.SuppliedSecrets,
  ) -> @core.AuthStart raise @core.AuthError
  /// 处理 `form_post` 回调——校验 `state` → 验 `id_token` → 换 token（ES256 client secret）
  /// → 归一身份。
  async fn complete_auth(
    Self,
    callback : @core.CallbackParams,
    expected : @core.AuthStart,
  ) -> @core.ExternalIdentity raise @core.AuthError
}
