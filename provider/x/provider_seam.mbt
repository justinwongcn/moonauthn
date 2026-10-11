//! moonauth / provider/x —— **整体替换点** `XProvider`（SDK-01）。

///|
/// X 登录的**整体替换点**。
pub(open) trait XProvider {
  /// 生成授权跳转（PKCE S256）；缺省临时态由 `RandomSource` 生成。
  async fn begin_auth(
    Self,
    secrets : @core.SuppliedSecrets,
  ) -> @core.AuthStart raise @core.AuthError
  /// 处理回调——校验 `state` → 换 token → 拉 `/2/users/me` → 归一身份。
  async fn complete_auth(
    Self,
    callback : @core.CallbackParams,
    expected : @core.AuthStart,
  ) -> @core.ExternalIdentity raise @core.AuthError
}
