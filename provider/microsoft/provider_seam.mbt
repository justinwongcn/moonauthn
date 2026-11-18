//! moonauth / provider/microsoft —— **整体替换点** `MicrosoftProvider`（SDK-01）。
//!
//! 与「能力 seam」不同，provider facade 是**更高一层的替换点**：下游（或官方 SDK
//! 适配层）可实现本 trait，用一个完全不同的 Microsoft 登录实现替换掉
//! `DefaultMicrosoftProvider`，而上层业务代码（对 `MicrosoftProvider` 泛型）无需改动。
//!
//! 🔴 声明为 `pub(open) trait`：`pub trait` 是只读的，跨包无法实现，会让
//! 「可替换性」失效（同 `core` seam 的理由）。

///|
/// Microsoft Entra ID 登录的**整体替换点**。
///
/// - `begin_auth`：生成授权跳转（内部经 `RandomSource` 生成 state / nonce / PKCE，
///   缺省项可由 `secrets` 提供以支持确定性重放）；
/// - `complete_auth`：处理回调——校验 `state` → 错误参数 → 换 token → 取 `tid`
///   做租户策略 → per-tenant issuer 验 `id_token` → 归一身份。
pub(open) trait MicrosoftProvider {
  /// 生成授权跳转。`secrets` 中缺省的临时态由库经 `RandomSource` 生成。
  async fn begin_auth(
    Self,
    secrets : @core.SuppliedSecrets,
  ) -> @core.AuthStart raise @core.AuthError
  /// 处理回调。`expected` 为 `begin_auth` 的返回值（携带本次流程的 `state` /
  /// `nonce` / `code_verifier`）。
  async fn complete_auth(
    Self,
    callback : @core.CallbackParams,
    expected : @core.AuthStart,
  ) -> @core.ExternalIdentity raise @core.AuthError
}
