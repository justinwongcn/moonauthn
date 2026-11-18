//! moonauth / provider/microsoft —— claims → `ExternalIdentity` 归一化。
//!
//! 取值表（见平台文档 `docs/platforms/microsoft.md`）：
//! - `uid = sub`（pairwise 标识，同一应用内稳定），`uid_kind = Stable`；
//! - `email_verified`：`id_token.email_verified`（可选）→ 缺失记 `false`
//!   （**不得假定微软邮箱已验证**）；
//! - `display_name = name`，缺省回退 `preferred_username`（两者皆可变，均非主键）；
//! - `avatar`：v2.0 id_token 无头像声明，恒 `None`；
//! - 其余声明（含 `oid` / `tid` / `groups` / `roles`）进 `extra`（字符串视图）——
//!   `tid` / `oid` 供调用方做租户策略与审计，`oid` 不可取代 `sub` 作主键。

///|
/// 把验签后的 `id_token` claims 归一为 `ExternalIdentity`。
pub fn microsoft_identity(claims : @core.IdTokenClaims) -> @core.ExternalIdentity {
  let display_name = match claims.raw.get("name") {
    Some(n) => Some(n)
    None => claims.raw.get("preferred_username")
  }
  {
    provider: "microsoft",
    uid: claims.subject,
    uid_kind: @core.UidKind::Stable,
    email: claims.email,
    email_verified: match claims.email_verified {
      Some(v) => v
      None => false
    },
    display_name,
    avatar: None,
    extra: claims.raw,
  }
}
