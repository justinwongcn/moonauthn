//! moonauth / provider/google —— claims → `ExternalIdentity` 归一化。
//!
//! 取值表（见平台文档 `docs/platforms/google.md`）：
//! - `uid = sub`（Google 的稳定用户标识），`uid_kind = Stable`；
//! - `email_verified`：`id_token.email_verified`（可选）→ 缺失记 `false`；
//! - `display_name = name` / `avatar = picture`（可能缺省）；
//! - 其余声明进 `extra`（字符串视图，无第三方类型泄漏）。

///|
/// 把验签后的 `id_token` claims 归一为 `ExternalIdentity`。
pub fn google_identity(claims : @core.IdTokenClaims) -> @core.ExternalIdentity {
  {
    provider: "google",
    uid: claims.subject,
    uid_kind: @core.UidKind::Stable,
    email: claims.email,
    email_verified: match claims.email_verified {
      Some(v) => v
      None => false
    },
    display_name: claims.raw.get("name"),
    avatar: claims.raw.get("picture"),
    extra: claims.raw,
  }
}
