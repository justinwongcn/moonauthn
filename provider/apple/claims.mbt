//! moonauth / provider/apple —— claims → `ExternalIdentity` 归一化。
//!
//! - `uid = sub`（Apple 的稳定用户标识），`uid_kind = Stable`；
//! - `email_verified`：`id_token.email_verified`（可选）→ 缺失记 `false`；
//! - `is_private_email`：Apple 会以 `true`（布尔）或 `"true"`（字符串）两形态返回，
//!   此处统一归一为 `Bool`（见 `apple_is_private_email`）；
//! - `display_name`：Apple **不在** `id_token` 里放姓名——姓名只经首次授权的 `user`
//!   字段返回（由 `backend` 从回调补入）；
//! - 其余声明进 `extra`（字符串视图）。

///|
/// 把验签后的 `id_token` claims 归一为 `ExternalIdentity`（`display_name` 为空，
/// 由 facade 视首次授权的 `user` 补入）。
pub fn apple_identity(claims : @core.IdTokenClaims) -> @core.ExternalIdentity {
  {
    provider: "apple",
    uid: claims.subject,
    uid_kind: @core.UidKind::Stable,
    email: claims.email,
    email_verified: match claims.email_verified {
      Some(v) => v
      None => false
    },
    display_name: None,
    avatar: None,
    extra: claims.raw,
  }
}

///|
/// `is_private_email` 归一为 `Bool`：兼容 `true`（布尔）与 `"true"`（字符串）两形态。
///
/// 归一后以标准 `Bool` 对外表达（`raw` 里两种形态都被字符串化为 `"true"`）。
pub fn apple_is_private_email(claims : @core.IdTokenClaims) -> Bool {
  match claims.raw.get("is_private_email") {
    Some(v) => v == "true"
    None => false
  }
}
