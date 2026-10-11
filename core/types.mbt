//! moonauth / core —— 公开类型（types）。
//!
//! 本文件定义库对外最稳定的三个类型：`UidKind` / `ExternalIdentity` / `ProviderDescriptor`。
//! 全部字段只使用 MoonBit 标准类型，禁止出现任何第三方类型（SDK-03）。

///|
/// 稳定标识（uid）的强度。
///
/// 降级（Degraded）用 **结果标记** 表达，不走 `AuthError`（架构 Q8 决议）：
/// 「降级」是一次**成功的**登录，只是拿到的标识较弱，下游据此决定是否接受绑定。
pub(all) enum UidKind {
  /// 平台保证稳定：Google/Apple `sub`、微信 `unionid`、支付宝 `user_id`、
  /// QQ `openid`（与 appid 绑定）、X 的数值用户 ID。
  Stable
  /// 只能拿到较弱标识：目前唯一场景是「微信仅返回 openid 而无 unionid」。
  Degraded
}

///|
/// 所有 provider 归一化后的身份。库对外唯一的「身份」类型。
///
/// 库**不**建账号、**不**存映射、**不**发会话——本类型只是把各平台返回的
/// 异构字段收敛成统一形态，交由调用方决定后续处理。
pub(all) struct ExternalIdentity {
  /// 平台标识："google" | "apple" | "wechat" | "qq" | "alipay" | "x"
  provider : String
  /// 稳定标识取值（见各 provider 文档的取值表）。
  uid : String
  /// 该取值能达到的稳定度。
  uid_kind : UidKind
  /// 平台可能不返回邮箱。
  email : String?
  /// 一律归一为 `Bool`（例如 Apple 的 `true` / `"true"` 在此收敛）。
  email_verified : Bool
  /// 昵称，可能缺省（如微信 2021 起不再返回）。
  display_name : String?
  /// 头像 URL，可能缺省。
  avatar : String?
  /// provider 附加字段的字符串视图（只用标准 `Map[String, String]`，无类型泄漏）。
  extra : Map[String, String]
}

///|
/// provider 元信息（供下游渲染「聚合登录入口」，不含任何页面）。
/// 零依赖、零 I/O、纯数据。
pub(all) struct ProviderDescriptor {
  /// 平台标识，如 "google"。
  id : String
  /// 展示名，如 "Google"。
  display_name : String
  /// 该平台是否使用 PKCE（S256）。
  supports_pkce : Bool
  /// 该平台是否返回可验签的 OIDC `id_token`。
  supports_id_token : Bool
  /// 该 provider 默认能达到的稳定度（运行时可能因缺字段而降级）。
  uid_kind : UidKind
  /// 指向库内平台文档的 URL。
  doc_url : String
}
