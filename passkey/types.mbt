//! moonauth / passkey —— passkey（WebAuthn）专属值类型。
//!
//! 全部只使用 `@core` 与 MoonBit 标准类型；临时态（challenge / key）随返回值交给调用方
//! 持有（零状态），持久化凭据也是**值类型**，由调用方自行落库。

///|
/// 一次 passkey 仪式（注册或认证）的临时挑战。
///
/// 调用方把 `challenge` 放进浏览器侧的 `PublicKeyCredentialCreationOptions.challenge`
/// / `PublicKeyCredentialRequestOptions.challenge`（base64url，**原样**），
/// 并在收尾时把 `key` 交回 `finish_*_stored`。
pub(all) struct PasskeyChallenge {
  /// base64url（无填充）的随机挑战。客户端会把它原样回显到 `clientDataJSON.challenge`，
  /// 服务端据此比对（见 `verify_client_data`）。
  challenge : String
  /// 该挑战在 `ChallengeStore` 中的键（仅 `*_stored` 流程使用；调用方可存进会话）。
  key : String
  /// 挑战过期时刻（Unix 秒），供调用方做展示 / 清理。
  expires_at : Int64
}

///|
/// 一条**已注册**的 passkey 凭据（供调用方持久化）。
///
/// 与 `@core.VerifiedRegistration` 语义一致，但作为「长期保存的凭据记录」命名。
/// `sign_count` 用于后续认证的**回退检测**（防克隆），认证时作为
/// `AssertionInput.stored_sign_count` 回传。
pub(all) struct PasskeyCredential {
  /// 凭据 ID（认证时浏览器回传，用作凭据主键）。
  credential_id : Bytes
  /// COSE 公钥（认证验签用）。
  public_key : Bytes
  /// 最近一次已知的签名计数器。
  sign_count : Int
  /// 认证器 AAGUID（UUID 文本；无 attested credential data 时为 `None`）。
  aaguid : String?
  /// 注册时是否完成用户验证（UV）。
  user_verified : Bool
  /// 该凭据关联的**用户句柄**（WebAuthn `user.id`，即浏览器 `PublicKeyCredentialUserEntity.id`
  /// 的原始字节）。用于后续认证时把凭据映射回具体用户。
  ///
  /// `from_registration` 默认置 `None`（seam 的 `VerifiedRegistration` 不含该字段）；
  /// 调用方在拿到 `user.id` 后经 `PasskeyCredential::with_user_handle` 回填。
  user_handle : Bytes?
}

///|
/// 把 seam 的注册结果转成可持久化的凭据记录。
///
/// `user_handle` 默认 `None`（`VerifiedRegistration` 不含用户句柄），可用
/// `with_user_handle` 回填。
pub fn PasskeyCredential::from_registration(
  registration : @core.VerifiedRegistration,
) -> PasskeyCredential {
  {
    credential_id: registration.credential_id,
    public_key: registration.public_key,
    sign_count: registration.sign_count,
    aaguid: registration.aaguid,
    user_verified: registration.user_verified,
    user_handle: None,
  }
}

///|
/// 关联用户句柄（WebAuthn `user.id` 原始字节），返回**新**凭据记录（不改原记录）。
pub fn PasskeyCredential::with_user_handle(
  self : PasskeyCredential,
  user_handle : Bytes,
) -> PasskeyCredential {
  { ..self, user_handle: Some(user_handle) }
}

// ════════ 浏览器侧选项（LIB-05 ①，**加法**补足） ════════
//
// 🔴 这些类型是「库替调用方产出的浏览器选项」。为**加法**补足，`PasskeyChallenge` 与
// `begin_*` / `finish_*` / `*_stored` 的签名**保持原样**（T04 已过 QA）；构建入口是新增的
// `PasskeyService::registration_options` / `authentication_options`（见 `facade.mbt`）。
//
// 字段名采用 MoonBit 约定（`snake_case`）；每个类型都注明其对应的**浏览器 JSON** 字段名
// （camelCase）——调用方把 options 序列化给浏览器时按该映射输出。

///|
/// WebAuthn `PublicKeyCredentialParameters`：一种可接受的**公钥算法**。
///
/// 浏览器 JSON：`{ "type": "public-key", "alg": -7 }`。
/// 本库默认（也是唯一）启用 **ES256（`alg = -7`）**——与 `StandardWebAuthnVerifier` 的能力一致。
pub(all) struct PublicKeyCredParam {
  /// 凭据类型，规范固定为 `"public-key"`（浏览器 JSON：`type`）。
  type_ : String
  /// COSE 算法标识，ES256 = **-7**（浏览器 JSON：`alg`）。
  alg : Int
}

///|
/// ES256（`type = "public-key"`、`alg = -7`）参数项。
pub fn PublicKeyCredParam::es256() -> PublicKeyCredParam {
  { type_: "public-key", alg: -7 }
}

///|
/// Relying Party 信息（浏览器 JSON：`rp`）。
pub(all) struct RpInfo {
  /// RP ID（SOP 域，如 `example.com`），取自 `PasskeyConfig.rp_id`（浏览器 JSON：`rp.id`）。
  id : String
  /// RP 展示名，取自 `PasskeyConfig.rp_name`（浏览器 JSON：`rp.name`）。
  name : String
}

///|
/// 注册用户实体（浏览器 JSON：`user`）。
pub(all) struct UserInfo {
  /// 用户句柄（浏览器 JSON：`user.id`）——**原始字节**。由调用方生成（如用户主键的字节）。
  /// 认证时浏览器会回显，可与 `PasskeyCredential.user_handle` 对应。
  id : Bytes
  /// 用户名（浏览器 JSON：`user.name`）。
  name : String
  /// 友好显示名（浏览器 JSON：`user.displayName`）；缺省时前端可回退到 `name`。
  display_name : String?
}

///|
/// 凭据描述符（浏览器 JSON：`allowCredentials` / `excludeCredentials` 的元素）。
pub(all) struct CredentialDescriptor {
  /// 固定为 `"public-key"`（浏览器 JSON：`type`）。
  type_ : String
  /// 凭据 ID（**原始字节**；浏览器 JSON：`id`）。
  id : Bytes
  /// 传输方式提示（如 `["internal"]`、`["usb","nfc"]`；浏览器 JSON：`transports`）；可缺省。
  transports : Array[String]?
}

///|
/// 由凭据 ID 构造一个 `public-key` 描述符（`transports` 缺省）。
pub fn CredentialDescriptor::public_key(id : Bytes) -> CredentialDescriptor {
  { type_: "public-key", id, transports: None }
}

///|
/// 认证器选择标准（浏览器 `authenticatorSelection` —— `AuthenticatorSelectionCriteria`）。
///
/// 🔴 浏览器该字段是**对象**（不是字符串）：`{ authenticatorAttachment, residentKey,
/// requireResidentKey, userVerification }`。各字段的浏览器 JSON 名见下方 doc。
///
/// 要拿到**可发现凭据**（真正的 passkey，而非绑定式凭据），通常需要
/// `resident_key = "required"`（+ 常见 `user_verification = "required"`）——
/// 见便捷构造 `AuthenticatorSelection::passkey()`。
pub(all) struct AuthenticatorSelection {
  /// 认证器类型（浏览器 JSON：`authenticatorAttachment`）：`"platform"` | `"cross-platform"`。
  authenticator_attachment : String?
  /// 常驻密钥要求（浏览器 JSON：`residentKey`）：`"required"` | `"preferred"` | `"discouraged"`。
  resident_key : String?
  /// 旧字段（浏览器 JSON：`requireResidentKey`）。与 `resident_key` **二选一**——供**旧实现**兼容
  /// （新实现用 `resident_key`）；`None` 时不输出该字段。
  require_resident_key : Bool?
  /// 用户验证要求（浏览器 JSON：`userVerification`）：`"required"` | `"preferred"` | `"discouraged"`。
  user_verification : String?
}

///|
/// passkey 的常见组合：平台认证器 + 强制常驻密钥（可发现凭据）+ 强制 UV。
///
/// = `{ authenticator_attachment: Some("platform"), resident_key: Some("required"),
///      user_verification: Some("required"), require_resident_key: None }`
pub fn AuthenticatorSelection::passkey() -> AuthenticatorSelection {
  {
    authenticator_attachment: Some("platform"),
    resident_key: Some("required"),
    require_resident_key: None,
    user_verification: Some("required"),
  }
}

///|
/// 注册选项（浏览器 `PublicKeyCredentialCreationOptions`）。
///
/// 🔴 `challenge` 为 **base64url（无填充）字符串**：与 `PasskeyChallenge.challenge` 同形态，
/// 也是**服务端发给浏览器的 JSON** 里 `challenge` 的既定编码。浏览器原生
/// `navigator.credentials.create()` 需要 `ArrayBuffer`——由**前端**把 base64url 解码为字节
/// （库不参与浏览器运行时，见 `facade.mbt` 的链路说明）。
pub(all) struct RegistrationOptions {
  /// base64url 挑战（原样取自 `PasskeyChallenge.challenge`）。
  challenge : String
  /// RP 信息（浏览器 JSON：`rp`）。
  rp : RpInfo
  /// 用户实体（浏览器 JSON：`user`）。
  user : UserInfo
  /// 可接受算法，默认 `[ES256]`（浏览器 JSON：`pubKeyCredParams`）。
  pub_key_cred_params : Array[PublicKeyCredParam]
  /// 超时毫秒（浏览器 JSON：`timeout`）；`None` 表示交给浏览器决定。
  timeout : Int?
  /// 证明偏好 `"none"` / `"indirect"` / `"direct"` / `"enterprise"`（浏览器 JSON：`attestation`）。
  attestation : String?
  /// 认证器选择（浏览器 JSON：`authenticatorSelection`）——**对象**（`AuthenticatorSelection`），
  /// **不是**字符串。`None` 时前端可省略该字段；需要可发现凭据时用
  /// `AuthenticatorSelection::passkey()`。
  authenticator_selection : AuthenticatorSelection?
  /// 排除已有凭据，避免同一认证器重复注册（浏览器 JSON：`excludeCredentials`）。
  exclude_credentials : Array[CredentialDescriptor]?
}

///|
/// 认证选项（浏览器 `PublicKeyCredentialRequestOptions`）。
pub(all) struct AuthenticationOptions {
  /// base64url 挑战（原样取自 `PasskeyChallenge.challenge`）。
  challenge : String
  /// RP ID（浏览器 JSON：`rpId`）。
  rp_id : String
  /// 允许的凭据（浏览器 JSON：`allowCredentials`）；`None` 表示省略（可发现凭据 / 常驻密钥）。
  allow_credentials : Array[CredentialDescriptor]?
  /// 用户验证偏好 `"required"` / `"preferred"` / `"discouraged"`（浏览器 JSON：`userVerification`）。
  user_verification : String?
  /// 超时毫秒（浏览器 JSON：`timeout`）。
  timeout : Int?
}
