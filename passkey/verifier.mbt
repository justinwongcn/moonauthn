//! moonauth / passkey —— 默认 `WebAuthnVerifier` 实现：`StandardWebAuthnVerifier`。
//!
//! 语义 = W3C WebAuthn Level 2 的注册（attestation）/ 登录（assertion）服务端校验。
//!
//! ## 校验顺序（严格按 WebAuthn §7）
//! 1. **解析 `clientDataJSON`**（本实现自解析，而非直接调 `@webauthn.verify_client_data`）：
//!    自解析才能同时拿到 `crossOrigin`——该标志**不在** `verify_client_data` 的检查范围内；
//! 2. **来源策略**：`crossOrigin = true` → `CrossOriginRejected`（跨源 iframe 一律拒绝）；
//!    `type` 必须为 `webauthn.create` / `webauthn.get`；`challenge` 与期望严格相等；
//!    `origin` 与期望严格相等；
//! 3. **认证器策略**（委托 `@webauthn`）：`rpIdHash` 绑定、User Present 必须置位、
//!    需要时强制 User Verified；
//! 4. **密码学**：attestation 签名 / assertion 签名（`@webauthn`）；
//! 5. **签名计数器回退检测**：`signCount` 非零且 `<= storedSignCount` → `SignCountRegression`
//!    （可疑克隆；`stored = received = 0` 时跳过——大量认证器恒报 0）。
//!
//! ## 第三方类型约束
//! `@webauthn.WebAuthnError` / `@cbor.CborValue` / `Json` **只出现在私有函数体**；公开签名
//! 只见 `@core` 与标准类型，`.mbti` 干净（SDK-03）。所有第三方错误在边界立即 `catch`
//! 并映射为 `AuthError`。

///|
/// 默认 `WebAuthnVerifier` 实现。
///
/// 只持有 UV 策略：`require_user_verification`（seam 的 `RegistrationInput` /
/// `AssertionInput` 不含 UV 字段，故它是实现级策略）。
pub struct StandardWebAuthnVerifier {
  require_user_verification : Bool
}

///|
/// 以默认策略构造（不强制 UV）。
pub fn StandardWebAuthnVerifier::new() -> StandardWebAuthnVerifier {
  { require_user_verification: false }
}

///|
/// 覆盖 UV 策略，返回**新**实例。
pub fn StandardWebAuthnVerifier::with_user_verification(
  self : StandardWebAuthnVerifier,
  require : Bool,
) -> StandardWebAuthnVerifier {
  let _ = self
  { require_user_verification: require }
}

///|
/// 只读访问 UV 策略。
pub fn StandardWebAuthnVerifier::require_user_verification(
  self : StandardWebAuthnVerifier,
) -> Bool {
  self.require_user_verification
}

// ════════ seam 实现 ════════

///|
/// 校验注册（attestation）。
pub impl @core.WebAuthnVerifier for StandardWebAuthnVerifier with fn verify_registration(
  self,
  input,
) {
  verify_registration_input(self.require_user_verification, input)
}

///|
/// 校验登录（assertion）。
pub impl @core.WebAuthnVerifier for StandardWebAuthnVerifier with fn verify_assertion(
  self,
  input,
) {
  verify_assertion_input(self.require_user_verification, input)
}

///|
/// 显式把 seam 方法提升为常规方法，避免隐式提升的弃用告警。
pub extend StandardWebAuthnVerifier with @core.WebAuthnVerifier::{
  verify_registration,
  verify_assertion,
}

// ════════ 注册校验 ════════

///|
/// 注册校验主流程（私有）。
fn verify_registration_input(
  require_user_verification : Bool,
  input : @core.RegistrationInput,
) -> @core.VerifiedRegistration raise @core.AuthError {
  let client_data = decode_client_data(input.client_data_json)
  check_client_data(
    client_data,
    "webauthn.create",
    input.expected_challenge,
    input.expected_origin,
  )
  let client_data_hash = @webauthn.client_data_hash(input.client_data_json)
  let rp_id_hash = @webauthn.rp_id_hash(input.rp_id)
  let result = @webauthn.verify_attestation(
    input.attestation_object,
    client_data_hash,
    rp_id_hash~,
    require_user_verification~,
  ) catch {
    e => raise map_webauthn_error(e)
  }
  // `AttestationResult` 不暴露 flags，故单独取 authData 读 UV 位。
  let user_verified = attestation_user_verified(input.attestation_object)
  {
    credential_id: result.credential_id,
    public_key: result.credential_public_key,
    sign_count: result.sign_count.reinterpret_as_int(),
    aaguid: format_aaguid(result.aaguid),
    user_verified,
  }
}

// ════════ 登录校验 ════════

///|
/// 登录校验主流程（私有）。
fn verify_assertion_input(
  require_user_verification : Bool,
  input : @core.AssertionInput,
) -> @core.VerifiedAssertion raise @core.AuthError {
  let client_data = decode_client_data(input.client_data_json)
  check_client_data(
    client_data,
    "webauthn.get",
    input.expected_challenge,
    input.expected_origin,
  )
  let client_data_hash = @webauthn.client_data_hash(input.client_data_json)
  let rp_id_hash = @webauthn.rp_id_hash(input.rp_id)
  let authenticator_data = @webauthn.parse_authenticator_data(
    input.authenticator_data,
  ) catch {
    e => raise map_webauthn_error(e)
  }
  @webauthn.verify_assertion(
    input.credential_public_key,
    input.authenticator_data,
    client_data_hash,
    input.signature,
    rp_id_hash~,
    require_user_verification~,
  ) catch {
    e => raise map_webauthn_error(e)
  }
  let received = authenticator_data.sign_count.reinterpret_as_int()
  let stored = input.stored_sign_count
  // WebAuthn §7.2：任一方非零且 received <= stored 视为克隆信号（0/0 例外：很多
  // 认证器恒报 0，此时计数器不具可比性，跳过）。
  if (received != 0 || stored != 0) && received <= stored {
    raise @core.SignCountRegression(stored, received)
  }
  { sign_count: received, user_verified: authenticator_data.user_verified() }
}

// ════════ clientDataJSON 解析与策略 ════════

///|
/// 解析后的 `clientDataJSON` 关键字段。
priv struct ClientData {
  ceremony_type : String
  challenge : String
  origin : String
  cross_origin : Bool
}

///|
/// 解析 `clientDataJSON`（**本实现自解析**，见文件头注释）。
fn decode_client_data(raw : Bytes) -> ClientData raise @core.AuthError {
  let text = @utf8.decode(raw) catch {
    _ =>
      raise @core.ParseError("moonauth: webauthn clientDataJSON is not valid UTF-8")
  }
  let parsed = @json.parse(text) catch {
    _ =>
      raise @core.ParseError("moonauth: webauthn clientDataJSON is not valid JSON")
  }
  let members = match parsed {
    Object(m) => m
    _ =>
      raise @core.ParseError(
        "moonauth: webauthn clientDataJSON is not a JSON object",
      )
  }
  {
    ceremony_type: client_data_string(members, "type"),
    challenge: client_data_string(members, "challenge"),
    origin: client_data_string(members, "origin"),
    cross_origin: client_data_cross_origin(members),
  }
}

///|
/// 取 `clientDataJSON` 的字符串字段；缺失 / 非字符串 → `ParseError`。
fn client_data_string(
  members : Map[String, Json],
  key : String,
) -> String raise @core.AuthError {
  match members.get(key) {
    Some(String(s)) => s
    _ =>
      raise @core.ParseError(
        "moonauth: webauthn clientDataJSON missing/invalid field: " + key,
      )
  }
}

///|
/// 取 `crossOrigin`（仅当显式为 `true` 才是跨源；缺失 / `false` 均视为同源）。
fn client_data_cross_origin(members : Map[String, Json]) -> Bool {
  match members.get("crossOrigin") {
    Some(True) => true
    _ => false
  }
}

///|
/// 来源 / 类型 / 挑战策略校验（顺序：跨源 → 类型 → 挑战 → 来源）。
fn check_client_data(
  client_data : ClientData,
  expected_type : String,
  expected_challenge : String,
  expected_origin : String,
) -> Unit raise @core.AuthError {
  if client_data.cross_origin {
    raise @core.CrossOriginRejected
  }
  if client_data.ceremony_type != expected_type {
    raise @core.TypeMismatch(client_data.ceremony_type, expected_type)
  }
  if client_data.challenge != expected_challenge {
    raise @core.ChallengeMismatch
  }
  if client_data.origin != expected_origin {
    raise @core.OriginMismatch(client_data.origin, expected_origin)
  }
}

// ════════ attestation 辅助 ════════

///|
/// 从 attestationObject 取 `authData` 并读 User Verified 位。
///
/// `AttestationResult` 不含 flags，故这里用 `@cbor` 解出 `authData` 再交给 `@webauthn` 解析
/// （`@cbor` 类型只在此私有函数体内出现）。
fn attestation_user_verified(
  attestation_object : Bytes,
) -> Bool raise @core.AuthError {
  let decoded = @cbor.decode(attestation_object) catch {
    _ =>
      raise @core.ParseError(
        "moonauth: webauthn attestationObject is not valid CBOR",
      )
  }
  let auth_data = match @cbor.map_get_str(decoded, "authData") {
    Some(Bytes(b)) => b
    _ =>
      raise @core.ParseError(
        "moonauth: webauthn attestationObject has no authData",
      )
  }
  let parsed = @webauthn.parse_authenticator_data(auth_data) catch {
    e => raise map_webauthn_error(e)
  }
  parsed.user_verified()
}

///|
/// AAGUID（16 字节）→ UUID 文本；长度非 16 → `None`。
fn format_aaguid(aaguid : Bytes) -> String? {
  if aaguid.length() != 16 {
    return None
  }
  let hex = hex_encode(aaguid)
  Some(
    hex[0:8].to_owned() +
    "-" +
    hex[8:12].to_owned() +
    "-" +
    hex[12:16].to_owned() +
    "-" +
    hex[16:20].to_owned() +
    "-" +
    hex[20:32].to_owned(),
  )
}

// ════════ 通用私有助手 ════════

///|
/// 字节 → 小写十六进制。
///
/// 说明：这是包内私有工具（`totp` 包亦有一份同形实现）。**有意不放进 `core`**——
/// `core` 在本轮已冻结，且它只是一个与领域无关的 3 行文本工具；跨包重复的代价远小于
/// 改动冻结契约的风险。
fn hex_encode(bytes : Bytes) -> String {
  let hex = @utf8.encode("0123456789abcdef")
  let out : Array[Byte] = []
  for b in bytes {
    let v = b.to_int()
    out.push(hex[(v >> 4) & 0x0F])
    out.push(hex[v & 0x0F])
  }
  @utf8.decode_lossy(Bytes::from_array(out))
}

///|
/// `@webauthn.WebAuthnError` → `AuthError`（边界转换；`@webauthn` / `@cbor` / `@pkix` 类型绝不逃逸）。
///
/// 映射要点：
/// - `RpIdMismatch` → `RpIdMismatch`；
/// - `SignatureInvalid` → `SignatureInvalid`；
/// - `UserNotPresent` / `UserNotVerified` → `InvalidInput`（认证器策略违规，无专属分支）；
/// - `ClientDataInvalid` → `ParseError`（本实现自解析 clientDataJSON，此臂为防御性兜底）。
fn map_webauthn_error(e : @webauthn.WebAuthnError) -> @core.AuthError {
  match e {
    Cbor(_) => @core.ParseError("moonauth: webauthn CBOR decode failed")
    ParseError(msg) => @core.ParseError("moonauth: webauthn: " + msg)
    UnsupportedAlgorithm(a) => @core.UnsupportedAlg("webauthn algorithm \{a}")
    UnsupportedKeyType(msg) =>
      @core.Unsupported("moonauth: webauthn key type: " + msg)
    Pkix(_) =>
      @core.KeyError("moonauth: webauthn attestation certificate parse failed")
    PkixVerify(_) =>
      @core.KeyError("moonauth: webauthn attestation key extraction failed")
    SignatureInvalid => @core.SignatureInvalid
    AttestationFailure(msg) =>
      @core.ParseError("moonauth: webauthn attestation failure: " + msg)
    ClientDataInvalid(detail) =>
      @core.ParseError("moonauth: webauthn clientData: " + detail)
    RpIdMismatch => @core.RpIdMismatch
    UserNotPresent =>
      @core.InvalidInput("moonauth: webauthn user-present flag not set")
    UserNotVerified =>
      @core.InvalidInput(
        "moonauth: webauthn user verification required but not performed",
      )
  }
}
