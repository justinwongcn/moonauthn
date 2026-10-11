//! moonauth / core —— 第三方错误 → `AuthError` 的转换助手（error_map）。
//!
//! 🔴 铁律：第三方错误类型**只允许出现在默认实现的函数体内**，在边界处**立即 catch
//! 并转换**，绝不逃逸到 `pub` 签名上。
//!
//! 因此本模块提供的助手一律只接收标准类型（`String` / `Int` / `Bool` / `Error`）：
//! - 默认实现在 `catch` 到第三方错误后，用这些助手把「已解码的语义」转成 `AuthError`；
//! - `@getrandom` / `@async/http` 等无法在 `core` 引用的第三方类型，由其所在子包
//!   （如 `rand`）自行 catch 后调用这里的助手。
//!
//! 映射依据见架构 §5（第三方错误 → `AuthError` 映射表）。

// ════════ 传输层 ════════

///|
/// 网络错误（连接失败 / 超时 / DNS）。
pub fn auth_network(message : String) -> AuthError {
  Network(message)
}

///|
/// 由任意第三方错误（`Error`）转网络错误，保留原始描述。
pub fn auth_network_from(err : Error) -> AuthError {
  Network("moonauth: network failure: \{err}")
}

///|
/// 非 2xx 响应。
pub fn auth_http_status(status : Int, body : String) -> AuthError {
  HttpStatus(status, body)
}

// ════════ 解析 ════════

///|
/// 解析失败（JSON / 表单 / JSONP）。
pub fn auth_parse(message : String) -> AuthError {
  ParseError(message)
}

///|
/// 由任意第三方解析错误转解析失败。
pub fn auth_parse_from(err : Error) -> AuthError {
  ParseError("moonauth: parse failure: \{err}")
}

// ════════ 回调 / 流程校验 ════════

///|
/// 回调缺参。
pub fn auth_missing_param(name : String) -> AuthError {
  MissingParam(name)
}

///|
/// `state` 不符。
pub fn auth_state_mismatch() -> AuthError {
  StateMismatch
}

///|
/// `nonce` 不符。
pub fn auth_nonce_mismatch() -> AuthError {
  NonceMismatch
}

// ════════ 令牌 / 签名 ════════

///|
/// 签名不合法。
pub fn auth_signature_invalid() -> AuthError {
  SignatureInvalid
}

///|
/// 令牌过期。
pub fn auth_token_expired() -> AuthError {
  TokenExpired
}

///|
/// 令牌尚未生效。
pub fn auth_token_not_yet_valid() -> AuthError {
  TokenNotYetValid
}

///|
/// 发行者不符。
pub fn auth_issuer_mismatch(actual : String, expected : String) -> AuthError {
  IssuerMismatch(actual, expected)
}

///|
/// 受众不符。
pub fn auth_audience_mismatch(actual : String, expected : String) -> AuthError {
  AudienceMismatch(actual, expected)
}

///|
/// 不支持的算法。
pub fn auth_unsupported_alg(alg : String) -> AuthError {
  UnsupportedAlg(alg)
}

///|
/// 密钥 / JWKS 加载失败。
pub fn auth_key_error(message : String) -> AuthError {
  KeyError(message)
}

// ════════ challenge（passkey） ════════

///|
/// challenge 不存在。
pub fn auth_challenge_not_found() -> AuthError {
  ChallengeNotFound
}

///|
/// challenge 已过期。
pub fn auth_challenge_expired() -> AuthError {
  ChallengeExpired
}

///|
/// challenge 已被使用（防重放）。
pub fn auth_challenge_already_used() -> AuthError {
  ChallengeAlreadyUsed
}

///|
/// challenge 不符。
pub fn auth_challenge_mismatch() -> AuthError {
  ChallengeMismatch
}

// ════════ WebAuthn 专属 ════════

///|
/// `clientData.origin` 不符。
pub fn auth_origin_mismatch(actual : String, expected : String) -> AuthError {
  OriginMismatch(actual, expected)
}

///|
/// `rp_id_hash` 不符。
pub fn auth_rp_id_mismatch() -> AuthError {
  RpIdMismatch
}

///|
/// `crossOrigin = true` 被拒。
pub fn auth_cross_origin_rejected() -> AuthError {
  CrossOriginRejected
}

///|
/// `signCount` 回退。
pub fn auth_sign_count_regression(stored : Int, received : Int) -> AuthError {
  SignCountRegression(stored, received)
}

///|
/// `clientData.type` 不符。
pub fn auth_type_mismatch(actual : String, expected : String) -> AuthError {
  TypeMismatch(actual, expected)
}

// ════════ provider 业务错误 ════════

///|
/// provider 业务错误码。
pub fn auth_provider_error(code : String, message : String) -> AuthError {
  ProviderError(code, message)
}

// ════════ 其它 ════════

///|
/// 入参非法。
pub fn auth_invalid_input(message : String) -> AuthError {
  InvalidInput(message)
}

///|
/// CSPRNG 不可用。
pub fn auth_random_unavailable() -> AuthError {
  RandomUnavailable
}

///|
/// 库不支持的配置 / 能力。
pub fn auth_unsupported(message : String) -> AuthError {
  Unsupported(message)
}

///|
/// 把「归档后的 `@jwt.Rejected` 语义键」映射为 `AuthError`。
///
/// 默认 `IdTokenVerifier` 在 `catch` 到 `@jwt.Rejected` 后，按其变体判定出一个
/// 稳定的语义键（见下表），再调用本函数，从而**不**把 `@jwt` 类型带进 `core`：
///
/// - `"exp"` → `TokenExpired`
/// - `"nbf"` → `TokenNotYetValid`
/// - `"iss"` → `IssuerMismatch(actual, expected)`
/// - `"aud"` → `AudienceMismatch(actual, expected)`
/// - `"alg"` / `"typ"` → `UnsupportedAlg(kind)`
/// - `"sig"` → `SignatureInvalid`
/// - 其它 → `ParseError`
///
/// 🔴 `"typ"` 归 `UnsupportedAlg`（对齐 ARCH §4.3 映射表）。`TypeMismatch(actual, expected)`
/// 在 `AuthError` 枚举里归属「WebAuthn 专属」分组、语义是 `clientData.type`，被 JWT 的
/// `typ` 头复用会是语义串味，故不在此处映射 `TypeMismatch`。
pub fn auth_from_jwt_reason(
  reason : String,
  actual : String,
  expected : String,
) -> AuthError {
  match reason {
    "exp" => TokenExpired
    "nbf" => TokenNotYetValid
    "iss" => IssuerMismatch(actual, expected)
    "aud" => AudienceMismatch(actual, expected)
    "alg" => UnsupportedAlg(actual)
    "typ" => UnsupportedAlg(actual)
    "sig" => SignatureInvalid
    _ => ParseError("moonauth: unrecognized jwt rejection: " + reason)
  }
}
