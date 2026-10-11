//! moonauth / core —— 错误类型（errors）。
//!
//! `AuthError` 是一个**可穷尽 match** 的错误枚举：下游不写 `_` 兜底也能编译通过
//! （分支穷尽，见 `auth_error_code`）。
//!
//! 🔴 不设 `Degraded` 分支：降级由 `ExternalIdentity.uid_kind = Degraded` 表达，
//! 不属于错误路径（架构 Q8）。

///|
/// 库对外唯一的错误类型。第三方错误在默认实现边界处立即 `catch` 并转换为本枚举，
/// 第三方错误类型**绝不**逃逸到任何 `pub` 签名上（SDK-03）。
///
/// 它是 `suberror`（MoonBit 中可作为 `raise` 目标的错误类型），但使用形态与枚举一致：
/// 可 `match`、可穷尽（见 `auth_error_code`），且**不做**「隐式 impl 提升为普通方法」的
/// 弃用推广。
pub(all) suberror AuthError {
  // —— 传输层 ——
  /// 连接失败 / 超时 / DNS 失败。
  Network(String)
  /// 非 2xx 响应：(status, body 摘要)。
  HttpStatus(Int, String)
  // —— 回调 / 流程校验 ——
  /// 回调缺少必需参数（参数名）。
  MissingParam(String)
  /// `state` 与预期不符。
  StateMismatch
  /// `nonce` 与预期不符。
  NonceMismatch
  // —— challenge（passkey） ——
  /// challenge 不存在。
  ChallengeNotFound
  /// challenge 已过期。
  ChallengeExpired
  /// challenge 已被使用（防重放）。
  ChallengeAlreadyUsed
  /// challenge 与预期不符。
  ChallengeMismatch
  // —— 令牌 / 签名 ——
  /// 签名不合法。
  SignatureInvalid
  /// 令牌已过期（exp）。
  TokenExpired
  /// 令牌尚未生效（nbf）。
  TokenNotYetValid
  /// 发行者不符：(actual, expected)。
  IssuerMismatch(String, String)
  /// 受众不符：(actual, expected)。
  AudienceMismatch(String, String)
  /// 不支持的签名算法。
  UnsupportedAlg(String)
  /// 密钥 / JWKS 加载失败。
  KeyError(String)
  // —— WebAuthn 专属 ——
  /// `clientData.origin` 不符：(actual, expected)。
  OriginMismatch(String, String)
  /// `rp_id_hash` 不符。
  RpIdMismatch
  /// `crossOrigin = true` 必须拒绝。
  CrossOriginRejected
  /// `signCount` 回退：(stored, received)。
  SignCountRegression(Int, Int)
  /// `clientData.type` 不符：(actual, expected)。
  TypeMismatch(String, String)
  // —— provider 业务错误码 ——
  /// provider 返回的业务错误：(code, message)。
  ProviderError(String, String)
  // —— 解析 ——
  /// JSON / form-encoded / JSONP 解析失败。
  ParseError(String)
  // —— 其它 ——
  /// 调用方入参非法（如 TOTP 密钥长度不足）。
  InvalidInput(String)
  /// CSPRNG 不可用。
  RandomUnavailable
  /// 库不支持的配置 / 能力。
  Unsupported(String)
}

///|
/// 为 `AuthError` 生成稳定的分类码。
///
/// 本函数对 `AuthError` 做了**不含 `_` 兜底**的穷尽 `match`——它能编译通过本身就是
/// 「枚举分支穷尽」的编译期证明（架构验收标准 2）。
pub fn auth_error_code(err : AuthError) -> String {
  match err {
    Network(_) => "network"
    HttpStatus(_, _) => "http_status"
    MissingParam(_) => "missing_param"
    StateMismatch => "state_mismatch"
    NonceMismatch => "nonce_mismatch"
    ChallengeNotFound => "challenge_not_found"
    ChallengeExpired => "challenge_expired"
    ChallengeAlreadyUsed => "challenge_already_used"
    ChallengeMismatch => "challenge_mismatch"
    SignatureInvalid => "signature_invalid"
    TokenExpired => "token_expired"
    TokenNotYetValid => "token_not_yet_valid"
    IssuerMismatch(_, _) => "issuer_mismatch"
    AudienceMismatch(_, _) => "audience_mismatch"
    UnsupportedAlg(_) => "unsupported_alg"
    KeyError(_) => "key_error"
    OriginMismatch(_, _) => "origin_mismatch"
    RpIdMismatch => "rp_id_mismatch"
    CrossOriginRejected => "cross_origin_rejected"
    SignCountRegression(_, _) => "sign_count_regression"
    TypeMismatch(_, _) => "type_mismatch"
    ProviderError(_, _) => "provider_error"
    ParseError(_) => "parse_error"
    InvalidInput(_) => "invalid_input"
    RandomUnavailable => "random_unavailable"
    Unsupported(_) => "unsupported"
  }
}

///|
/// `AuthError` 的人类可读描述（一律返回标准 `String`，不引入第三方类型）。
pub fn auth_error_message(err : AuthError) -> String {
  match err {
    Network(msg) => "network error: " + msg
    HttpStatus(status, body) => "http status \{status}: " + body
    MissingParam(name) => "missing callback parameter: " + name
    StateMismatch => "state mismatch"
    NonceMismatch => "nonce mismatch"
    ChallengeNotFound => "challenge not found"
    ChallengeExpired => "challenge expired"
    ChallengeAlreadyUsed => "challenge already used"
    ChallengeMismatch => "challenge mismatch"
    SignatureInvalid => "signature invalid"
    TokenExpired => "token expired"
    TokenNotYetValid => "token not yet valid"
    IssuerMismatch(actual, expected) =>
      "issuer mismatch: actual=" + actual + ", expected=" + expected
    AudienceMismatch(actual, expected) =>
      "audience mismatch: actual=" + actual + ", expected=" + expected
    UnsupportedAlg(alg) => "unsupported algorithm: " + alg
    KeyError(msg) => "key error: " + msg
    OriginMismatch(actual, expected) =>
      "origin mismatch: actual=" + actual + ", expected=" + expected
    RpIdMismatch => "rp id mismatch"
    CrossOriginRejected => "cross-origin rejected"
    SignCountRegression(stored, received) =>
      "sign count regression: stored=\{stored}, received=\{received}"
    TypeMismatch(actual, expected) =>
      "type mismatch: actual=" + actual + ", expected=" + expected
    ProviderError(code, message) => "provider error " + code + ": " + message
    ParseError(msg) => "parse error: " + msg
    InvalidInput(msg) => "invalid input: " + msg
    RandomUnavailable => "random source unavailable"
    Unsupported(msg) => "unsupported: " + msg
  }
}
