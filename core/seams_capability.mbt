//! moonauth / core —— 能力 seam（5 个）。
//!
//! 🔴 全部 trait 必须写成 `pub(open) trait`（理由见 `seams_io.mbt`）。
//! 所有方法一律 `raise AuthError`；第三方错误在默认实现边界处立即转换，不逃逸。
//!
//! 🔴 其中涉及 I/O 的能力 seam（`OAuthAuthCode` / `IdTokenVerifier`）声明为 `async fn`：
//! - `OAuthAuthCode.exchange` 必须发 HTTP 请求换 token；
//! - `IdTokenVerifier.verify` 可能需要拉取 JWKS（网络 I/O）。
//! 实现侧写 `with fn`（**不是** `with async fn`），调用侧在 async 上下文内直接调用。
//! 纯计算的能力 seam（`WebAuthnVerifier` / `TotpPrimitive` / `SecretSigner`）保持**同步**。

///|
/// 能力 1：OAuth2 Authorization Code（组授权 URL + 换 token）。OIDC / OAuth2 通用语义。
///
/// 声明为 `async fn`：`exchange` 必然发起 HTTP 换 token 请求，须在执行方的 async 上下文内运行。
pub(open) trait OAuthAuthCode {
  /// 组授权 URL，并生成 / 回传本次流程的临时态。
  async fn begin(Self, req : AuthorizeRequest) -> AuthStart raise AuthError
  /// 用授权码换 token。
  async fn exchange(Self, req : TokenExchangeRequest) -> TokenSet raise AuthError
}

///|
/// 能力 2：JWT（id_token）验签。语义 = OIDC：校验 `iss` / `aud` / `exp` / `nonce` 后返回 claims。
///
/// 声明为 `async fn`：验签可能需经 `jwks_uri` 拉取 JWKS（网络 I/O），须在执行方的
/// async 上下文内运行。
pub(open) trait IdTokenVerifier {
  async fn verify(
    Self,
    token : String,
    expect : IdTokenExpectations,
  ) -> IdTokenClaims raise AuthError
}

///|
/// 能力 3：WebAuthn 服务端验签（注册 attestation + 登录 assertion）。
/// 语义 = W3C WebAuthn Level 2。
///
/// 保持**同步**：纯本地密码学计算，无网络 I/O。
pub(open) trait WebAuthnVerifier {
  verify_registration(
    Self,
    input : RegistrationInput,
  ) -> VerifiedRegistration raise AuthError
  verify_assertion(Self, input : AssertionInput) -> VerifiedAssertion raise AuthError
}

///|
/// 能力 4：TOTP 原语。语义 = RFC 6238 / RFC 4226。
///
/// 保持**同步**：纯本地计算（HMAC / Base32），无 I/O。
pub(open) trait TotpPrimitive {
  /// 生成密钥，`bits` 为期望熵位数（如 160）。
  generate_secret(Self, bits : Int) -> Bytes raise AuthError
  /// 生成 `otpauth://` URI（供用户扫码）。
  otpauth_uri(
    Self,
    secret : Bytes,
    account : String,
    issuer : String,
    opts : TotpOptions,
  ) -> String raise AuthError
  /// 校验一次性口令，`at_unix` 为当前时间，`window` 为允许的时钟漂移步数。
  verify(Self, secret : Bytes, code : String, at_unix : Int64, window : Int) -> Bool raise AuthError
  /// 生成恢复码（明文，由调用方展示一次）。
  generate_recovery_codes(Self, count : Int) -> Array[String] raise AuthError
  /// 对恢复码做不可逆哈希（只应持久化哈希结果）。
  hash_recovery_codes(Self, codes : Array[String]) -> Array[String] raise AuthError
}

///|
/// 能力 5：密钥签名（Apple client secret 的 ES256 / 支付宝网关的 RSA2）。
///
/// 保持**同步**：纯本地密码学计算，无 I/O。
pub(open) trait SecretSigner {
  sign(Self, alg : SignAlg, key : SigningKey, message : Bytes) -> Bytes raise AuthError
}
