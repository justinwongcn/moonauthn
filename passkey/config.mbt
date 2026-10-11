//! moonauth / passkey —— passkey（WebAuthn）部署配置（`PasskeyConfig`）。
//!
//! 配置只使用 MoonBit 标准类型，可跨包传递。
//!
//! `rp_id` / `expected_origin` 是 WebAuthn 的两条**绑定**依据，缺一不可：
//! - `rp_id`：SOP 域（如 `example.com`），与 `authenticatorData.rpIdHash` 绑定，防跨站点；
//! - `expected_origin`：完整来源（如 `https://example.com`），与 `clientDataJSON.origin` 绑定，
//!   防跨来源（含跨源 iframe）攻击。

///|
/// passkey 服务的部署配置。
pub(all) struct PasskeyConfig {
  /// Relying Party ID：通常为可注册域（如 `example.com`）。
  rp_id : String
  /// Relying Party 展示名（写入浏览器创建选项，供用户识别）。
  rp_name : String
  /// 期望的完整来源（如 `https://example.com`），与 `clientDataJSON.origin` 严格相等比对。
  expected_origin : String
  /// 是否**强制**用户验证（UV）。`true` 时缺少 UV 标志的凭据被拒。
  require_user_verification : Bool
  /// 挑战存活秒数（`ChallengeStore` 的 TTL）。
  challenge_ttl_seconds : Int
}

///|
/// 以最小必需项构造：`rp_id` / `rp_name` / `expected_origin`。
///
/// 默认：`require_user_verification = false`、`challenge_ttl_seconds = 300`（5 分钟）。
pub fn PasskeyConfig::new(
  rp_id : String,
  rp_name : String,
  expected_origin : String,
) -> PasskeyConfig {
  {
    rp_id,
    rp_name,
    expected_origin,
    require_user_verification: false,
    challenge_ttl_seconds: 300,
  }
}

///|
/// 覆盖 UV 策略，返回**新**配置。
pub fn PasskeyConfig::with_user_verification(
  self : PasskeyConfig,
  require : Bool,
) -> PasskeyConfig {
  {
    rp_id: self.rp_id,
    rp_name: self.rp_name,
    expected_origin: self.expected_origin,
    require_user_verification: require,
    challenge_ttl_seconds: self.challenge_ttl_seconds,
  }
}

///|
/// 覆盖挑战 TTL（秒），返回**新**配置。
pub fn PasskeyConfig::with_challenge_ttl(
  self : PasskeyConfig,
  ttl_seconds : Int,
) -> PasskeyConfig {
  {
    rp_id: self.rp_id,
    rp_name: self.rp_name,
    expected_origin: self.expected_origin,
    require_user_verification: self.require_user_verification,
    challenge_ttl_seconds: ttl_seconds,
  }
}
