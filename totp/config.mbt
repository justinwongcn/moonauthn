//! moonauth / totp —— TOTP 配置（`TotpConfig`）。
//!
//! 配置只使用 MoonBit 标准类型（`String` / `Int`），可自由跨包传递，且不泄漏任何第三方类型。
//!
//! 🔴 为什么 `digits` / `period` / `algorithm` 是**配置**而不是 `verify` 的入参：
//! seam `core.TotpPrimitive.verify(Self, secret, code, at_unix, window)` 的签名由 SDK-01
//! 冻结（不含选项），故这些「每个部署固定、每次校验恒定」的参数放在实现状态里。
//! `window`（时钟漂移容差）则随每次调用传入——它依赖调用场景而非部署。

///|
/// TOTP 参数集（RFC 6238 / RFC 4226）。
///
/// 字段直接公开，调用方可先用 `TotpConfig::new` 取默认集，再用 `with_*` 链式覆盖。
pub(all) struct TotpConfig {
  /// 服务 / 平台名（`otpauth://` 的 `issuer`）。
  issuer : String
  /// 用户账号（`otpauth://` 的 label 后半段）。
  account : String
  /// 口令位数（RFC 允许 6 或 8）。
  digits : Int
  /// 时间步长（秒，RFC 默认 30）。
  period : Int
  /// HMAC 算法名：`"SHA1"` | `"SHA256"` | `"SHA512"`。
  algorithm : String
  /// 允许的时钟漂移步数（每步 = 一个 `period`）。
  window : Int
}

///|
/// 以 RFC 6238 的推荐默认值构造：SHA-1 / 6 位 / 30 秒 / 漂移 ±1 步。
pub fn TotpConfig::new(issuer : String, account : String) -> TotpConfig {
  {
    issuer,
    account,
    digits: 6,
    period: 30,
    algorithm: "SHA1",
    window: 1,
  }
}

///|
/// 覆盖口令位数，返回**新**配置（不改原配置）。
pub fn TotpConfig::with_digits(self : TotpConfig, digits : Int) -> TotpConfig {
  {
    issuer: self.issuer,
    account: self.account,
    digits,
    period: self.period,
    algorithm: self.algorithm,
    window: self.window,
  }
}

///|
/// 覆盖时间步长（秒），返回**新**配置。
pub fn TotpConfig::with_period(self : TotpConfig, period : Int) -> TotpConfig {
  {
    issuer: self.issuer,
    account: self.account,
    digits: self.digits,
    period,
    algorithm: self.algorithm,
    window: self.window,
  }
}

///|
/// 覆盖 HMAC 算法名（`"SHA1"` / `"SHA256"` / `"SHA512"`），返回**新**配置。
pub fn TotpConfig::with_algorithm(self : TotpConfig, algorithm : String) -> TotpConfig {
  {
    issuer: self.issuer,
    account: self.account,
    digits: self.digits,
    period: self.period,
    algorithm,
    window: self.window,
  }
}

///|
/// 覆盖时钟漂移容差（步数），返回**新**配置。
pub fn TotpConfig::with_window(self : TotpConfig, window : Int) -> TotpConfig {
  {
    issuer: self.issuer,
    account: self.account,
    digits: self.digits,
    period: self.period,
    algorithm: self.algorithm,
    window,
  }
}

///|
/// 该配置下推荐的自带熵位数：与所选 HMAC 算法输出宽度一致
/// （SHA-1 → 160、SHA-256 → 256、SHA-512 → 512），对齐 RFC 6238 附录 B 的密钥长度。
///
/// 未知算法名回退到 160（SHA-1 的宽度）。
pub fn TotpConfig::recommended_secret_bits(self : TotpConfig) -> Int {
  match self.algorithm {
    "SHA256" => 256
    "SHA512" => 512
    _ => 160
  }
}
