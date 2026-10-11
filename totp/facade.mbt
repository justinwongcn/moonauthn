//! moonauth / totp —— 高层门面：`TotpService`。
//!
//! 门面把「配置 + 注入的 seam（`TotpPrimitive` / `Clock`）」组装成调用方直接可用的 2FA 流程：
//! - `enroll`：生成密钥 + `otpauth://` URI（一次性展示给用户）；
//! - `verify`：以注入时钟的当前时间 + 配置的漂移窗口校验口令；
//! - `recovery_codes`：生成明文恢复码（展示一次）**及其**待持久化哈希。
//!
//! ## 零状态
//! 门面自身不持有任何用户数据：密钥、恢复码明文与哈希都随返回值**交给调用方**。
//! 门面只持有注入的 seam 引用与一份部署级配置。
//!
//! ## 全部同步
//! `TotpPrimitive` / `Clock` 都是**同步** seam（纯本地 HMAC / 时间读取，无 I/O），
//! 故本门面全部方法为同步——不引入 async 传染。

///|
/// 注册（enrollment）结果：密钥与供扫码的 `otpauth://` URI。
///
/// 🔴 `secret` 是**秘密**：只应展示给用户一次（扫码 / 抄写），切勿落日志或明文库。
pub(all) struct TotpEnrollment {
  /// 原始共享密钥字节（保存它才能校验后续口令）。
  secret : Bytes
  /// `otpauth://totp/...` URI（渲染为二维码供认证器 App 扫描）。
  uri : String
}

///|
/// 恢复码结果：明文（展示一次）与待持久化哈希。
///
/// 🔴 只持久化 `hashes`；`plaintext` 展示一次后**必须丢弃**。
pub(all) struct TotpRecoveryCodes {
  /// 明文恢复码（仅展示一次）。
  plaintext : Array[String]
  /// 与 `plaintext` 一一对应的 `hex(sha256(code))`。
  hashes : Array[String]
}

///|
/// TOTP 门面。持有注入的能力 seam 与部署配置，本身无状态。
pub struct TotpService {
  primitive : &@core.TotpPrimitive
  clock : &@core.Clock
  config : TotpConfig
}

///|
/// 以配置构造。默认装配 `StandardTotpPrimitive`（其 `RandomSource` 为 `@rand.GetrandomSource`）
/// 与 `@core.SystemClock`，二者均可用 `with_*` 覆盖（测试注入固定随机源 / 固定时钟）。
pub fn TotpService::new(config : TotpConfig) -> TotpService {
  let primitive : &@core.TotpPrimitive = StandardTotpPrimitive::new().with_config(
    config,
  )
  let clock : &@core.Clock = @core.SystemClock::new()
  { primitive, clock, config }
}

///|
/// 只读访问当前配置。
pub fn TotpService::config(self : TotpService) -> TotpConfig {
  self.config
}

///|
/// 覆盖原语实现，返回**新**门面（不改原门面）。
pub fn TotpService::with_primitive(
  self : TotpService,
  primitive : &@core.TotpPrimitive,
) -> TotpService {
  { primitive, clock: self.clock, config: self.config }
}

///|
/// 覆盖时钟，返回**新**门面（不改原门面）。
pub fn TotpService::with_clock(
  self : TotpService,
  clock : &@core.Clock,
) -> TotpService {
  { primitive: self.primitive, clock, config: self.config }
}

// ════════ 注册 ════════

///|
/// 注册：生成密钥与 `otpauth://` URI。
///
/// 熵位数取 `config.recommended_secret_bits()`（与所选 HMAC 算法输出宽度一致）。
pub fn TotpService::enroll(self : TotpService) -> TotpEnrollment raise @core.AuthError {
  self.enroll_with_bits(self.config.recommended_secret_bits())
}

///|
/// 注册（自定义熵位数）。
pub fn TotpService::enroll_with_bits(
  self : TotpService,
  bits : Int,
) -> TotpEnrollment raise @core.AuthError {
  let secret = @core.TotpPrimitive::generate_secret(self.primitive, bits)
  let opts : @core.TotpOptions = {
    digits: self.config.digits,
    period: self.config.period,
    algorithm: self.config.algorithm,
  }
  let uri = @core.TotpPrimitive::otpauth_uri(
    self.primitive,
    secret,
    self.config.account,
    self.config.issuer,
    opts,
  )
  { secret, uri }
}

// ════════ 校验 ════════

///|
/// 校验口令：以注入时钟的**当前**时间 + 配置的漂移窗口校验。
pub fn TotpService::verify(
  self : TotpService,
  secret : Bytes,
  code : String,
) -> Bool raise @core.AuthError {
  let now = self.clock.now_unix()
  @core.TotpPrimitive::verify(self.primitive, secret, code, now, self.config.window)
}

///|
/// 校验口令（指定时间戳）：便于确定性测试与「补偿历史漂移」的调用方。
pub fn TotpService::verify_at(
  self : TotpService,
  secret : Bytes,
  code : String,
  at_unix : Int64,
) -> Bool raise @core.AuthError {
  @core.TotpPrimitive::verify(
    self.primitive,
    secret,
    code,
    at_unix,
    self.config.window,
  )
}

// ════════ 恢复码 ════════

///|
/// 生成 10 个恢复码（明文 + 哈希）。
pub fn TotpService::recovery_codes(
  self : TotpService,
) -> TotpRecoveryCodes raise @core.AuthError {
  self.recovery_codes_with(10)
}

///|
/// 生成 `count` 个恢复码（明文 + 哈希）。
pub fn TotpService::recovery_codes_with(
  self : TotpService,
  count : Int,
) -> TotpRecoveryCodes raise @core.AuthError {
  let plaintext = @core.TotpPrimitive::generate_recovery_codes(
    self.primitive,
    count,
  )
  let hashes = @core.TotpPrimitive::hash_recovery_codes(self.primitive, plaintext)
  { plaintext, hashes }
}
