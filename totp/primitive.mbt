//! moonauth / totp —— 默认 `TotpPrimitive` 实现：`StandardTotpPrimitive`。
//!
//! 语义 = RFC 6238（TOTP）/ RFC 4226（HOTP 基元）。
//!
//! ## 为什么自写而非直接套用 `@otp`
//! `1726914517-spec/moon_otp` 提供 `totp` / `hotp` / `sha256` 等纯函数，本实现**复用**它们做
//! MAC 计算；但它的三个入口 `generate_secret` / `generate_recovery_codes` 与 `totp_verify`
//! 直接读 `@env.rand` / `@env.now`，**绕过了 `RandomSource` / `Clock` seam**。因此：
//! - `generate_secret` / `generate_recovery_codes`：本实现自行经注入的 `RandomSource` 取随机，
//!   复用 `@otp.base32_encode` / `@otp.sha256` 做纯编码与哈希（保持确定性可重放）；
//! - `verify`：本实现自行按 `window` 各偏移计算 `@otp.totp(alg, secret, at_unix, ...)` 再比对，
//!   **不**调用 `@otp.totp_verify`（后者把时间固定在 `@env.now()`，无法注入 `at_unix`）。
//!
//! ## 恒定时间比较
//! 提交的口令与期望口令之间用**逐字节异或累加**（`constant_time_eq`）而非 `==`：
//! `==` 会在首个不同字符处提前返回，逐位泄露「前 k 位正确」，攻击者可用时序侧信道
//! 逐位试探出有效口令。异或累加对每一位都执行相同的操作、无提前返回，比较耗时与
//! 「第几位不同」无关（长度不同仍会提前返回，但 TOTP 口令长度固定，不构成泄漏）。
//!
//! ## 第三方类型约束
//! `@otp.HashAlgorithm` / `@otp.OtpError` / `@otp.OtpAuth` **只出现在私有函数体**，
//! 公开签名（`StandardTotpPrimitive` 的方法）一律只用 `@core` 与标准类型，`.mbti` 干净。

///|
/// 默认 `TotpPrimitive` 实现。
///
/// 只持有两个 seam / 配置：`random`（生成密钥与恢复码，**唯一**随机来源）与 `config`
/// （`digits` / `period` / `algorithm` / `window`，供 `verify` / `otpauth_uri` 使用）。
pub struct StandardTotpPrimitive {
  random : &@core.RandomSource
  config : TotpConfig
  /// 恢复码哈希的 **pepper**（服务器侧秘密，见 `hash_recovery_codes`）；`None` = 未设。
  pepper : Bytes?
}

///|
/// 以默认配置构造：`RandomSource` 取 `@rand.GetrandomSource`，参数取
/// `TotpConfig::new("moonauth", "user")`（SHA-1 / 6 位 / 30 秒）。
pub fn StandardTotpPrimitive::new() -> StandardTotpPrimitive {
  let random : &@core.RandomSource = @rand.GetrandomSource::new()
  { random, config: TotpConfig::new("moonauth", "user"), pepper: None }
}

///|
/// 覆盖随机源，返回**新**实例（不改原实例）。
pub fn StandardTotpPrimitive::with_random(
  self : StandardTotpPrimitive,
  random : &@core.RandomSource,
) -> StandardTotpPrimitive {
  { random, config: self.config, pepper: self.pepper }
}

///|
/// 设置恢复码哈希的 **pepper**（服务器侧秘密，返回**新**实例）。
///
/// 🔴 强烈建议设置：见 `hash_recovery_codes`——pepper 把「数据库泄露后恢复码可被
/// GPU 一次穷举批量撞出」变成「没有 pepper 就算不动」。pepper 需**稳定且保密**
///（换 pepper 会使已持久化的哈希全部失效）。确定性保持不变：同 pepper + 同码
/// → 同哈希，「按哈希查找」的用法不受影响。
pub fn StandardTotpPrimitive::with_recovery_hash_pepper(
  self : StandardTotpPrimitive,
  pepper : Bytes,
) -> StandardTotpPrimitive {
  { random: self.random, config: self.config, pepper: Some(pepper) }
}

///|
/// 覆盖配置，返回**新**实例（不改原实例）。
pub fn StandardTotpPrimitive::with_config(
  self : StandardTotpPrimitive,
  config : TotpConfig,
) -> StandardTotpPrimitive {
  { random: self.random, config, pepper: self.pepper }
}

///|
/// 只读访问当前配置。
pub fn StandardTotpPrimitive::config(
  self : StandardTotpPrimitive,
) -> TotpConfig {
  self.config
}

///|
/// 只读访问当前恢复码哈希 pepper。
pub fn StandardTotpPrimitive::recovery_hash_pepper(
  self : StandardTotpPrimitive,
) -> Bytes? {
  self.pepper
}

// ════════ seam 实现 ════════

///|
/// 生成 `bits` 位熵的密钥（`ceil(bits / 8)` 字节，经注入的 `RandomSource`）。
///
/// 随机源返回的字节数不足时抛 `InvalidInput`——绝不静默截断或补零（那会削弱熵）。
pub impl @core.TotpPrimitive for StandardTotpPrimitive with fn generate_secret(
  self,
  bits,
) {
  if bits <= 0 {
    raise @core.InvalidInput("moonauth: TOTP secret entropy bits must be positive")
  }
  let nbytes = (bits + 7) / 8
  let secret = @core.RandomSource::bytes(self.random, nbytes)
  if secret.length() != nbytes {
    raise @core.InvalidInput("moonauth: random source returned a short TOTP secret")
  }
  secret
}

///|
/// 生成 `otpauth://totp/` URI（供用户扫码）。
///
/// `opts.algorithm` 非法（非 `SHA1`/`SHA256`/`SHA512`）→ `UnsupportedAlg`；
/// `opts.digits` / `opts.period` 越界 → `@otp` 的对应错误经边界映射为 `InvalidInput`。
pub impl @core.TotpPrimitive for StandardTotpPrimitive with fn otpauth_uri(
  self,
  secret,
  account,
  issuer,
  opts,
) {
  let _ = self
  let algorithm = match @otp.parse_algorithm(opts.algorithm) {
    Some(a) => a
    None => raise @core.UnsupportedAlg(opts.algorithm)
  }
  let otp : @otp.OtpAuth = {
    issuer,
    account,
    secret,
    algorithm,
    digits: opts.digits,
    period: opts.period,
    otp_type: @otp.OtpKind::Totp,
    counter: 0UL,
  }
  @otp.otpauth_uri(otp) catch {
    e => raise map_otp_error(e)
  }
}

///|
/// 校验一次性口令：在 `at_unix` 的**当前与至多前 `window` 个时间步**内逐一比对
/// （恒定时间）。
///
/// 🔴 **仅回看，不接受未来步**（黑客审计第 2 轮确认，JEV 0.993）：此前为 `±window`
/// 对称——接受未来步会把在线爆破窗口从 2 步扩大到 3 步、并接受「预先生成的未来码」，
/// 与实现契约 §6.6.4（「校验当前时间步和至多一个前一时间步」）及 OWASP 口径冲突。
///
/// `window < 0` → `InvalidInput`。窗口外/为空的时间戳（`at_unix - k*period < 0`）直接跳过。
pub impl @core.TotpPrimitive for StandardTotpPrimitive with fn verify(
  self,
  secret,
  code,
  at_unix,
  window,
) {
  if window < 0 {
    raise @core.InvalidInput("moonauth: TOTP verification window must be non-negative")
  }
  let algorithm = self.hash_algorithm()
  let period = self.config.period
  let digits = self.config.digits
  let mut matched = false
  let mut offset = 0
  while offset <= window {
    // 🔴 仅回看：`totp_matches` 的语义是 `at = base + delta*period`——**正 delta 是
    // 未来时间**。故回看必须用负 delta（当前步 + 前 window 步）。
    let delta = 0L - offset.to_int64()
    if totp_matches(algorithm, secret, code, at_unix, delta, period, digits) {
      matched = true
    }
    offset = offset + 1
  }
  matched
}

///|
/// 生成 `count` 个互不相同的恢复码（明文，由调用方展示一次）。
///
/// 每码形如 `XXXX-XXXX`（`groups = 2` / `group_size = 4`），字母表与 `@otp` 一致
/// （剔除易混的 `I` / `L` / `O` / `0` / `1`，共 30 个符号）。
pub impl @core.TotpPrimitive for StandardTotpPrimitive with fn generate_recovery_codes(
  self,
  count,
) {
  if count < 1 {
    raise @core.InvalidInput("moonauth: recovery code count must be positive")
  }
  let codes : Array[String] = []
  let mut made = 0
  while made < count {
    let code = self.random_recovery_code()
    if !codes.contains(code) {
      codes.push(code)
      made = made + 1
    }
  }
  codes
}

///|
/// 对恢复码做不可逆哈希，返回 64 个小写十六进制字符。
///
/// - 已设 pepper（`with_recovery_hash_pepper`）：`hex(HMAC-SHA256(pepper, code))`——
///   🔴 **推荐**。恢复码全空间约 `30^8 ≈ 6.6e11`，无盐无钥的 `sha256(code)` 在库泄露后
///   可被一块 GPU 一次穷举、**批量**撞出所有用户；HMAC pepper 迫使攻击者逐目标持钥计算。
///   确定性保持：同 pepper + 同码 → 同哈希，「按哈希查找」的用法不受影响。
/// - 未设 pepper（默认）：`hex(sha256(code))`——仅为兼容保留；**生产必须设 pepper**。
///
/// 只应持久化哈希结果；明文**绝不**落库，pepper**绝不**与哈希同库存放。
pub impl @core.TotpPrimitive for StandardTotpPrimitive with fn hash_recovery_codes(
  self,
  codes,
) {
  let out : Array[String] = []
  for code in codes {
    let digest = match self.pepper {
      Some(pepper) => @otp.hmac(@otp.HashAlgorithm::Sha256, pepper[:], @utf8.encode(code)[:])
      None => @otp.sha256(@utf8.encode(code)[:])
    }
    out.push(hex_encode(digest))
  }
  out
}

///|
/// 显式把 seam 方法提升为常规方法，避免隐式提升的弃用告警。
pub extend StandardTotpPrimitive with @core.TotpPrimitive::{
  generate_secret,
  otpauth_uri,
  verify,
  generate_recovery_codes,
  hash_recovery_codes,
}

// ════════ 公开编码助手（LIB-06 ①） ════════

///|
/// 把原始密钥字节编码为 **RFC 4648 Base32（大写、无填充）**——面向用户的密钥展示形态
/// （Google Authenticator 等标准 App 在 `otpauth://` 中使用的即此形态）。
///
/// 🔴 与 `otpauth_uri` 内部使用的编码**逐字符一致**（同走 `@otp.base32_encode_unpadded`），
/// 故「展示给用户的密钥」与「二维码里的密钥」必然相同（这是 LIB-06 ① 的验收点）。
///
/// 入参 / 返回均为标准类型，第三方类型不逃逸（SDK-03）。
pub fn base32_encode(secret : Bytes) -> String {
  @otp.base32_encode_unpadded(secret[:])
}

// ════════ 私有助手 ════════

///|
/// 配置里的算法名 → `@otp.HashAlgorithm`；未知算法名 → `UnsupportedAlg`。
fn StandardTotpPrimitive::hash_algorithm(
  self : StandardTotpPrimitive,
) -> @otp.HashAlgorithm raise @core.AuthError {
  match @otp.parse_algorithm(self.config.algorithm) {
    Some(a) => a
    None => raise @core.UnsupportedAlg(self.config.algorithm)
  }
}

///|
/// 计算 `at_unix + delta * period` 处的口令并与 `code` 恒定时间比对。
fn totp_matches(
  algorithm : @otp.HashAlgorithm,
  secret : Bytes,
  code : String,
  base : Int64,
  delta : Int64,
  period : Int,
  digits : Int,
) -> Bool raise @core.AuthError {
  let at = base + delta * period.to_int64()
  if at < 0L {
    return false
  }
  // `at >= 0` 已由上方保证，故 `reinterpret_as_uint64` 与「数值转换」等价（无符号歧义）。
  let expected = @otp.totp(
    algorithm,
    secret,
    at.reinterpret_as_uint64(),
    digits=digits,
    period=period,
  ) catch {
    e => raise map_otp_error(e)
  }
  constant_time_eq(expected, code)
}

///|
/// 生成单个恢复码（`XXXX-XXXX`）。
fn StandardTotpPrimitive::random_recovery_code(
  self : StandardTotpPrimitive,
) -> String raise @core.AuthError {
  let groups = 2
  let group_size = 4
  let total = groups * group_size
  let random = @core.RandomSource::bytes(self.random, total)
  if random.length() != total {
    raise @core.InvalidInput(
      "moonauth: random source returned too few bytes for a recovery code",
    )
  }
  let alphabet = recovery_alphabet()
  let width = alphabet.length()
  let buf = Buffer()
  for g in 0..<groups {
    if g > 0 {
      buf.write_byte(b'-')
    }
    for i in 0..<group_size {
      let idx = random[g * group_size + i].to_int() % width
      buf.write_byte(alphabet[idx])
    }
  }
  @utf8.decode_lossy(buf.to_bytes())
}

///|
/// 恢复码字母表（30 个符号，剔除易混的 `I` / `L` / `O` / `0` / `1`）。
fn recovery_alphabet() -> Bytes {
  @utf8.encode("ABCDEFGHJKMNPQRSTVWXYZ23456789")
}

///|
/// 恒定时间字符串比较（逐字节异或累加，无提前返回）。
///
/// 长度不同立即返回 `false`（TOTP 口令长度固定，长度本身不是秘密）。
fn constant_time_eq(a : String, b : String) -> Bool {
  let x = @utf8.encode(a)
  let y = @utf8.encode(b)
  let n = x.length()
  if n != y.length() {
    return false
  }
  let mut diff = 0
  for i in 0..<n {
    diff = diff | (x[i].to_int() ^ y[i].to_int())
  }
  diff == 0
}

///|
/// 字节 → 小写十六进制。
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
/// `@otp.OtpError` → `AuthError`（边界转换；`@otp` 类型绝不逃逸）。
fn map_otp_error(e : @otp.OtpError) -> @core.AuthError {
  match e {
    InvalidDigits(d) => @core.InvalidInput("moonauth: totp invalid digits \{d}")
    InvalidPeriod(p) => @core.InvalidInput("moonauth: totp invalid period \{p}")
    EmptySecret => @core.InvalidInput("moonauth: totp empty secret")
    RandomUnavailable => @core.RandomUnavailable
    InvalidSecretLength(n) =>
      @core.InvalidInput("moonauth: totp invalid secret length \{n}")
    InvalidUri(msg) => @core.ParseError("moonauth: totp invalid otpauth URI: " + msg)
  }
}
