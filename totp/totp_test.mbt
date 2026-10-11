//! moonauth / totp —— 黑盒测试：RFC 6238 向量 / 确定性随机 / 门面 / 契约。
//!
//! 🔴 本文件是**黑盒测试**（`*_test.mbt`）：被测包以 `@totp.` 限定引用。
//! 用例一律写成 `async test`——`TotpPrimitive` 为同步 seam，但契约 / 门面测试与
//! 其余包保持一致的 async 形态（`moonbitlang/async` 已在 `moon.pkg` 的 test 段导入）。
//!
//! 离线、确定性：随机源经 `FixedRandomSource` 注入，时间经 `@contract.FixedClock` 注入。

// ════════ 测试辅助 ════════

///|
/// 十六进制字符串 → 字节。
fn hex_bytes(s : String) -> Bytes {
  let src = @utf8.encode(s)
  let out : Array[Byte] = []
  let n = src.length()
  let mut i = 0
  while i + 1 < n {
    let hi = hex_nibble(src[i].to_int())
    let lo = hex_nibble(src[i + 1].to_int())
    out.push(((hi << 4) | lo).to_byte())
    i = i + 2
  }
  Bytes::from_array(out)
}

///|
/// 单个十六进制字符 → 数值（非法记为 0，仅在已知合法输入上使用）。
fn hex_nibble(v : Int) -> Int {
  if v >= 48 && v <= 57 {
    v - 48
  } else if v >= 97 && v <= 102 {
    v - 87
  } else if v >= 65 && v <= 70 {
    v - 55
  } else {
    0
  }
}

///|
/// 返回固定字节序列的 `RandomSource`（确定性重放；按需循环填充到 `n` 字节）。
struct FixedRandomSource {
  data : Bytes
}

///|
/// 实现 seam。
impl @core.RandomSource for FixedRandomSource with fn bytes(self, n) {
  let out : Array[Byte] = []
  let len = self.data.length()
  if len == 0 {
    return Bytes::from_array(out)
  }
  let mut i = 0
  while i < n {
    out.push(self.data[i % len])
    i = i + 1
  }
  Bytes::from_array(out)
}

///|
/// 以指定算法 / 位数 / 步长构造默认原语。
fn primitive_for(algorithm : String, digits : Int, period : Int) -> @totp.StandardTotpPrimitive {
  @totp.StandardTotpPrimitive::new().with_config(
    @totp.TotpConfig::new("Acme", "alice@example.com")
    .with_digits(digits)
    .with_period(period)
    .with_algorithm(algorithm),
  )
}

///|
/// 断言各向量在本原语上通过、且错码被拒。
///
/// 注：本函数声明 `raise @core.AuthError`，而 `assert_true` / `assert_false` 的错误类型是
/// 开放的 `Error`，故此处改用 `abort`（`Never`，不引入错误）做断言，以保持精确的错误契约。
fn check_vectors(
  primitive : &@core.TotpPrimitive,
  seed : Bytes,
  vectors : Array[(Int64, String)],
) -> Unit raise @core.AuthError {
  for vector in vectors {
    let (at, code) = vector
    if !primitive.verify(seed, code, at, 0) {
      abort("expected the RFC code " + code + " to verify at " + at.to_string())
    }
    if primitive.verify(seed, "00000000", at, 0) {
      abort("accepted an unrelated code at " + at.to_string())
    }
  }
}

// ════════ RFC 6238 附录 B 向量 ════════

///|
/// SHA-1 / 8 位 / 30 秒：RFC 6238 附录 B 的 6 条官方向量。
async test "totp: RFC 6238 SHA-1 reference vectors" {
  let primitive : &@core.TotpPrimitive = primitive_for("SHA1", 8, 30)
  check_vectors(primitive, b"12345678901234567890", [
    (59L, "94287082"),
    (1111111109L, "07081804"),
    (1111111111L, "14050471"),
    (1234567890L, "89005924"),
    (2000000000L, "69279037"),
    (20000000000L, "65353130"),
  ])
}

///|
/// SHA-256 / 8 位 / 30 秒：RFC 6238 附录 B 向量。
async test "totp: RFC 6238 SHA-256 reference vectors" {
  let primitive : &@core.TotpPrimitive = primitive_for("SHA256", 8, 30)
  check_vectors(primitive, b"12345678901234567890123456789012", [
    (59L, "46119246"),
    (1111111109L, "68084774"),
    (1111111111L, "67062674"),
    (1234567890L, "91819424"),
    (2000000000L, "90698825"),
    (20000000000L, "77737706"),
  ])
}

///|
/// SHA-512 / 8 位 / 30 秒：RFC 6238 附录 B 向量。
async test "totp: RFC 6238 SHA-512 reference vectors" {
  let primitive : &@core.TotpPrimitive = primitive_for("SHA512", 8, 30)
  check_vectors(
    primitive,
    b"1234567890123456789012345678901234567890123456789012345678901234",
    [
      (59L, "90693936"),
      (1111111109L, "25091201"),
      (1111111111L, "99943326"),
      (1234567890L, "93441116"),
      (2000000000L, "38618901"),
      (20000000000L, "47863826"),
    ],
  )
}

// ════════ 漂移窗口 ════════

///|
/// 漂移窗口：`window = 1` 接受相邻一步的口令，拒绝两步之外。
async test "totp: verify honours the drift window" {
  let primitive = primitive_for("SHA1", 8, 30)
  let seed = b"12345678901234567890"
  // t=59 的口令在 t=89（+1 步）应通过、在 t=119（+2 步）应被拒。
  assert_true(primitive.verify(seed, "94287082", 89L, 1))
  assert_false(primitive.verify(seed, "94287082", 119L, 1))
  // window=0 时仅当前步有效。
  assert_false(primitive.verify(seed, "94287082", 89L, 0))
}

// ════════ 确定性随机 ════════

///|
/// `generate_secret` 只经注入的 `RandomSource`：相同随机源 → 相同密钥。
async test "totp: generate_secret is deterministic from the injected random source" {
  let data = hex_bytes(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  let random : &@core.RandomSource = FixedRandomSource::{ data }
  let primitive = @totp.StandardTotpPrimitive::new().with_random(random)
  let secret = primitive.generate_secret(160)
  @debug.assert_eq(secret.length(), 20)
  @debug.assert_eq(secret, Bytes::makei(20, fn(i) { data[i] }))
}

// ════════ 门面 ════════

///|
/// 门面：`enroll` 生成密钥 + `otpauth://` URI；`verify` 用注入时钟当前时间校验。
async test "totp: facade enroll + verify round-trips with a fixed clock" {
  let config = @totp.TotpConfig::new("Acme", "alice@example.com")
    .with_digits(8)
    .with_period(30)
    .with_algorithm("SHA1")
  let primitive = @totp.StandardTotpPrimitive::new().with_config(config)
  // 时钟固定在 RFC 向量的 59 秒处。
  let clock : &@core.Clock = @contract.FixedClock::new(59L)
  let service = @totp.TotpService::new(config).with_primitive(primitive).with_clock(clock)

  let enrollment = service.enroll()
  @debug.assert_eq(enrollment.secret.length(), 20)
  assert_true(enrollment.uri.has_prefix("otpauth://totp/Acme:alice"))
  assert_true(enrollment.uri.contains("algorithm=SHA1"))

  // 用 RFC 种子 + 向量的确定性校验（时钟 = 59s）。
  let known : Bytes = b"12345678901234567890"
  assert_true(service.verify(known, "94287082"))
  assert_false(service.verify(known, "00000000"))
  assert_true(service.verify_at(known, "94287082", 59L))
}

///|
/// 门面：恢复码明文 + 哈希（哈希为 64 位十六进制、与明文一一对应）。
async test "totp: facade recovery codes pair plaintext with hashes" {
  let config = @totp.TotpConfig::new("Acme", "alice@example.com")
  let primitive = @totp.StandardTotpPrimitive::new().with_config(config)
  let service = @totp.TotpService::new(config).with_primitive(primitive)
  let recovery = service.recovery_codes_with(5)
  @debug.assert_eq(recovery.plaintext.length(), 5)
  @debug.assert_eq(recovery.hashes.length(), 5)
  for hash in recovery.hashes {
    @debug.assert_eq(hash.length(), 64)
  }
  // 明文格式 `XXXX-XXXX`。
  for code in recovery.plaintext {
    @debug.assert_eq(code.length(), 9)
    @debug.assert_eq(code.get_char(4), Some('-'))
  }
  // 哈希必与明文一一对应（对同一明文再哈希，结果一致）。
  let recomputed = primitive.hash_recovery_codes(recovery.plaintext)
  for i in 0..<5 {
    @debug.assert_eq(recomputed[i], recovery.hashes[i])
  }
}

///|
/// 非法算法名 → `UnsupportedAlg`；非正 window → `InvalidInput`。
async test "totp: invalid configuration surfaces as AuthError" {
  let primitive = primitive_for("MD5", 6, 30)
  let code_bad_alg = try {
    let _ = primitive.verify(b"12345678901234567890", "000000", 59L, 0)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code_bad_alg, "unsupported_alg")

  let good = primitive_for("SHA1", 6, 30)
  let code_bad_window = try {
    let _ = good.verify(b"12345678901234567890", "000000", 59L, -1)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code_bad_window, "invalid_input")
}

// ════════ 契约：对默认实现跑参数化断言集 ════════

///|
/// `TotpPrimitive` 契约对**库自实现**（`StandardTotpPrimitive`）100% 通过。
///
/// 🔴 契约的 RFC 向量针对 SHA-1 / 8 位 / 30 秒，故 `make` 必须返回该配置的实现
/// （见 `contract/totp_contract.mbt` 文件头的「调用方契约」）。
async test "totp contract: StandardTotpPrimitive passes every case" {
  let cases = @contract.run_totp(fn() {
    let subject : &@core.TotpPrimitive = primitive_for("SHA1", 8, 30)
    subject
  })
  @contract.assert_all_pass(cases)
}

// ════════ 公开 Base32 助手（LIB-06 ①） ════════

///|
/// 🔴 LIB-06 ①：公开 Base32 助手——**无填充** RFC 4648（Google Authenticator 密钥形态），
/// 且与 `otpauth_uri` 内的 `secret` 编码**逐字符一致**。
async test "totp: base32_encode matches RFC 4648 vectors (unpadded)" {
  // RFC 4648 §10 官方向量（此处为去填充形态）
  @debug.assert_eq(@totp.base32_encode(b""), "")
  @debug.assert_eq(@totp.base32_encode(b"f"), "MY")
  @debug.assert_eq(@totp.base32_encode(b"fo"), "MZXQ")
  @debug.assert_eq(@totp.base32_encode(b"foo"), "MZXW6")
  @debug.assert_eq(@totp.base32_encode(b"foob"), "MZXW6YQ")
  @debug.assert_eq(@totp.base32_encode(b"fooba"), "MZXW6YTB")
  @debug.assert_eq(@totp.base32_encode(b"foobar"), "MZXW6YTBOI")
  // RFC 6238 附录 B 的 ASCII 密钥 → 与 otpauth_uri 中的 secret 逐字符一致
  let secret = b"12345678901234567890"
  @debug.assert_eq(
    @totp.base32_encode(secret),
    "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
  )
  let primitive = @totp.StandardTotpPrimitive::new()
  let opts : @core.TotpOptions = { digits: 6, period: 30, algorithm: "SHA1" }
  let uri = primitive.otpauth_uri(secret, "bob", "GitHub", opts)
  assert_true(uri.contains("secret=" + @totp.base32_encode(secret)))
}
