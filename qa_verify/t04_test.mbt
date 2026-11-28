//! moonauth / qa_verify —— T04 对抗性独立验证（passkey + totp）。
//!
//! 覆盖 team-lead 的 §2.1~§2.7：
//! - §2.1 🔴 `RandomSource` seam 全程性（固定随机源 → 确定性；证伪「上游被调用」）；
//! - §2.2 🔴 存储故障 ≠ challenge 不存在（必然失败的 store → network，而非 not_found）；
//! - §2.3 TOTP RFC 6238 官方向量独立复算 + window 漂移 + 恢复码不含明文；
//! - §2.4 恒定时间比较（代码审计，无提前返回）；
//! - §2.5 WebAuthn 逐字段篡改 + signCount 0/0 例外（对照规范）；
//! - §2.6 `-unused_async` 未掩盖 bug（代码审计）；
//! - §2.7 纯度 / 封闭。
//!
//! 🔴 全部离线、确定性：随机经 `FixedRandomSource`，时间经 `@contract.FixedClock`。
//! WebAuthn 向量由**本文件自带 P-256 私钥**现场签名（独立于 `passkey_test.mbt` 的密钥）。

// ════════════════════ 通用助手 ════════════════════

///| 十六进制字符串 → 字节。
fn t4_hex(s : String) -> Bytes {
  let src = @utf8.encode(s)
  let out : Array[Byte] = []
  let n = src.length()
  let mut i = 0
  while i + 1 < n {
    out.push(((t4_nib(src[i]) << 4) | t4_nib(src[i + 1])).to_byte())
    i = i + 2
  }
  Bytes::from_array(out)
}

///| 单十六进制字符 → 数值。
fn t4_nib(c : Byte) -> Int {
  let v = c.to_int()
  if v >= 48 && v <= 57 {
    v - 48
  } else if v >= 97 && v <= 102 {
    v - 97 + 10
  } else if v >= 65 && v <= 70 {
    v - 65 + 10
  } else {
    0
  }
}

///| ASCII 字符串 → 字节。
fn t4_ascii(s : String) -> Bytes {
  Bytes::makei(s.length(), fn(i) {
    (s.get_char(i).unwrap().to_int() & 0xFF).to_byte()
  })
}

///| 字节拼接。
fn t4_cat(a : Bytes, b : Bytes) -> Bytes {
  let out : Array[Byte] = []
  for x in a {
    out.push(x)
  }
  for x in b {
    out.push(x)
  }
  Bytes::from_array(out)
}

///| 大端写入 32 位无符号。
fn t4_u32be(out : Array[Byte], n : Int) -> Unit {
  out.push(((n >> 24) & 0xFF).to_byte())
  out.push(((n >> 16) & 0xFF).to_byte())
  out.push(((n >> 8) & 0xFF).to_byte())
  out.push((n & 0xFF).to_byte())
}

///| 固定字节序列的 `RandomSource`（确定性重放，按需循环填充）。
struct T4Random {
  data : Bytes
}

///| 实现 seam。
impl @core.RandomSource for T4Random with fn bytes(self, n) {
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
/// **确定性、有状态**的 `RandomSource`：每次调用返回**不同**但可重放的字节流。
/// 用于 `generate_recovery_codes`（其内部有「去重」循环，若每次返回相同字节会死循环）。
/// 相同初始 `counter` 的两个实例产生相同序列 → 可测「同源 → 同结果」。
struct T4Seq {
  mut counter : Int
}

///| 实现 seam（确定性序列，无隐藏熵）。
impl @core.RandomSource for T4Seq with fn bytes(self, n) {
  let out : Array[Byte] = []
  let mut i = 0
  while i < n {
    out.push(((self.counter * 131 + i * 17 + 41) & 0xFF).to_byte())
    i = i + 1
  }
  self.counter = self.counter + 1
  Bytes::from_array(out)
}

// ════════════════════ §2.1 🔴 RandomSource seam 全程性 ════════════════════

///|
/// 🔴 **确定性证明（TOTP）**：同一固定 `RandomSource` → 两次 `generate_secret` /
/// `generate_recovery_codes` 结果**逐字节相同**。若不同 → 存在绕过 seam 的隐藏熵源。
async test "T04 §2.1 totp generate_secret/recovery are deterministic from the injected source" {
  let data = t4_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
  let r1 : &@core.RandomSource = T4Random::{ data }
  let p1 = @totp.StandardTotpPrimitive::new().with_random(r1)
  let s1 = p1.generate_secret(160)
  let s2 = p1.generate_secret(160)
  @debug.assert_eq(s1, s2)
  @debug.assert_eq(s1, Bytes::makei(20, fn(i) { data[i] }))
  // 恢复码：用**同初值**的有状态确定性源的两个独立实例 → 相同结果（无隐藏熵）。
  let ra : &@core.RandomSource = T4Seq::{ counter: 0 }
  let pa = @totp.StandardTotpPrimitive::new().with_random(ra)
  let codes_a = pa.generate_recovery_codes(5)
  let rb : &@core.RandomSource = T4Seq::{ counter: 0 }
  let pb = @totp.StandardTotpPrimitive::new().with_random(rb)
  let codes_b = pb.generate_recovery_codes(5)
  @debug.assert_eq(codes_a, codes_b)
  // 另一随机源 → 不同密钥（证明确实消费了 seam，而非返回常量）。
  let r2 : &@core.RandomSource = T4Random::{ data: t4_hex("ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100") }
  let p2 = @totp.StandardTotpPrimitive::new().with_random(r2)
  assert_true(p2.generate_secret(160) != s1)
}

///|
/// 🔴 **确定性证明（passkey）**：同一固定随机源 → 两次 `begin_registration`
/// 的 challenge 与 key **完全相同**（若不同 → 隐患）。
async test "T04 §2.1 passkey challenge is deterministic from the injected source" {
  let data = t4_hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf")
  let random : &@core.RandomSource = T4Random::{ data }
  let clock : &@core.Clock = @contract.FixedClock::new(1000L)
  let store : &@core.ChallengeStore = @store_memory.MemoryChallengeStore::new(clock)
  let svc = @passkey.PasskeyService::new(
    @passkey.PasskeyConfig::new("example.com", "T", "https://example.com"),
  ).with_random(random).with_clock(clock).with_store(store)
  let a = svc.begin_registration()
  let b = svc.begin_registration()
  @debug.assert_eq(a.challenge, b.challenge)
  @debug.assert_eq(a.key, b.key)
}

// ════════════════════ §2.2 🔴 存储故障 ≠ challenge 不存在 ════════════════════

///| T04 的通过性 WebAuthn 夹具所需辅助（复用于 §2.2 与 §2.5）。见文件下部。
fn t4_passkey_config() -> @passkey.PasskeyConfig {
  @passkey.PasskeyConfig::new("example.com", "T", "https://example.com")
}

///|
/// 🔴 **存储故障**：三个方法均 `raise Network` 的 store → `finish_*_stored` 必须拿到
/// 可捕获的 `AuthError`（`network`），**且可区分于** `challenge_not_found`。
/// 复用 qa_verify 自带的 `FailingStore`（T01 资产）。
async test "T04 §2.2 failing store yields network, distinct from challenge_not_found" {
  let failing : &@core.ChallengeStore = @qa_verify.FailingStore::new()
  let svc = @passkey.PasskeyService::new(t4_passkey_config()).with_store(failing)

  let reg_code = try {
    let _ = svc.finish_registration_stored(
      "pk:reg:x",
      t4_registration_input("dGVzdC1jaGFsbGVuZ2UtMDAx"),
    )
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  assert_true(reg_code != "challenge_not_found")
  @debug.assert_eq(reg_code, "network")

  let auth_code = try {
    let _ = svc.finish_authentication_stored(
      "pk:auth:x",
      t4_assertion_input("dGVzdC1jaGFsbGVuZ2UtMDAx", "example.com", 5, 0),
    )
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(auth_code, "network")
}

///|
/// **对照**：空 store（真正「不存在」）→ `challenge_not_found`（与故障可区分）。
async test "T04 §2.2 unknown key is challenge_not_found" {
  let svc = @passkey.PasskeyService::new(t4_passkey_config())
  let code = try {
    let _ = svc.finish_registration_stored(
      "pk:reg:absent",
      t4_registration_input("dGVzdC1jaGFsbGVuZ2UtMDAx"),
    )
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "challenge_not_found")
}

///|
/// **对照**：过期条目 → `challenge_not_found`。
async test "T04 §2.2 expired entry is challenge_not_found" {
  let clock_raw = @contract.FixedClock::new(1000L)
  let clock : &@core.Clock = clock_raw
  let store : &@core.ChallengeStore = @store_memory.MemoryChallengeStore::new(clock)
  let svc = @passkey.PasskeyService::new(t4_passkey_config())
    .with_clock(clock)
    .with_store(store)
  let ch = svc.begin_authentication()
  clock_raw.advance(301L)
  let code = try {
    let _ = svc.finish_authentication_stored(
      ch.key,
      t4_assertion_input(ch.challenge, "example.com", 5, 0),
    )
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "challenge_not_found")
}

// ════════════════════ §2.3 TOTP RFC 6238 官方向量（独立复算） ════════════════════

///| 以 SHA1/8/30 构造原语。
fn t4_totp_sha1_8() -> &@core.TotpPrimitive {
  @totp.StandardTotpPrimitive::new().with_config(
    @totp.TotpConfig::new("Acme", "alice").with_digits(8).with_period(30).with_algorithm("SHA1"),
  )
}

///|
/// **RFC 6238 附录 B SHA-1 向量独立复算**（不引用工程师断言）。
async test "T04 §2.3 RFC 6238 SHA-1 reference vectors (independent)" {
  let p = t4_totp_sha1_8()
  let seed : Bytes = b"12345678901234567890"
  let vectors : Array[(Int64, String)] = [
    (59L, "94287082"),
    (1111111109L, "07081804"),
    (1111111111L, "14050471"),
    (1234567890L, "89005924"),
    (2000000000L, "69279037"),
    (20000000000L, "65353130"),
  ]
  for v in vectors {
    let (at, code) = v
    assert_true(p.verify(seed, code, at, 0))
    assert_false(p.verify(seed, "00000000", at, 0))
  }
}

///|
/// `generate_secret` 熵：160 bit → 20 字节（≥128 bit）。
async test "T04 §2.3 generate_secret entropy is at least 128 bits" {
  let random : &@core.RandomSource = T4Random::{ data: t4_hex("aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd") }
  let p = @totp.StandardTotpPrimitive::new().with_random(random)
  @debug.assert_eq(p.generate_secret(128).length(), 16)
  @debug.assert_eq(p.generate_secret(160).length(), 20)
  @debug.assert_eq(p.generate_secret(256).length(), 32)
}

///|
/// `otpauth_uri` 形状符合 RFC 6238 / Key Uri 约定。
async test "T04 §2.3 otpauth_uri shape" {
  let p = t4_totp_sha1_8()
  let opts : @core.TotpOptions = { digits: 8, period: 30, algorithm: "SHA1" }
  let uri = p.otpauth_uri(b"12345678901234567890", "alice@example.com", "Acme", opts)
  assert_true(uri.has_prefix("otpauth://totp/"))
  assert_true(uri.contains("Acme:alice"))
  assert_true(uri.contains("secret="))
  assert_true(uri.contains("issuer=Acme"))
  assert_true(uri.contains("algorithm=SHA1"))
  assert_true(uri.contains("digits=8"))
  assert_true(uri.contains("period=30"))
}

///|
/// **window 漂移边界（仅回看）**：window=1 时
/// 当前步 / 前一步（at-30）通过；未来步（at+30）与 ±2 一律拒绝。
async test "T04 §2.3 window drift: lookback-only (current/previous pass, future and ±2 rejected)" {
  let p = t4_totp_sha1_8()
  let seed : Bytes = b"12345678901234567890"
  // t=59 的口令 "94287082"。
  assert_true(p.verify(seed, "94287082", 59L, 1)) // 当前步
  assert_true(p.verify(seed, "94287082", 89L, 1)) // 前一步（89-30=59，回看命中）
  assert_false(p.verify(seed, "94287082", 29L, 1)) // 未来步（29+30=59）——仅回看后拒绝
  assert_false(p.verify(seed, "94287082", 119L, 1)) // +2 步
  // 🔴 窗口按「时间步」而非「绝对秒」：lookback 只检查 at-0/−30 步，t=0 时
  // 回看命中 t=-30（跳过）→ 不再命中 t=59 的码（旧 ± 实现会经 +30 命中）。
  assert_false(p.verify(seed, "94287082", 0L, 1))
  assert_true(p.verify(seed, "94287082", 59L, 0)) // window=0 仅当前步
  assert_false(p.verify(seed, "94287082", 89L, 0))
}

///|
/// 🔴 **恢复码哈希不含明文**：`hash_recovery_codes` 输出里找不到任何明文片段，
/// 且哈希为 64 位小写十六进制、确定性、与明文一一对应。
async test "T04 §2.3 recovery hashes never contain the plaintext" {
  let random : &@core.RandomSource = T4Seq::{ counter: 7 }
  let p = @totp.StandardTotpPrimitive::new().with_random(random)
  let codes = p.generate_recovery_codes(8)
  let hashes = p.hash_recovery_codes(codes)
  @debug.assert_eq(hashes.length(), codes.length())
  for i in 0..<codes.length() {
    let h = hashes[i]
    @debug.assert_eq(h.length(), 64)
    // 明文（含去连字符形式）绝不出现在哈希里
    assert_false(h.contains(codes[i]))
    assert_false(h.contains(codes[i].replace(old="-", new="")))
  }
  // 确定性
  @debug.assert_eq(p.hash_recovery_codes(codes), hashes)
  // 互不相同
  assert_true(hashes[0] != hashes[1])
}

// ════════════════════ §2.4 恒定时间比较（代码审计） ════════════════════
// `totp/primitive.mbt:284-296` `constant_time_eq`：`for i in 0..<n { diff = diff | (x[i]^y[i]) }`，
// 长度不同先返回 false（口令长度固定，非秘密），此后对**每一位**执行同量操作、**无提前返回**。
// —— 已读代码确认无短路；运行时耗时不具备可重复性，本环境不作时序测量（不假装测过）。

///| 行为层：恒定时间比较对「首位错」与「末位错」都判不等（无功能性早退导致误判）。
async test "T04 §2.4 verify rejects first-position and last-position wrong codes" {
  let p = t4_totp_sha1_8()
  let seed : Bytes = b"12345678901234567890"
  // "94287082" 是 t=59 的正确口令。首位改错、末位改错都必须被拒。
  let first_wrong = "0" + "4287082"
  let last_wrong = "9428708" + "0"
  assert_false(p.verify(seed, first_wrong, 59L, 0))
  assert_false(p.verify(seed, last_wrong, 59L, 0))
}

// ════════════════════ §2.5 WebAuthn 逐字段 + signCount ════════════════════

///| 本文件自带 P-256 私钥（独立于 passkey_test.mbt）。
fn t4_p256_key() -> @p256.PrivateKey {
  @p256.PrivateKey::from_bytes(
    t4_hex("f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f00"),
  ) catch {
    _ => abort("qa_verify: invalid P-256 scalar for T04")
  }
}

///| 由自带私钥导出 ES256 COSE 公钥（CBOR）。
fn t4_cose() -> Bytes {
  let uncompressed = t4_p256_key().public_key().to_uncompressed()
  let x = Bytes::makei(32, fn(i) { uncompressed[1 + i] })
  let y = Bytes::makei(32, fn(i) { uncompressed[33 + i] })
  @cbor.encode(
    @cbor.CborValue::Map([
      (@cbor.CborValue::Uint(1UL), @cbor.CborValue::Uint(2UL)),
      (@cbor.CborValue::Uint(3UL), @cbor.CborValue::Nint(6UL)),
      (@cbor.CborValue::Nint(0UL), @cbor.CborValue::Uint(1UL)),
      (@cbor.CborValue::Nint(1UL), @cbor.CborValue::Bytes(x)),
      (@cbor.CborValue::Nint(2UL), @cbor.CborValue::Bytes(y)),
    ]),
  )
}

///| 固定凭据 ID（32 字节）。
fn t4_cred_id() -> Bytes {
  t4_hex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
}

///| 固定 AAGUID（16 字节）。
fn t4_aaguid() -> Bytes {
  t4_hex("0102030405060708090a0b0c0d0e0f10")
}

///| authenticatorData（含 attested credential data）。
fn t4_ad_attested(rp_hash : Bytes, flags : Int, sc : Int) -> Bytes {
  let out : Array[Byte] = []
  for b in rp_hash {
    out.push(b)
  }
  out.push(flags.to_byte())
  t4_u32be(out, sc)
  for b in t4_aaguid() {
    out.push(b)
  }
  let cid = t4_cred_id()
  out.push(((cid.length() >> 8) & 0xFF).to_byte())
  out.push((cid.length() & 0xFF).to_byte())
  for b in cid {
    out.push(b)
  }
  for b in t4_cose() {
    out.push(b)
  }
  Bytes::from_array(out)
}

///| authenticatorData（无 attested credential data）。
fn t4_ad_plain(rp_hash : Bytes, flags : Int, sc : Int) -> Bytes {
  let out : Array[Byte] = []
  for b in rp_hash {
    out.push(b)
  }
  out.push(flags.to_byte())
  t4_u32be(out, sc)
  Bytes::from_array(out)
}

///| 合成 clientDataJSON。
fn t4_cdj(ceremony : String, challenge : String, origin : String, cross : Bool) -> Bytes {
  let base = "{\"type\":\"" + ceremony + "\",\"challenge\":\"" + challenge + "\",\"origin\":\"" + origin + "\""
  if cross {
    t4_ascii(base + ",\"crossOrigin\":true}")
  } else {
    t4_ascii(base + "}")
  }
}

///| 一个必然通过的注册输入（none 格式）。
fn t4_registration_input(challenge : String) -> @core.RegistrationInput {
  t4_registration_input_ex(challenge, "example.com", "https://example.com", "webauthn.create", false)
}

///| 注册输入（可变 rp/origin/type/crossOrigin）。
fn t4_registration_input_ex(
  challenge : String,
  rp_id : String,
  origin : String,
  ceremony : String,
  cross : Bool,
) -> @core.RegistrationInput {
  let auth_data = t4_ad_attested(@webauthn.rp_id_hash(rp_id), 0x45, 0)
  let empty : Array[(@cbor.CborValue, @cbor.CborValue)] = []
  let attestation = @cbor.encode(
    @cbor.CborValue::Map([
      (@cbor.CborValue::Text("fmt"), @cbor.CborValue::Text("none")),
      (@cbor.CborValue::Text("authData"), @cbor.CborValue::Bytes(auth_data)),
      (@cbor.CborValue::Text("attStmt"), @cbor.CborValue::Map(empty)),
    ]),
  )
  {
    client_data_json: t4_cdj(ceremony, challenge, origin, cross),
    attestation_object: attestation,
    expected_challenge: challenge,
    expected_origin: "https://example.com",
    rp_id,
  }
}

///| 一个必然通过的认证输入（ES256，signCount 可指定）。
fn t4_assertion_input(
  challenge : String,
  rp_id : String,
  sign_count : Int,
  stored : Int,
) -> @core.AssertionInput {
  t4_assertion_input_ex(
    challenge,
    rp_id,
    "https://example.com",
    "webauthn.get",
    false,
    sign_count,
    stored,
  )
}

///| 认证输入（可变 rp/origin/type/crossOrigin/signCount/stored）。
fn t4_assertion_input_ex(
  challenge : String,
  rp_id : String,
  origin : String,
  ceremony : String,
  cross : Bool,
  sign_count : Int,
  stored : Int,
) -> @core.AssertionInput {
  let auth_data = t4_ad_plain(@webauthn.rp_id_hash(rp_id), 0x05, sign_count)
  let cdj = t4_cdj(ceremony, challenge, origin, cross)
  let hash = @webauthn.client_data_hash(cdj)
  let signature = t4_p256_key().sign(
    t4_cat(auth_data, hash),
    format=@p256.SignatureFormat::Der,
  )
  {
    client_data_json: cdj,
    authenticator_data: auth_data,
    signature,
    credential_public_key: t4_cose(),
    expected_challenge: challenge,
    expected_origin: "https://example.com",
    rp_id,
    stored_sign_count: stored,
  }
}

let t4_challenge : String = "dGVzdC1jaGFsbGVuZ2UtMDAx"

///|
/// **§2.5 正对照**：自签有效注册 / 认证向量必须通过（否则下方负例全为空套）。
async test "T04 §2.5 self-signed valid registration + assertion pass" {
  let svc = @passkey.PasskeyService::new(t4_passkey_config())
  let reg = svc.finish_registration(t4_registration_input(t4_challenge))
  @debug.assert_eq(reg.credential_id, t4_cred_id())
  @debug.assert_eq(reg.aaguid, Some("01020304-0506-0708-090a-0b0c0d0e0f10"))
  let asn = svc.finish_authentication(
    t4_assertion_input(t4_challenge, "example.com", 5, 0),
  )
  @debug.assert_eq(asn.sign_count, 5)
}

///| 跑一次 assert 校验并返回错误码（成功 `no-error`）。
async fn t4_assert_code(
  svc : @passkey.PasskeyService,
  input : @core.AssertionInput,
) -> String {
  try {
    let _ = svc.finish_authentication(input)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
}

///| 跑一次注册校验并返回错误码。
async fn t4_reg_code(
  svc : @passkey.PasskeyService,
  input : @core.RegistrationInput,
) -> String {
  try {
    let _ = svc.finish_registration(input)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
}

///|
/// 🔴 **逐字段独立验证**（注册侧）：crossOrigin / type / origin / rpId 各自篡改 → 对应错误码。
async test "T04 §2.5 registration rejects each single tampered field" {
  let svc = @passkey.PasskeyService::new(t4_passkey_config())
  // crossOrigin=true
  @debug.assert_eq(
    t4_reg_code(svc, t4_registration_input_ex(t4_challenge, "example.com", "https://example.com", "webauthn.create", true)),
    "cross_origin_rejected",
  )
  // type 错
  @debug.assert_eq(
    t4_reg_code(svc, t4_registration_input_ex(t4_challenge, "example.com", "https://example.com", "webauthn.get", false)),
    "type_mismatch",
  )
  // origin 错
  @debug.assert_eq(
    t4_reg_code(svc, t4_registration_input_ex(t4_challenge, "example.com", "https://evil.example", "webauthn.create", false)),
    "origin_mismatch",
  )
  // challenge 错
  let bad_chal : @core.RegistrationInput = {
    client_data_json: t4_registration_input(t4_challenge).client_data_json,
    attestation_object: t4_registration_input(t4_challenge).attestation_object,
    expected_challenge: t4_challenge + "x",
    expected_origin: "https://example.com",
    rp_id: "example.com",
  }
  @debug.assert_eq(t4_reg_code(svc, bad_chal), "challenge_mismatch")
  // rpId 错（保持 authData 哈希自 example.com，仅把 input.rp_id 改成 evil.example）
  let good = t4_registration_input(t4_challenge)
  let bad_rp : @core.RegistrationInput = {
    client_data_json: good.client_data_json,
    attestation_object: good.attestation_object,
    expected_challenge: good.expected_challenge,
    expected_origin: good.expected_origin,
    rp_id: "evil.example",
  }
  @debug.assert_eq(t4_reg_code(svc, bad_rp), "rp_id_mismatch")
}

///|
/// 🔴 **逐字段独立验证**（认证侧）：签名篡改 → `signature_invalid`；type / origin / crossOrigin。
async test "T04 §2.5 assertion rejects tampered signature / type / origin / cross-origin" {
  let svc = @passkey.PasskeyService::new(t4_passkey_config())
  // 签名篡改（翻转首位）
  let good = t4_assertion_input(t4_challenge, "example.com", 5, 0)
  let tampered : @core.AssertionInput = {
    client_data_json: good.client_data_json,
    authenticator_data: good.authenticator_data,
    signature: Bytes::makei(good.signature.length(), fn(i) {
      if i == 0 {
        (good.signature[i].to_int() ^ 0xFF).to_byte()
      } else {
        good.signature[i]
      }
    }),
    credential_public_key: good.credential_public_key,
    expected_challenge: good.expected_challenge,
    expected_origin: good.expected_origin,
    rp_id: good.rp_id,
    stored_sign_count: good.stored_sign_count,
  }
  @debug.assert_eq(t4_assert_code(svc, tampered), "signature_invalid")
  // type 错
  @debug.assert_eq(
    t4_assert_code(svc, t4_assertion_input_ex(t4_challenge, "example.com", "https://example.com", "webauthn.create", false, 5, 0)),
    "type_mismatch",
  )
  // origin 错
  @debug.assert_eq(
    t4_assert_code(svc, t4_assertion_input_ex(t4_challenge, "example.com", "https://evil.example", "webauthn.get", false, 5, 0)),
    "origin_mismatch",
  )
  // crossOrigin
  @debug.assert_eq(
    t4_assert_code(svc, t4_assertion_input_ex(t4_challenge, "example.com", "https://example.com", "webauthn.get", true, 5, 0)),
    "cross_origin_rejected",
  )
  // rpId 错（authData 哈希自 example.com，仅 input.rp_id 改 evil.example）
  let good2 = t4_assertion_input(t4_challenge, "example.com", 5, 0)
  let bad_rp2 : @core.AssertionInput = {
    client_data_json: good2.client_data_json,
    authenticator_data: good2.authenticator_data,
    signature: good2.signature,
    credential_public_key: good2.credential_public_key,
    expected_challenge: good2.expected_challenge,
    expected_origin: good2.expected_origin,
    rp_id: "evil.example",
    stored_sign_count: good2.stored_sign_count,
  }
  @debug.assert_eq(t4_assert_code(svc, bad_rp2), "rp_id_mismatch")
}

///|
/// 🔴 **signCount 边界（对照 WebAuthn §7.2）**：
/// - `(0,0)` → 接受（计数器不可比，例外）；
/// - `stored=0, received=5` → 接受（received > stored）；
/// - `received == stored` 且非 0 → **拒绝**（≤ 视为疑似克隆）；
/// - `received < stored` → 拒绝。
async test "T04 §2.5 signCount 0/0 exception and regression boundary" {
  let svc = @passkey.PasskeyService::new(t4_passkey_config())
  // 0/0 例外：接受
  @debug.assert_eq(
    t4_assert_code(svc, t4_assertion_input(t4_challenge, "example.com", 0, 0)),
    "no-error",
  )
  // stored=0, received=5：接受
  @debug.assert_eq(
    t4_assert_code(svc, t4_assertion_input(t4_challenge, "example.com", 5, 0)),
    "no-error",
  )
  // received == stored == 5：拒绝（<=）
  @debug.assert_eq(
    t4_assert_code(svc, t4_assertion_input(t4_challenge, "example.com", 5, 5)),
    "sign_count_regression",
  )
  // received(5) < stored(6)：拒绝
  @debug.assert_eq(
    t4_assert_code(svc, t4_assertion_input(t4_challenge, "example.com", 5, 6)),
    "sign_count_regression",
  )
  // stored 非零、received=0：拒绝（任一方非零 → 比较）
  @debug.assert_eq(
    t4_assert_code(svc, t4_assertion_input(t4_challenge, "example.com", 0, 3)),
    "sign_count_regression",
  )
}

///|
/// **challenge 一次性（托管式）**：同一 `key` 二次使用必须被拒。
async test "T04 §2.5 stored challenge is single-use" {
  let clock_raw = @contract.FixedClock::new(2000L)
  let clock : &@core.Clock = clock_raw
  let store : &@core.ChallengeStore = @store_memory.MemoryChallengeStore::new(clock)
  let svc = @passkey.PasskeyService::new(t4_passkey_config())
    .with_clock(clock)
    .with_store(store)
  let ch = svc.begin_registration()
  let input = t4_registration_input(ch.challenge)
  let _ = svc.finish_registration_stored(ch.key, input)
  let replay = try {
    let _ = svc.finish_registration_stored(ch.key, input)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(replay, "challenge_not_found")
}

// ════════════════════ §2.6 `-unused_async` 审计 ════════════════════
// `passkey/facade.mbt:162/197` 对两条非 `_stored` 方法加了 `#warnings("-unused_async")`。
// 读代码：二者**仅**调用同步 `@core.WebAuthnVerifier::verify_registration` /
// `verify_assertion`（`passkey/verifier.mbt` 是同步 seam），**不触碰** async 存储，
// 确属"接口一致性"而非"忘写 await"。→ 抑制未掩盖 bug。

///| 行为层佐证：两条方法在**无 async 存储**参与下正常返回（抑制未掩盖真 bug）。
async test "T04 §2.6 stateless finish methods work without any async store" {
  let svc = @passkey.PasskeyService::new(t4_passkey_config())
  let reg = svc.finish_registration(t4_registration_input(t4_challenge))
  @debug.assert_eq(reg.credential_id, t4_cred_id())
  let asn = svc.finish_authentication(t4_assertion_input(t4_challenge, "example.com", 5, 0))
  @debug.assert_eq(asn.sign_count, 5)
}
