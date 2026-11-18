//! moonauth / passkey —— 黑盒测试：WebAuthn 向量 / 门面 / 存储语义 / 契约。
//!
//! 🔴 本文件是**黑盒测试**（`*_test.mbt`）：被测包以 `@passkey.` 限定引用。
//! 用例一律写成 `async test`（门面全 async，且需 `moonbitlang/async` 运行时）。
//!
//! 离线、确定性：零真实网络；随机源经 `FixedRandomSource` 注入、时间经
//! `@contract.FixedClock` 注入。WebAuthn 向量由**独立构造的 P-256 私钥**现场签名，
//! 与被测实现不共享代码路径（公钥坐标经 COSE 编码独立给出）。

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
/// 单个十六进制字符 → 数值（非法记为 0）。
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
/// ASCII 字符串 → 字节。
fn ascii_bytes(s : String) -> Bytes {
  Bytes::makei(s.length(), fn(i) {
    (s.get_char(i).unwrap().to_int() & 0xFF).to_byte()
  })
}

///|
/// 字节拼接。
fn concat(a : Bytes, b : Bytes) -> Bytes {
  let out : Array[Byte] = []
  for x in a {
    out.push(x)
  }
  for x in b {
    out.push(x)
  }
  Bytes::from_array(out)
}

///|
/// 大端写入 32 位无符号（`authenticatorData.signCount`）。
fn push_u32_be(out : Array[Byte], n : Int) -> Unit {
  out.push(((n >> 24) & 0xFF).to_byte())
  out.push(((n >> 16) & 0xFF).to_byte())
  out.push(((n >> 8) & 0xFF).to_byte())
  out.push((n & 0xFF).to_byte())
}

///|
/// authenticatorData：rpIdHash(32) || flags(1) || signCount(4) || attestedCredentialData。
fn auth_data_attested(
  rp_id_hash : Bytes,
  flags : Int,
  sign_count : Int,
  aaguid : Bytes,
  cred_id : Bytes,
  cose : Bytes,
) -> Bytes {
  let out : Array[Byte] = []
  for b in rp_id_hash {
    out.push(b)
  }
  out.push(flags.to_byte())
  push_u32_be(out, sign_count)
  for b in aaguid {
    out.push(b)
  }
  out.push(((cred_id.length() >> 8) & 0xFF).to_byte())
  out.push((cred_id.length() & 0xFF).to_byte())
  for b in cred_id {
    out.push(b)
  }
  for b in cose {
    out.push(b)
  }
  Bytes::from_array(out)
}

///|
/// authenticatorData（认证器 / 无 attested credential data）：rpIdHash(32) || flags(1) || signCount(4)。
fn auth_data_plain(rp_id_hash : Bytes, flags : Int, sign_count : Int) -> Bytes {
  let out : Array[Byte] = []
  for b in rp_id_hash {
    out.push(b)
  }
  out.push(flags.to_byte())
  push_u32_be(out, sign_count)
  Bytes::from_array(out)
}

///|
/// 固定 P-256 测试私钥（与被测实现无关；标量来自已知测试向量）。
fn test_private_key() -> @p256.PrivateKey {
  @p256.PrivateKey::from_bytes(
    hex_bytes(
      "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
    ),
  ) catch {
    _ => abort("moonauth test: invalid fixed P-256 scalar")
  }
}

///|
/// 由固定私钥导出 ES256 COSE 公钥（CBOR）。
fn credential_cose() -> Bytes {
  let uncompressed = test_private_key().public_key().to_uncompressed()
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

///|
/// 固定凭据 ID（32 字节）。
fn credential_id() -> Bytes {
  hex_bytes("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
}

///|
/// 固定 AAGUID（16 字节）。
fn fixed_aaguid() -> Bytes {
  hex_bytes("0102030405060708090a0b0c0d0e0f10")
}

///|
/// 合成 `clientDataJSON`。
fn client_data(ceremony_type : String, challenge : String, origin : String) -> Bytes {
  ascii_bytes(
    "{\"type\":\"" +
    ceremony_type +
    "\",\"challenge\":\"" +
    challenge +
    "\",\"origin\":\"" +
    origin +
    "\"}",
  )
}

///|
/// 构造一个**必然通过**的注册输入：`none` 格式 attestation（无签名），
/// flags = 0x45（UP + UV + AT），signCount = 0。
fn registration_input(challenge : String) -> @core.RegistrationInput {
  registration_input_with_flags(challenge, 0x45)
}

///|
/// 同上，但可指定 `authenticatorData.flags`（用于 UV 策略负例，如 `0x41` = UP+AT 无 UV）。
fn registration_input_with_flags(
  challenge : String,
  flags : Int,
) -> @core.RegistrationInput {
  let rp_id = "example.com"
  let auth_data = auth_data_attested(
    @webauthn.rp_id_hash(rp_id),
    flags,
    0,
    fixed_aaguid(),
    credential_id(),
    credential_cose(),
  )
  let empty : Array[(@cbor.CborValue, @cbor.CborValue)] = []
  let attestation_object = @cbor.encode(
    @cbor.CborValue::Map([
      (@cbor.CborValue::Text("fmt"), @cbor.CborValue::Text("none")),
      (@cbor.CborValue::Text("authData"), @cbor.CborValue::Bytes(auth_data)),
      (@cbor.CborValue::Text("attStmt"), @cbor.CborValue::Map(empty)),
    ]),
  )
  {
    client_data_json: client_data(
      "webauthn.create",
      challenge,
      "https://example.com",
    ),
    attestation_object,
    expected_challenge: challenge,
    expected_origin: "https://example.com",
    rp_id,
  }
}

///|
/// 构造一个**必然通过**的认证输入：flags = 0x05（UP + UV），signCount = 5，
/// 签名由固定私钥对 `authData || clientDataHash` 现场生成。
fn assertion_input(challenge : String) -> @core.AssertionInput {
  let rp_id = "example.com"
  let auth_data = auth_data_plain(@webauthn.rp_id_hash(rp_id), 0x05, 5)
  let client_data_json = client_data("webauthn.get", challenge, "https://example.com")
  let hash = @webauthn.client_data_hash(client_data_json)
  let signature = test_private_key().sign(
    concat(auth_data, hash),
    format=@p256.SignatureFormat::Der,
  )
  {
    client_data_json,
    authenticator_data: auth_data,
    signature,
    credential_public_key: credential_cose(),
    expected_challenge: challenge,
    expected_origin: "https://example.com",
    rp_id,
    stored_sign_count: 0,
  }
}

///|
/// 契约使用的固定挑战。
let fixed_challenge : String = "dGVzdC1jaGFsbGVuZ2UtMDAx"

///|
/// 契约夹具（固定挑战）。
fn webauthn_fixtures() -> @contract.WebAuthnFixtures {
  {
    registration: registration_input(fixed_challenge),
    expected_credential_id: credential_id(),
    expected_registration_sign_count: 0,
    assertion: assertion_input(fixed_challenge),
    expected_assertion_sign_count: 5,
  }
}

///|
/// 测试用 RP 配置。
fn passkey_config() -> @passkey.PasskeyConfig {
  @passkey.PasskeyConfig::new("example.com", "moonauth Test", "https://example.com")
}

///|
/// 返回固定字节序列的 `RandomSource`（确定性重放）。
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
/// **必然失败**的 `ChallengeStore`：三个方法一律抛 `Network`（模拟 Redis 连接失败）。
///
/// 用于锁定核心契约：存储故障必须是可捕获的 `AuthError`，**不能**被降级成 `None`。
struct FailingChallengeStore {
  reason : String
}

///|
/// 实现 seam（async）：写入即失败。
impl @core.ChallengeStore for FailingChallengeStore with fn put(
  self,
  key,
  value,
  ttl,
) {
  let _ = (key, value, ttl)
  raise @core.Network("moonauth test: challenge store unavailable: " + self.reason)
}

///|
/// 实现 seam（async）：取用即失败（**不**返回 `None`）。
impl @core.ChallengeStore for FailingChallengeStore with fn take(self, key) {
  let _ = key
  raise @core.Network("moonauth test: challenge store unavailable: " + self.reason)
}

///|
/// 实现 seam（async）：只读检查即失败。
impl @core.ChallengeStore for FailingChallengeStore with fn peek(self, key) {
  let _ = key
  raise @core.Network("moonauth test: challenge store unavailable: " + self.reason)
}

// ════════ 🔴 存储故障 ≠ challenge 不存在 ════════

///|
/// 核心契约：**必然失败的 `ChallengeStore` → 调用方拿到 `AuthError`（`network`），
/// 而不是 `None` / `ChallengeNotFound`**。
///
/// 若 `take` 的存储异常被吞成 `None`，调用方会把「Redis 连接失败」误判为
/// 「challenge 不存在（重放 / 凭据失效）」——安全语义事故。此用例锁定「不吞错」。
async test "passkey: storage failure surfaces as AuthError, not ChallengeNotFound" {
  let failing : &@core.ChallengeStore = FailingChallengeStore::{
    reason: "redis connection refused",
  }
  let service = @passkey.PasskeyService::new(passkey_config()).with_store(failing)
  let code = try {
    let _ = service.finish_registration_stored(
      "pk:reg:whatever",
      webauthn_fixtures().registration,
    )
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  assert_true(code != "challenge_not_found")
  @debug.assert_eq(code, "network")

  // 认证路径同理。
  let auth_code = try {
    let _ = service.finish_authentication_stored(
      "pk:auth:whatever",
      webauthn_fixtures().assertion,
    )
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(auth_code, "network")
}

///|
/// 与上一条**对照**：真正的「不存在」是 `ChallengeNotFound`（与存储故障可区分）。
async test "passkey: an unknown challenge is ChallengeNotFound" {
  let service = @passkey.PasskeyService::new(passkey_config())
  let code = try {
    let _ = service.finish_registration_stored(
      "pk:reg:absent",
      webauthn_fixtures().registration,
    )
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "challenge_not_found")
  let auth_code = try {
    let _ = service.finish_authentication_stored(
      "pk:auth:absent",
      webauthn_fixtures().assertion,
    )
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(auth_code, "challenge_not_found")
}

// ════════ 门面：无状态式 ════════

///|
/// 无状态式：有效注册 / 认证通过，字段还原正确（含 AAGUID / UV）。
async test "passkey: stateless registration and authentication verify valid vectors" {
  let service = @passkey.PasskeyService::new(passkey_config())
  let fixtures = webauthn_fixtures()
  let registration = service.finish_registration(fixtures.registration)
  @debug.assert_eq(registration.credential_id, fixtures.expected_credential_id)
  @debug.assert_eq(registration.sign_count, 0)
  assert_true(registration.user_verified)
  @debug.assert_eq(registration.aaguid, Some("01020304-0506-0708-090a-0b0c0d0e0f10"))

  let assertion = service.finish_authentication(fixtures.assertion)
  @debug.assert_eq(assertion.sign_count, 5)
  assert_true(assertion.user_verified)

  // 注册结果 → 可持久化凭据（`PasskeyCredential` 字段一一对应）。
  let credential = @passkey.PasskeyCredential::from_registration(registration)
  @debug.assert_eq(credential.credential_id, fixtures.expected_credential_id)
  @debug.assert_eq(credential.public_key, registration.public_key)
  @debug.assert_eq(credential.sign_count, 0)
  assert_true(credential.user_verified)
}

///|
/// `PasskeyCredential.user_handle` 默认 `None`；`with_user_handle` 回填（返回新记录，值语义）。
async test "passkey: credential records a user handle via with_user_handle" {
  let service = @passkey.PasskeyService::new(passkey_config())
  let registration = service.finish_registration(webauthn_fixtures().registration)
  let base = @passkey.PasskeyCredential::from_registration(registration)
  match base.user_handle {
    None => ()
    Some(_) => abort("passkey: a fresh credential must start without a user handle")
  }
  let handle = b"user-handle-0001"
  let tagged = base.with_user_handle(handle)
  match tagged.user_handle {
    Some(h) => @debug.assert_eq(h, handle)
    None => abort("passkey: user handle must be recorded after with_user_handle")
  }
  // 原记录未被改动（值语义）
  match base.user_handle {
    None => ()
    Some(_) => abort("passkey: with_user_handle must not mutate the source record")
  }
  @debug.assert_eq(tagged.credential_id, base.credential_id)
}

///|
/// 🔴 LIB-05 ①：库产出**浏览器创建选项**。固定 challenge + 固定用户 → 确定性 options；
/// `pubKeyCredParams` 含 ES256（`alg = -7`）；`rp.id` / `user.id` 正确；challenge 原样。
async test "passkey: registration_options builds deterministic browser creation options" {
  let service = @passkey.PasskeyService::new(passkey_config())
  let challenge = service.begin_registration()
  let user : @passkey.UserInfo = {
    id: b"user-handle-0001",
    name: "alice@example.com",
    display_name: Some("Alice"),
  }
  let options = service.registration_options(challenge, user)
  // challenge 原样（base64url 字符串）
  @debug.assert_eq(options.challenge, challenge.challenge)
  // rp 取自 config
  @debug.assert_eq(options.rp.id, "example.com")
  @debug.assert_eq(options.rp.name, "moonauth Test")
  // user 原样
  @debug.assert_eq(options.user.id, b"user-handle-0001")
  @debug.assert_eq(options.user.name, "alice@example.com")
  @debug.assert_eq(options.user.display_name, Some("Alice"))
  // ES256（alg = -7）
  @debug.assert_eq(options.pub_key_cred_params.length(), 1)
  @debug.assert_eq(options.pub_key_cred_params[0].type_, "public-key")
  @debug.assert_eq(options.pub_key_cred_params[0].alg, -7)
  // 默认 attestation = "none"；未提供排除凭据
  @debug.assert_eq(options.attestation, Some("none"))
  match options.exclude_credentials {
    None => ()
    Some(_) => abort("passkey: exclude_credentials should default to None")
  }
}

///|
/// LIB-05 ①：认证选项——`rpId` 取自 config；授权凭据映射为 `allow_credentials`；
/// `user_verification` 缺省按 UV 策略推导（此处非强制 → `preferred`）。
async test "passkey: authentication_options builds browser request options" {
  let service = @passkey.PasskeyService::new(passkey_config())
  let challenge = service.begin_authentication()
  let options = service.authentication_options(
    challenge,
    allow_credentials=[@passkey.CredentialDescriptor::public_key(b"cred-1")],
  )
  @debug.assert_eq(options.challenge, challenge.challenge)
  @debug.assert_eq(options.rp_id, "example.com")
  @debug.assert_eq(options.user_verification, Some("preferred"))
  match options.allow_credentials {
    Some(list) => {
      @debug.assert_eq(list.length(), 1)
      @debug.assert_eq(list[0].type_, "public-key")
      @debug.assert_eq(list[0].id, b"cred-1")
    }
    None => abort("passkey: allow_credentials should be present when supplied")
  }
  // 未提供 allow_credentials → None
  let bare = service.authentication_options(challenge)
  match bare.allow_credentials {
    None => ()
    Some(_) => abort("passkey: allow_credentials should be None when omitted")
  }
}

///|
/// 🔴 `authenticator_selection` 是**结构化对象**（浏览器 `AuthenticatorSelectionCriteria`），
/// **不是字符串**：`registration_options` 透传正确；且 `AuthenticatorSelection::passkey()`
/// 给出「可发现凭据」的常见组合（平台认证器 + 常驻密钥 required + UV required）。
async test "passkey: registration_options passes a structured authenticator_selection" {
  let service = @passkey.PasskeyService::new(passkey_config())
  let challenge = service.begin_registration()
  let user : @passkey.UserInfo = { id: b"uh-1", name: "bob", display_name: None }
  // 缺省 → None
  let plain = service.registration_options(challenge, user)
  match plain.authenticator_selection {
    None => ()
    Some(_) => abort("passkey: authenticator_selection should default to None")
  }
  // 便捷构造的各字段值
  let sel = @passkey.AuthenticatorSelection::passkey()
  @debug.assert_eq(sel.authenticator_attachment, Some("platform"))
  @debug.assert_eq(sel.resident_key, Some("required"))
  @debug.assert_eq(sel.user_verification, Some("required"))
  @debug.assert_eq(sel.require_resident_key, None)
  // 透传到 options
  let options = service.registration_options(
    challenge,
    user,
    authenticator_selection=Some(sel),
  )
  match options.authenticator_selection {
    Some(s) => {
      @debug.assert_eq(s.authenticator_attachment, Some("platform"))
      @debug.assert_eq(s.resident_key, Some("required"))
      @debug.assert_eq(s.user_verification, Some("required"))
      @debug.assert_eq(s.require_resident_key, None)
    }
    None => abort("passkey: authenticator_selection should be present when supplied")
  }
}

///|
/// 配置覆盖生效：`require_user_verification = true` 时拒收**无 UV 标志**的凭据
/// （`UserNotVerified` → `InvalidInput`）；带 UV 的同形凭据通过。
async test "passkey: require_user_verification rejects a credential without the UV flag" {
  let service = @passkey.PasskeyService::new(
    passkey_config().with_user_verification(true),
  )
  let without_uv = registration_input_with_flags(fixed_challenge, 0x41)
  let code = try {
    let _ = service.finish_registration(without_uv)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "invalid_input")
  // 带 UV 的同形凭据（0x45）通过。
  let with_uv = service.finish_registration(registration_input(fixed_challenge))
  assert_true(with_uv.user_verified)
}

///|
/// 配置覆盖生效：`challenge_ttl_seconds` 影响 `begin_*` 返回的过期时刻。
async test "passkey: challenge ttl override is reflected in expires_at" {
  let clock : &@core.Clock = @contract.FixedClock::new(500L)
  let store : &@core.ChallengeStore = @store_memory.MemoryChallengeStore::new(clock)
  let service = @passkey.PasskeyService::new(
    passkey_config().with_challenge_ttl(60),
  ).with_clock(clock).with_store(store)
  let challenge = service.begin_registration()
  @debug.assert_eq(challenge.expires_at, 560L)
}

///|
/// 无状态式：挑战不符 → `ChallengeMismatch`；篡改签名 → `SignatureInvalid`。
async test "passkey: stateless flow rejects a mismatched challenge and a tampered signature" {
  let service = @passkey.PasskeyService::new(passkey_config())
  let fixtures = webauthn_fixtures()

  let source = fixtures.registration
  let bad_challenge : @core.RegistrationInput = {
    client_data_json: source.client_data_json,
    attestation_object: source.attestation_object,
    expected_challenge: source.expected_challenge + "x",
    expected_origin: source.expected_origin,
    rp_id: source.rp_id,
  }
  let challenge_code = try {
    let _ = service.finish_registration(bad_challenge)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(challenge_code, "challenge_mismatch")

  let signed = fixtures.assertion
  let tampered : @core.AssertionInput = {
    client_data_json: signed.client_data_json,
    authenticator_data: signed.authenticator_data,
    signature: Bytes::makei(signed.signature.length(), fn(i) {
      if i == 0 {
        (signed.signature[i].to_int() ^ 0xFF).to_byte()
      } else {
        signed.signature[i]
      }
    }),
    credential_public_key: signed.credential_public_key,
    expected_challenge: signed.expected_challenge,
    expected_origin: signed.expected_origin,
    rp_id: signed.rp_id,
    stored_sign_count: signed.stored_sign_count,
  }
  let signature_code = try {
    let _ = service.finish_authentication(tampered)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(signature_code, "signature_invalid")
}

// ════════ 门面：托管式（ChallengeStore） ════════

///|
/// 托管式：`begin_registration` 生成并存储挑战（TTL / 过期时刻正确）；
/// `finish_registration_stored` 消费挑战并通过校验；**二次消费失败**（一次性）。
async test "passkey: stored flow consumes the challenge exactly once" {
  let random : &@core.RandomSource = FixedRandomSource::{
    data: hex_bytes(
      "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
    ),
  }
  let clock : &@core.Clock = @contract.FixedClock::new(1000L)
  let store : &@core.ChallengeStore = @store_memory.MemoryChallengeStore::new(clock)
  let service = @passkey.PasskeyService::new(passkey_config())
    .with_random(random)
    .with_clock(clock)
    .with_store(store)

  let challenge = service.begin_registration()
  assert_true(challenge.key.has_prefix("pk:reg:"))
  assert_true(challenge.challenge.length() > 20)
  // TTL 默认 300s，时钟 = 1000 → 过期时刻 1300。
  @debug.assert_eq(challenge.expires_at, 1300L)

  // 用生成的挑战构造有效注册输入，再消费。
  let input = registration_input(challenge.challenge)
  let registration = service.finish_registration_stored(challenge.key, input)
  @debug.assert_eq(registration.credential_id, credential_id())

  // 一次性：同一 key 二次消费 → ChallengeNotFound。
  let replay_code = try {
    let _ = service.finish_registration_stored(challenge.key, input)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(replay_code, "challenge_not_found")
}

///|
/// 托管式：认证 `begin_authentication` + `finish_authentication_stored` 全链路通过。
async test "passkey: stored authentication flow verifies a valid assertion" {
  let clock : &@core.Clock = @contract.FixedClock::new(2000L)
  let store : &@core.ChallengeStore = @store_memory.MemoryChallengeStore::new(clock)
  let service = @passkey.PasskeyService::new(passkey_config())
    .with_clock(clock)
    .with_store(store)
  let challenge = service.begin_authentication()
  assert_true(challenge.key.has_prefix("pk:auth:"))
  let input = assertion_input(challenge.challenge)
  let assertion = service.finish_authentication_stored(challenge.key, input)
  @debug.assert_eq(assertion.sign_count, 5)
}

///|
/// 托管式：**过期**的挑战视为一次性失败（`ChallengeNotFound`）——`MemoryChallengeStore`
/// 的过期语义（`ttl` 后 `take` → `None`）。
async test "passkey: an expired stored challenge is treated as not-found" {
  let clock_raw = @contract.FixedClock::new(1000L)
  let clock : &@core.Clock = clock_raw
  let store : &@core.ChallengeStore = @store_memory.MemoryChallengeStore::new(clock)
  let service = @passkey.PasskeyService::new(passkey_config())
    .with_clock(clock)
    .with_store(store)
  let challenge = service.begin_authentication()
  // 前进到过期之后。
  clock_raw.advance(301L)
  let code = try {
    let _ = service.finish_authentication_stored(
      challenge.key,
      assertion_input(challenge.challenge),
    )
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "challenge_not_found")
}

// ════════ 契约：对默认实现跑参数化断言集 ════════

///|
/// `WebAuthnVerifier` 契约对**库自实现**（`StandardWebAuthnVerifier`）100% 通过。
async test "webauthn contract: StandardWebAuthnVerifier passes every case" {
  let cases = @contract.run_webauthn(fn() {
    let subject : &@core.WebAuthnVerifier = @passkey.StandardWebAuthnVerifier::new()
    subject
  })
  @contract.assert_all_pass(cases)
}

///|
/// 契约与向量**解耦**：同一断言集换用「调用方提供」的向量（本地现场签名构造）依旧
/// 100% 通过——这正是 SDK-04 可替换性的基础（同一断言集可对不同实现 / 不同向量各跑一次）。
async test "webauthn contract: run_webauthn_with accepts caller-provided vectors" {
  let cases = @contract.run_webauthn_with(fn() {
    let subject : &@core.WebAuthnVerifier = @passkey.StandardWebAuthnVerifier::new()
    subject
  }, webauthn_fixtures())
  @contract.assert_all_pass(cases)
}

///|
/// 🔴 WebAuthn Level 3：credentialId **不得超过 1023 字节**（黑客审计第 1 轮确认
/// 修复）——超长凭据的注册输入必须被 `InvalidInput` 拒绝，不得透传给调用方存储。
async test "passkey: credential id over 1023 bytes is rejected" {
  let oversized = Bytes::makei(2000, fn(i) { (i % 256).to_byte() })
  let rp_id = "example.com"
  let auth_data = auth_data_attested(
    @webauthn.rp_id_hash(rp_id),
    0x45,
    0,
    fixed_aaguid(),
    oversized,
    credential_cose(),
  )
  let empty : Array[(@cbor.CborValue, @cbor.CborValue)] = []
  let attestation_object = @cbor.encode(
    @cbor.CborValue::Map([
      (@cbor.CborValue::Text("fmt"), @cbor.CborValue::Text("none")),
      (@cbor.CborValue::Text("authData"), @cbor.CborValue::Bytes(auth_data)),
      (@cbor.CborValue::Text("attStmt"), @cbor.CborValue::Map(empty)),
    ]),
  )
  let challenge = "challenge-oversized-credential-id"
  let input : @core.RegistrationInput = {
    client_data_json: client_data("webauthn.create", challenge, "https://example.com"),
    attestation_object,
    expected_challenge: challenge,
    expected_origin: "https://example.com",
    rp_id,
  }
  let service = @passkey.PasskeyService::new(passkey_config())
  let code = try {
    let _ = service.finish_registration(input)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "invalid_input")
}
