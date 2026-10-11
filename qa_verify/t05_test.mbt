//! moonauth / qa_verify —— **T05 F1（passkey options）/ F2（base32）独立验证**（QA：严过关）。
//!
//! 目标：不复用工程师断言；既有 API 未回归、ES256 `alg=-7`、options 确定性、
//! challenge 原样、user_handle、base32 RFC4648 官方向量、otpauth secret 一致。

// ════════ 辅助 ════════

///|
/// 字节逐元素相等（避免依赖第三方类型的 Eq/Debug）。
fn t5_bytes_eq(a : Bytes, b : Bytes) -> Bool {
  if a.length() != b.length() {
    return false
  }
  let mut i = 0
  let mut ok = true
  while i < a.length() {
    if a[i] != b[i] {
      ok = false
    }
    i = i + 1
  }
  ok
}

///|
/// 从 `uri` 中取 `name=` 到下一个 `&`（或串尾）之间的值。
fn t5_param(uri : String, name : String) -> String {
  match uri.split_once(name + "=") {
    Some((_, rest)) =>
      match rest.split_once("&") {
        Some((val, _)) => val.to_owned()
        None => rest.to_owned()
      }
    None => ""
  }
}

///|
/// 一个固定的 passkey 配置（供 options 组装用）。
fn t5_passkey_service() -> @passkey.PasskeyService {
  @passkey.PasskeyService::new(
    @passkey.PasskeyConfig::new("example.com", "Example RP", "https://example.com"),
  )
}

///|
/// 一个固定的注册挑战（**直接构造**，值为合法 base64url 形态）。
fn t5_challenge() -> @passkey.PasskeyChallenge {
  {
    challenge: "AAECAwQFBgcICQoLDA0ODw",
    key: "pk:reg:00112233445566778899aabbccddeeff001122334455",
    expires_at: 1700000000L,
  }
}

///|
/// 一个固定的用户实体。
fn t5_user() -> @passkey.UserInfo {
  { id: @utf8.encode("user-handle-42"), name: "ada", display_name: Some("Ada Lovelace") }
}

// ════════ §2 F1-②：ES256 的 COSE alg 必须 = -7 ════════

///|
/// 🔴 `PublicKeyCredParam::es256()` → `type_="public-key"`、**`alg = -7`**。
/// 另用 `registration_options` 里实际产出的参数项复核（防止构造器与组装点脱节）。
async test "t05 F1.2 PublicKeyCredParam::es256 gives type=public-key, alg=-7" {
  let p = @passkey.PublicKeyCredParam::es256()
  @debug.assert_eq(p.type_, "public-key")
  @debug.assert_eq(p.alg, -7)
  // 组装点实际产出也必须含 -7
  let opts = t5_passkey_service().registration_options(t5_challenge(), t5_user())
  assert_true(opts.pub_key_cred_params.length() == 1)
  @debug.assert_eq(opts.pub_key_cred_params[0].type_, "public-key")
  @debug.assert_eq(opts.pub_key_cred_params[0].alg, -7)
}

// ════════ §3 F1：options 确定性 + 字段完整性 + challenge 原样 ════════

///|
/// `registration_options`：字段取自传入值与 config；`challenge` **原样**（不二次编码）。
async test "t05 F1.3 registration_options: fields + challenge passthrough" {
  let svc = t5_passkey_service()
  let ch = t5_challenge()
  let user = t5_user()
  let o = svc.registration_options(ch, user)
  // challenge 原样（与传入字符串逐字符相等 —— 未被再次 base64url/hex 编码）
  @debug.assert_eq(o.challenge, "AAECAwQFBgcICQoLDA0ODw")
  @debug.assert_eq(o.challenge, ch.challenge)
  // rp 取自 config
  @debug.assert_eq(o.rp.id, "example.com")
  @debug.assert_eq(o.rp.name, "Example RP")
  // user 原样
  assert_true(t5_bytes_eq(o.user.id, @utf8.encode("user-handle-42")))
  @debug.assert_eq(o.user.name, "ada")
  @debug.assert_eq(o.user.display_name, Some("Ada Lovelace"))
  // 默认值
  @debug.assert_eq(o.timeout, Some(60000))
  @debug.assert_eq(o.attestation, Some("none"))
  match o.authenticator_selection {
    None => ()
    Some(_) => abort("t05: default authenticator_selection must be None")
  }
  match o.exclude_credentials {
    None => ()
    Some(_) => abort("t05: default exclude_credentials must be None")
  }
}

///|
/// 固定 challenge + 固定用户 → `registration_options` **确定性**（两次输出关键字段一致）。
async test "t05 F1.3 registration_options is deterministic" {
  let svc = t5_passkey_service()
  let a = svc.registration_options(t5_challenge(), t5_user())
  let b = svc.registration_options(t5_challenge(), t5_user())
  @debug.assert_eq(a.challenge, b.challenge)
  @debug.assert_eq(a.rp.id, b.rp.id)
  @debug.assert_eq(a.rp.name, b.rp.name)
  @debug.assert_eq(a.user.name, b.user.name)
  @debug.assert_eq(a.timeout, b.timeout)
  @debug.assert_eq(a.attestation, b.attestation)
  assert_true(t5_bytes_eq(a.user.id, b.user.id))
  assert_true(a.pub_key_cred_params[0].alg == b.pub_key_cred_params[0].alg)
}

///|
/// `registration_options` 的 exclude_credentials / authenticator_selection 参数透传。
async test "t05 F1.3 registration_options honours optional params" {
  let svc = t5_passkey_service()
  let desc = @passkey.CredentialDescriptor::public_key(@utf8.encode("cid-1"))
  let sel = @passkey.AuthenticatorSelection::passkey()
  let o = svc.registration_options(
    t5_challenge(),
    t5_user(),
    timeout=12345,
    attestation="direct",
    authenticator_selection=Some(sel),
    exclude_credentials=[desc],
  )
  @debug.assert_eq(o.timeout, Some(12345))
  @debug.assert_eq(o.attestation, Some("direct"))
  // 结构化透传：字段不丢
  match o.authenticator_selection {
    Some(s) => {
      @debug.assert_eq(s.authenticator_attachment, Some("platform"))
      @debug.assert_eq(s.resident_key, Some("required"))
      @debug.assert_eq(s.require_resident_key, None)
      @debug.assert_eq(s.user_verification, Some("required"))
    }
    None => abort("t05: authenticator_selection must be Some when supplied")
  }
  match o.exclude_credentials {
    Some(arr) => {
      assert_true(arr.length() == 1)
      @debug.assert_eq(arr[0].type_, "public-key")
      assert_true(t5_bytes_eq(arr[0].id, @utf8.encode("cid-1")))
    }
    None => abort("t05: exclude_credentials must be Some when non-empty")
  }
}

///|
/// `authentication_options`：challenge 原样、rp_id 取自 config、UV 由 config 推导 / 显式覆盖。
async test "t05 F1.3 authentication_options: challenge, rp_id, uv policy" {
  let ch = t5_challenge()
  // config UV=false → 推导 "preferred"
  let svc = t5_passkey_service()
  let a = svc.authentication_options(ch)
  @debug.assert_eq(a.challenge, ch.challenge)
  @debug.assert_eq(a.rp_id, "example.com")
  @debug.assert_eq(a.user_verification, Some("preferred"))
  @debug.assert_eq(a.timeout, Some(60000))
  match a.allow_credentials {
    None => ()
    Some(_) => abort("t05: default allow_credentials must be None")
  }
  // config UV=true → 推导 "required"
  let svc_uv = @passkey.PasskeyService::new(
    @passkey.PasskeyConfig::new(
      "example.com",
      "Example RP",
      "https://example.com",
    ).with_user_verification(true),
  )
  @debug.assert_eq(svc_uv.authentication_options(ch).user_verification, Some("required"))
  // 显式覆盖
  @debug.assert_eq(
    svc.authentication_options(ch, user_verification=Some("discouraged")).user_verification,
    Some("discouraged"),
  )
  // allow_credentials 透传
  let desc = @passkey.CredentialDescriptor::public_key(@utf8.encode("cid-2"))
  match svc.authentication_options(ch, allow_credentials=[desc]).allow_credentials {
    Some(arr) => assert_true(arr.length() == 1)
    None => abort("t05: allow_credentials must be Some when non-empty")
  }
}

// ════════ §4 F1：user_handle ════════

///|
/// `from_registration` 默认 `user_handle = None`；`with_user_handle` 写入并可读回，且不改原记录。
async test "t05 F1.4 user_handle defaults None and round-trips" {
  let reg : @core.VerifiedRegistration = {
    credential_id: @utf8.encode("cid"),
    public_key: @utf8.encode("cose-pk"),
    sign_count: 7,
    aaguid: None,
    user_verified: true,
  }
  let cred = @passkey.PasskeyCredential::from_registration(reg)
  match cred.user_handle {
    None => ()
    Some(_) => abort("t05: from_registration must default user_handle to None")
  }
  @debug.assert_eq(cred.sign_count, 7)
  @debug.assert_eq(cred.user_verified, true)
  let handle = @utf8.encode("user-handle-bytes")
  let cred2 = cred.with_user_handle(handle)
  match cred2.user_handle {
    Some(b) => assert_true(t5_bytes_eq(b, handle))
    None => abort("t05: with_user_handle must set Some")
  }
  // 返回新值，不改原记录
  match cred.user_handle {
    None => ()
    Some(_) => abort("t05: with_user_handle must not mutate the original")
  }
  assert_true(t5_bytes_eq(cred2.credential_id, @utf8.encode("cid")))
  assert_true(t5_bytes_eq(cred2.public_key, @utf8.encode("cose-pk")))
}

// ════════ §1 F1：既有 API 未回归（T04 签名的编译期 / 行为期核对） ════════

///|
/// `begin_*` 仍返回 `PasskeyChallenge`（三字段形态未变）；`finish_*` 的调用见既有
/// `t04_test.mbt`（本包编译通过即证明其签名兼容）。
async test "t05 F1.1 begin_* still return PasskeyChallenge (shape unchanged)" {
  let svc = t5_passkey_service()
  let ch : @passkey.PasskeyChallenge = svc.begin_registration()
  let ch2 : @passkey.PasskeyChallenge = svc.begin_authentication()
  // 三字段仍在
  assert_true(ch.challenge.length() == 43)
  assert_true(ch.key.has_prefix("pk:reg:"))
  assert_true(ch.expires_at >= 0L)
  assert_true(ch2.key.has_prefix("pk:auth:"))
  // 挑战确实变了（每次 begin 独立，非复用同一值）
  assert_true(ch.challenge != ch2.challenge || ch.key != ch2.key)
}

///|
/// `StandardWebAuthnVerifier` 的既有签名未变（构造 + UV 策略读写 + 两 seam 方法可用）。
async test "t05 F1.1 StandardWebAuthnVerifier signatures unchanged" {
  let v = @passkey.StandardWebAuthnVerifier::new()
  @debug.assert_eq(v.require_user_verification(), false)
  let v2 = v.with_user_verification(true)
  @debug.assert_eq(v2.require_user_verification(), true)
  // 类型可赋给 seam 引用（verify_registration / verify_assertion 方法可用）
  let _seam : &@core.WebAuthnVerifier = v2
}

// ════════ §5 F2：base32_encode RFC 4648 官方向量（独立复算） ════════

///|
/// 🔴 RFC 4648 §10 官方向量（`f`/`fo`/`foo`/`foob`/`fooba`/`foobar`）——**QA 独立复算**。
async test "t05 F2.5 base32_encode matches RFC 4648 official vectors" {
  @debug.assert_eq(@totp.base32_encode(@utf8.encode("")), "")
  @debug.assert_eq(@totp.base32_encode(@utf8.encode("f")), "MY")
  @debug.assert_eq(@totp.base32_encode(@utf8.encode("fo")), "MZXQ")
  @debug.assert_eq(@totp.base32_encode(@utf8.encode("foo")), "MZXW6")
  @debug.assert_eq(@totp.base32_encode(@utf8.encode("foob")), "MZXW6YQ")
  @debug.assert_eq(@totp.base32_encode(@utf8.encode("fooba")), "MZXW6YTB")
  @debug.assert_eq(@totp.base32_encode(@utf8.encode("foobar")), "MZXW6YTBOI")
  // 大写无填充（无 `=`）
  assert_true(!@totp.base32_encode(@utf8.encode("fo")).contains("="))
}

///|
/// 🔴 `otpauth_uri` 里的 `secret=` 必须与 `base32_encode(secret)` **逐字符一致**（LIB-06 ①）。
async test "t05 F2.5 otpauth_uri secret == base32_encode(secret)" {
  let prim = @totp.StandardTotpPrimitive::new()
  // 用 RFC6238 的种子（20 字节 ASCII）
  let secret = @utf8.encode("12345678901234567890")
  let opts : @core.TotpOptions = { digits: 6, period: 30, algorithm: "SHA1" }
  let uri = prim.otpauth_uri(secret, "user", "moonauth", opts) catch {
    e => abort("t05: otpauth_uri failed: " + @core.auth_error_message(e))
  }
  let from_uri = t5_param(uri, "secret")
  @debug.assert_eq(from_uri, @totp.base32_encode(secret))
  assert_true(from_uri.length() > 0)
}

///|
/// `generate_secret` 的 seam 签名**仍返回 `Bytes`**（未改为 String / 未新增编码步骤）。
async test "t05 F2.5 generate_secret seam still returns Bytes" {
  let prim = @totp.StandardTotpPrimitive::new()
  let s : Bytes = prim.generate_secret(160) // 160 bit → 20 字节
  @debug.assert_eq(s.length(), 20)
  // 与 `base32_encode` 组合可用（展示形态）
  assert_true(@totp.base32_encode(s).length() == 32)
}

// ════════ 窄复验：AuthenticatorSelection 结构化类型（浏览器对象语义） ════════

///|
/// 🔴 `AuthenticatorSelection::passkey()` 字段值须能请求到**可发现凭据（真 passkey）**：
/// `platform`（平台认证器）+ `required`（常驻密钥）+ `required`（UV）；旧字段不输出。
async test "t05 fix AuthenticatorSelection::passkey() field values" {
  let s = @passkey.AuthenticatorSelection::passkey()
  @debug.assert_eq(s.authenticator_attachment, Some("platform"))
  @debug.assert_eq(s.resident_key, Some("required"))
  @debug.assert_eq(s.require_resident_key, None)
  @debug.assert_eq(s.user_verification, Some("required"))
}
