//! moonauth / example —— 裸 `async` 最小 handler：串起 **Google + passkey + TOTP**。
//!
//! 🔴 **LIB-08**：示范「不依赖任何 Web 框架」时，如何用 `moonauth` 的能力 seam 拼出
//! 三条最常见的鉴权链路，并且**全部离线确定性**：
//! - HTTP 走 `@contract.MockHttpClient`（预置固定响应），**零真实网络**；
//! - 时钟走 `@contract.FixedClock`，随机走本文件内的 `FixedRandomSource` seam，**可重放**；
//! - 固定向量来自 `@contract`（RS256 `id_token` / JWKS / WebAuthn / RFC 6238），**零资质**。
//!
//! 运行：`moon run examples/bare-async/src`（native）。
//!
//! 说明：真正的服务端只需把本文件里的三段逻辑放进各自的 HTTP handler；
//! 本示例用一个 `async fn main` 顺序驱动它们，以便在无端口、无 socket 的情况下
//! 一次跑完并打印可核对的结果（框架接入见 `examples/moonback` / `examples/mars`）。

///|
/// 固定字节序列的 `RandomSource`：以固定种子重复填充，得到**确定性**的伪随机流。
///
/// 这正是 SDK-01 / §10.4 的要点——随机性一律经注入 seam，绝不直连 `@env.rand`，
/// 故本示例无需、也不引入 `rand` 子包（`getrandom`）。
struct FixedRandomSource {
  data : Bytes
}

///|
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
/// 统计契约用例通过数。
fn passed_count(results : Array[@contract.CaseResult]) -> Int {
  let mut n = 0
  for r in results {
    if r.passed {
      n = n + 1
    }
  }
  n
}

///|
/// 判断 `uid_kind` 是否为 `Stable`（避免对枚举直接用 `==`）。
fn is_stable(kind : @core.UidKind) -> Bool {
  match kind {
    @core.UidKind::Stable => true
    @core.UidKind::Degraded => false
  }
}

///|
/// 裸 async 主程序：顺序驱动 Google / passkey / TOTP 三条 handler 链路。
async fn main {
  let clock : &@core.Clock = @contract.FixedClock::new(@contract.fixed_now_unix())
  let random : &@core.RandomSource = FixedRandomSource::{
    data: b"moonauth-bare-async-seed",
  }
  println("=== moonauth bare-async demo (offline, deterministic) ===")

  // ════════ ① Google：begin → 回调 → complete → ExternalIdentity ════════
  // 装配点（mock HTTP + 固定时钟 + 固定 issuer）由 contract 起手函数给出。
  let gcfg = @contract.google_mock_config()
  let gstart = @google.begin_auth(gcfg, {
    state: Some("st-c1"),
    code_verifier: Some("verifier-1"),
    nonce: Some("nonce-1"),
  })
  println("[google] authorize url       = " + gstart.url)
  // 浏览器回调：把 query 变成 CallbackParams（库只解析，不关心来源）。
  let gcallback = @core.CallbackParams::from_query_string(
    "code=auth-code-1&state=st-c1",
  )
  let gidentity = @google.complete_auth(gcfg, gcallback, gstart)
  println("[google] provider/uid        = " + gidentity.provider + " / " + gidentity.uid)
  println("[google] email               = " + gidentity.email.unwrap_or("<none>"))
  println(
    "[google] email_verified/stable = " +
    gidentity.email_verified.to_string() +
    " / " +
    is_stable(gidentity.uid_kind).to_string(),
  )

  // ════════ ② passkey：挑战经 seam 生成 + 一次性存储 + 固定向量验证 ════════
  let store : &@core.ChallengeStore = @store_memory.MemoryChallengeStore::new(clock)
  let passkey = @passkey.PasskeyService::new(
    @passkey.PasskeyConfig::new("example.com", "Example", "https://example.com"),
  ).with_store(store).with_clock(clock).with_random(random)
  let challenge = passkey.begin_registration()
  println("[passkey] challenge          = " + challenge.challenge)
  println("[passkey] store key          = " + challenge.key)

  // ②a 产出发给浏览器的 `RegistrationOptions`——**LIB-08③**：真实接入方要抄的就是这几步。
  // 🔴 用 `AuthenticatorSelection::passkey()` 才能拿到**可发现凭据（真 passkey）**，
  //    否则只是「绑定式凭据」（`resident_key` 缺省、不可发现）。
  // 🔴 `authenticatorSelection` 在浏览器侧是**对象**、不是字符串（字段 JSON 名见 passkey/types.mbt）。
  // 说明：库**只产出 options 数据结构**；把它序列化成 JSON（camelCase 字段名）并发给前端，
  //      以及前端把 `challenge`（base64url 字符串）转 `ArrayBuffer` 调 `navigator.credentials.create()`，
  //      都是**调用方**的活——库不参与浏览器运行时。
  let user = @passkey.UserInfo::{
    id: b"user-handle-1",
    name: "alice@example.com",
    display_name: Some("Alice"),
  }
  let options = passkey.registration_options(
    challenge,
    user,
    authenticator_selection=Some(@passkey.AuthenticatorSelection::passkey()),
  )
  println("[passkey] options.rp.id      = " + options.rp.id)
  println("[passkey] options.rp.name    = " + options.rp.name)
  println("[passkey] options.user.name  = " + options.user.name)
  println("[passkey] options.challenge  = " + options.challenge)
  println(
    "[passkey] pubKeyCredParams   = n=" +
    options.pub_key_cred_params.length().to_string() +
    " type=" +
    options.pub_key_cred_params[0].type_ +
    " alg=" +
    options.pub_key_cred_params[0].alg.to_string(),
  )
  // 关键：`authenticatorSelection`（浏览器 JSON：`authenticatorSelection`）的取值。
  match options.authenticator_selection {
    Some(sel) =>
      println(
        "[passkey] authSel            = attachment=" +
        sel.authenticator_attachment.unwrap_or("<none>") +
        " residentKey=" +
        sel.resident_key.unwrap_or("<none>") +
        " userVerification=" +
        sel.user_verification.unwrap_or("<none>"),
      )
    None => println("[passkey] authSel            = <none>")
  }

  // 用 contract 的固定 WebAuthn 向量跑完整验签断言集（注册 + 认证 + 负例）。
  let wres = @contract.run_webauthn(() => @passkey.StandardWebAuthnVerifier::new())
  println(
    "[passkey] webauthn contract  = " +
    passed_count(wres).to_string() +
    "/" +
    wres.length().to_string() +
    " passed",
  )

  // ════════ ③ TOTP：enroll → otpauth URI；RFC 6238 向量校验 ════════
  let totp_config = @totp.TotpConfig::new("moonauth-demo", "alice@example.com").with_digits(
    8,
  ).with_period(30).with_algorithm("SHA1")
  let primitive : &@core.TotpPrimitive = @totp.StandardTotpPrimitive::new().with_config(
    totp_config,
  ).with_random(random)
  let totp = @totp.TotpService::new(totp_config).with_clock(clock).with_primitive(
    primitive,
  )
  let enrollment = totp.enroll()
  println("[totp]    otpauth uri         = " + enrollment.uri)
  let verified = totp.verify_at(@contract.rfc6238_sha1_seed(), "94287082", 59L)
  println("[totp]    RFC 6238 @59s       = " + verified.to_string())

  println("=== done: 3/3 flows ran offline ===")
}
