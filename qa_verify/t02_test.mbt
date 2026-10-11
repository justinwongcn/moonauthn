//! moonauth / qa_verify —— T02 对抗性独立验证（oauth + oidc 默认实现）。
//!
//! 覆盖 team-lead 的 §3.1~§3.7：
//! - §3.1 错误向量「只错一处」+ 正对照 + exp/nbf 边界 + leeway + nonce 缺省语义；
//! - §3.2 `exchange` 的 form-encoded 回退分支（含百分号 / `+` 解码、content-type 变体）；
//! - §3.3 JWKS 缓存与轮转（恰好一次 / TTL / with_ttl / 重取失败）；
//! - §3.4 `MooncryptSecretSigner`（ES256 64 字节 r‖s / RS256 / Pem+Der / 非法密钥）；
//! - §3.5 PKCE RFC 7636 与 `core/lexical`（默认序 ≠ 字典序的独立复算）；
//! - §3.6/§3.7 纯度、封闭、零真实网络（grep 层证据见报告，测试层用 MockHttpClient）。
//!
//! 🔴 全部向量离线、确定性：网络走 `@contract.MockHttpClient`，时钟走 `@contract.FixedClock`。
//! 自签向量使用**本文件自带的 P-256 私钥**（运行时派生公钥并组 JWKS），与工程师的固定
//! RS256 向量**互不共享代码路径**——用于独立复算边界语义。

// ════════════════════ 通用助手 ════════════════════

///| 十六进制字符串 → 字节（本地独立实现，不依赖被测包）。
fn t02_hex(s : String) -> Bytes {
  let src = @utf8.encode(s)
  let out : Array[Byte] = []
  let n = src.length()
  let mut i = 0
  while i + 1 < n {
    out.push(((t02_nib(src[i]) << 4) | t02_nib(src[i + 1])).to_byte())
    i = i + 2
  }
  Bytes::from_array(out)
}

///| 单十六进制字符 → 数值。
fn t02_nib(c : Byte) -> Int {
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

///| 按 `.` 切分并取第 `idx` 段（用于比对 JOSE 段）。
fn t02_part(tok : String, idx : Int) -> String {
  let mut i = 0
  let mut res = ""
  for seg in tok.split(".") {
    if i == idx {
      res = seg.to_owned()
    }
    i = i + 1
  }
  res
}

// ════════════════════ 自带 P-256 私钥（自签向量） ════════════════════

///| qa_verify 自带的 P-256 私钥标量（32 字节）。与工程师固定向量无关。
let t02_ec_scalar_hex : String = "1337133713371337133713371337133713371337133713371337133713371337"

///| 构造本地 P-256 私钥（固定标量，必定合法）。
fn t02_ec_key() -> @ecdsa.PrivateKey {
  @ecdsa.PrivateKey::new(t02_hex(t02_ec_scalar_hex)[:], curve=@ecdsa.Curve::P256) catch {
    _ => abort("qa_verify: local P-256 scalar is invalid")
  }
}

///| 本文件固定 JWKS（kid=`qa-k1`，公钥由上面私钥运行时派生）。
fn t02_jwks_response() -> @core.HttpResponse {
  let (x, y) = t02_ec_key().public().xy()
  let body = "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" +
    @oauth.base64url_encode(x) +
    "\",\"y\":\"" +
    @oauth.base64url_encode(y) +
    "\",\"alg\":\"ES256\",\"kid\":\"qa-k1\",\"use\":\"sig\"}]}"
  { status: 200, headers: Map([("Content-Type", "application/json")]), body, }
}

///| 手工组一个 ES256 JWT（header 固定 kid=`qa-k1`，signature = raw r‖s 的 base64url）。
fn t02_sign(payload_json : String) -> String {
  let header = "{\"alg\":\"ES256\",\"typ\":\"JWT\",\"kid\":\"qa-k1\"}"
  let h = @oauth.base64url_encode(@utf8.encode(header))
  let p = @oauth.base64url_encode(@utf8.encode(payload_json))
  let sig = t02_ec_key().sign(@utf8.encode(h + "." + p)[:])
  h + "." + p + "." + @oauth.base64url_encode(sig)
}

///| 固定时钟的 OIDC 验签器。
fn t02_verifier(
  client : &@core.HttpClient,
  now : Int64,
) -> @oidc.JwksIdTokenVerifier {
  @oidc.JwksIdTokenVerifier::new_with_http(client).with_clock(
    @contract.FixedClock::new(now),
  )
}

///| 固定基准时钟（Unix 秒）。
fn t02_now() -> Int64 {
  1700000000L
}

///| 组期望值。
fn t02_exp(
  issuers : Array[String],
  audiences : Array[String],
  nonce : String?,
  leeway : Int,
) -> @core.IdTokenExpectations {
  {
    issuers,
    audiences,
    nonce,
    jwks_uri: Some("mock://jwks"),
    leeway_seconds: Some(leeway),
  }
}

///| 跑一次 verify，返回 `auth_error_code`（成功则 `"no-error"`）。
async fn t02_code(
  v : &@core.IdTokenVerifier,
  token : String,
  exp : @core.IdTokenExpectations,
) -> String {
  try {
    let _ = @core.IdTokenVerifier::verify(v, token, exp)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
}

// 自签 payload 模板（基准 now = t02_now()）。

///| 完全合法（iss/aud/sub/iat/exp/nonce 全对）。
fn t02_payload_valid() -> String {
  "{\"iss\":\"https://issuer.example\",\"aud\":\"client-1\",\"sub\":\"user-1\",\"iat\":1699999000,\"exp\":1700003600,\"nonce\":\"nonce-1\"}"
}

// ════════════════════ §3.1 🔴 错误向量「正确原因」 ════════════════════

///|
/// 🔴 **正对照（自签）**：完全合法的 token 必须验证成功。
/// 若验签器过严（aud/iss 逻辑写错），此用例会失败——它是整套错误向量测试的「非空」前提。
async test "T02 §3.1 self-signed valid token verifies (positive control)" {
  let client = @contract.MockHttpClient::new([t02_jwks_response()])
  let v = t02_verifier(client, t02_now())
  // try 块内只放 verify（其 raise 类型为 AuthError）；断言移到块外，避免 Error 汇合。
  let res = try {
    let claims = v.verify(
      t02_sign(t02_payload_valid()),
      t02_exp(["https://issuer.example"], ["client-1"], Some("nonce-1"), 0),
    )
    (claims.subject, claims.issuer, claims.audience, "ok")
  } catch {
    e => ("", "", [], "error:" + @core.auth_error_code(e))
  }
  let (subj, iss, aud, status) = res
  @debug.assert_eq(status, "ok")
  @debug.assert_eq(subj, "user-1")
  @debug.assert_eq(iss, "https://issuer.example")
  @debug.assert_eq(aud, ["client-1"])
}

///|
/// 🔴 **自签错误向量「只错一处」**：每个向量除目标属性外全部合法，必须命中**对应**错误码。
async test "T02 §3.1 each self-signed single-fault vector maps to its own code" {
  let cases : Array[(String, String, @core.IdTokenExpectations)] = [
    (
      // 只错 iss
      t02_sign(
        "{\"iss\":\"https://evil.example\",\"aud\":\"client-1\",\"sub\":\"user-1\",\"exp\":1700003600,\"nonce\":\"nonce-1\"}",
      ),
      "issuer_mismatch",
      t02_exp(["https://issuer.example"], ["client-1"], Some("nonce-1"), 0),
    ),
    (
      // 只错 aud
      t02_sign(
        "{\"iss\":\"https://issuer.example\",\"aud\":\"client-2\",\"sub\":\"user-1\",\"exp\":1700003600,\"nonce\":\"nonce-1\"}",
      ),
      "audience_mismatch",
      t02_exp(["https://issuer.example"], ["client-1"], Some("nonce-1"), 0),
    ),
    (
      // 只错 nonce
      t02_sign(
        "{\"iss\":\"https://issuer.example\",\"aud\":\"client-1\",\"sub\":\"user-1\",\"exp\":1700003600,\"nonce\":\"nonce-2\"}",
      ),
      "nonce_mismatch",
      t02_exp(["https://issuer.example"], ["client-1"], Some("nonce-1"), 0),
    ),
    (
      // 只错 exp（已过期）
      t02_sign(
        "{\"iss\":\"https://issuer.example\",\"aud\":\"client-1\",\"sub\":\"user-1\",\"exp\":1699999999,\"nonce\":\"nonce-1\"}",
      ),
      "token_expired",
      t02_exp(["https://issuer.example"], ["client-1"], Some("nonce-1"), 0),
    ),
  ]
  for c in cases {
    let (token, want, exp) = c
    let client = @contract.MockHttpClient::new([t02_jwks_response()])
    let v = t02_verifier(client, t02_now())
    @debug.assert_eq(t02_code(v, token, exp), want)
  }
}

///|
/// 🔴 **「只错一处」的严格证明（中和法）**：把「错的那一处」在期望里改成与 token 一致，
/// 该向量必须**验证成功**——若仍失败，说明它其实还错在别处（测试就是「假命中」）。
async test "T02 §3.1 neutralizing the single fault makes each vector pass" {
  // 错 iss → 期望改成 evil
  let bad_iss = t02_sign(
    "{\"iss\":\"https://evil.example\",\"aud\":\"client-1\",\"sub\":\"user-1\",\"exp\":1700003600,\"nonce\":\"nonce-1\"}",
  )
  let c1 = @contract.MockHttpClient::new([t02_jwks_response()])
  @debug.assert_eq(
    t02_code(
      t02_verifier(c1, t02_now()),
      bad_iss,
      t02_exp(["https://evil.example"], ["client-1"], Some("nonce-1"), 0),
    ),
    "no-error",
  )
  // 错 aud → 期望改成 client-2
  let bad_aud = t02_sign(
    "{\"iss\":\"https://issuer.example\",\"aud\":\"client-2\",\"sub\":\"user-1\",\"exp\":1700003600,\"nonce\":\"nonce-1\"}",
  )
  let c2 = @contract.MockHttpClient::new([t02_jwks_response()])
  @debug.assert_eq(
    t02_code(
      t02_verifier(c2, t02_now()),
      bad_aud,
      t02_exp(["https://issuer.example"], ["client-2"], Some("nonce-1"), 0),
    ),
    "no-error",
  )
  // 错 nonce → 期望改成 nonce-2
  let bad_nonce = t02_sign(
    "{\"iss\":\"https://issuer.example\",\"aud\":\"client-1\",\"sub\":\"user-1\",\"exp\":1700003600,\"nonce\":\"nonce-2\"}",
  )
  let c3 = @contract.MockHttpClient::new([t02_jwks_response()])
  @debug.assert_eq(
    t02_code(
      t02_verifier(c3, t02_now()),
      bad_nonce,
      t02_exp(["https://issuer.example"], ["client-1"], Some("nonce-2"), 0),
    ),
    "no-error",
  )
}

///|
/// 🔴 **`bad_sig` 是「纯签名错」的证明**：其 header+payload 段与合法 token **逐字节相同**，
/// 只有第 3 段（签名）不同——排除「其实错在 claims」的可能。
async test "T02 §3.1 contract bad_sig differs from ok ONLY in the signature segment" {
  @debug.assert_eq(
    t02_part(@contract.fixed_token_ok, 0),
    t02_part(@contract.fixed_token_bad_sig, 0),
  )
  @debug.assert_eq(
    t02_part(@contract.fixed_token_ok, 1),
    t02_part(@contract.fixed_token_bad_sig, 1),
  )
  assert_true(
    t02_part(@contract.fixed_token_ok, 2) != t02_part(@contract.fixed_token_bad_sig, 2),
  )
}

///|
/// 🔴 **中和 `bad_sig` 的 payload 后仍失败**（对照）：把 bad_sig 的 payload 段换成合法
/// token 的 payload 段，签名不变 → 仍应 `signature_invalid`，证明错的确实是签名。
async test "T02 §3.1 contract bad_sig stays signature_invalid even with a valid payload" {
  let spliced = t02_part(@contract.fixed_token_bad_sig, 0) +
    "." +
    t02_part(@contract.fixed_token_ok, 1) +
    "." +
    t02_part(@contract.fixed_token_bad_sig, 2)
  let client = @contract.MockHttpClient::new([@contract.jwks_response()])
  let v = t02_verifier(client, @contract.fixed_now_unix())
  @debug.assert_eq(t02_code(v, spliced, @contract.expectations()), "signature_invalid")
}

// ════════════════════ §3.1 边界：exp / nbf / leeway ════════════════════

///|
/// 🔴 **`exp` 恰好等于当前时刻**：按 RFC 7519（current MUST be before exp）应判**过期**。
/// leeway=0，断言 `token_expired`。
async test "T02 §3.1 exp == now is expired (RFC strict)" {
  let tok = t02_sign(
    "{\"iss\":\"https://issuer.example\",\"aud\":\"client-1\",\"sub\":\"user-1\",\"exp\":1700000000,\"nonce\":\"nonce-1\"}",
  )
  let client = @contract.MockHttpClient::new([t02_jwks_response()])
  @debug.assert_eq(
    t02_code(
      t02_verifier(client, t02_now()),
      tok,
      t02_exp(["https://issuer.example"], ["client-1"], Some("nonce-1"), 0),
    ),
    "token_expired",
  )
}

///|
/// **`exp` 恰好比当前时刻大 1 秒**：有效。
async test "T02 §3.1 exp == now + 1 is valid" {
  let tok = t02_sign(
    "{\"iss\":\"https://issuer.example\",\"aud\":\"client-1\",\"sub\":\"user-1\",\"exp\":1700000001,\"nonce\":\"nonce-1\"}",
  )
  let client = @contract.MockHttpClient::new([t02_jwks_response()])
  @debug.assert_eq(
    t02_code(
      t02_verifier(client, t02_now()),
      tok,
      t02_exp(["https://issuer.example"], ["client-1"], Some("nonce-1"), 0),
    ),
    "no-error",
  )
}

///|
/// **`nbf` 恰好等于当前时刻**：按 RFC 7519（current MUST be after or equal）应**有效**。
async test "T02 §3.1 nbf == now is valid (RFC inclusive)" {
  let tok = t02_sign(
    "{\"iss\":\"https://issuer.example\",\"aud\":\"client-1\",\"sub\":\"user-1\",\"nbf\":1700000000,\"exp\":1700003600,\"nonce\":\"nonce-1\"}",
  )
  let client = @contract.MockHttpClient::new([t02_jwks_response()])
  @debug.assert_eq(
    t02_code(
      t02_verifier(client, t02_now()),
      tok,
      t02_exp(["https://issuer.example"], ["client-1"], Some("nonce-1"), 0),
    ),
    "no-error",
  )
}

///|
/// **`nbf` 比当前时刻大 1 秒**：尚未生效 → `token_not_yet_valid`。
async test "T02 §3.1 nbf == now + 1 is not yet valid" {
  let tok = t02_sign(
    "{\"iss\":\"https://issuer.example\",\"aud\":\"client-1\",\"sub\":\"user-1\",\"nbf\":1700000001,\"exp\":1700003600,\"nonce\":\"nonce-1\"}",
  )
  let client = @contract.MockHttpClient::new([t02_jwks_response()])
  @debug.assert_eq(
    t02_code(
      t02_verifier(client, t02_now()),
      tok,
      t02_exp(["https://issuer.example"], ["client-1"], Some("nonce-1"), 0),
    ),
    "token_not_yet_valid",
  )
}

///|
/// **`leeway` 交互**：token 过期 5 秒；leeway=10 应放行，leeway=3 应拒绝。
async test "T02 §3.1 leeway relaxes expiry exactly as configured" {
  let tok = t02_sign(
    "{\"iss\":\"https://issuer.example\",\"aud\":\"client-1\",\"sub\":\"user-1\",\"exp\":1699999995,\"nonce\":\"nonce-1\"}",
  )
  let c_loose = @contract.MockHttpClient::new([t02_jwks_response()])
  @debug.assert_eq(
    t02_code(
      t02_verifier(c_loose, t02_now()),
      tok,
      t02_exp(["https://issuer.example"], ["client-1"], Some("nonce-1"), 10),
    ),
    "no-error",
  )
  let c_tight = @contract.MockHttpClient::new([t02_jwks_response()])
  @debug.assert_eq(
    t02_code(
      t02_verifier(c_tight, t02_now()),
      tok,
      t02_exp(["https://issuer.example"], ["client-1"], Some("nonce-1"), 3),
    ),
    "token_expired",
  )
}

// ════════════════════ §3.1 🔴 nonce 缺省语义 ════════════════════

///|
/// 🔴 **`expect.nonce = None` 必须跳过 nonce 校验**：token 带 nonce 也应通过。
async test "T02 §3.1 expect.nonce=None skips nonce check" {
  let tok = t02_sign(
    "{\"iss\":\"https://issuer.example\",\"aud\":\"client-1\",\"sub\":\"user-1\",\"exp\":1700003600,\"nonce\":\"nonce-1\"}",
  )
  let client = @contract.MockHttpClient::new([t02_jwks_response()])
  @debug.assert_eq(
    t02_code(
      t02_verifier(client, t02_now()),
      tok,
      t02_exp(["https://issuer.example"], ["client-1"], None, 0),
    ),
    "no-error",
  )
}

///|
/// 🔴🔴 **`expect.nonce = Some(x)` 而 token 无 nonce 字段 → 必须拒绝**（放行即漏洞）。
/// 断言 `nonce_mismatch`。
async test "T02 §3.1 🔴 expect.nonce=Some but token has NO nonce is rejected" {
  let tok = t02_sign(
    "{\"iss\":\"https://issuer.example\",\"aud\":\"client-1\",\"sub\":\"user-1\",\"exp\":1700003600}",
  )
  let client = @contract.MockHttpClient::new([t02_jwks_response()])
  @debug.assert_eq(
    t02_code(
      t02_verifier(client, t02_now()),
      tok,
      t02_exp(["https://issuer.example"], ["client-1"], Some("nonce-1"), 0),
    ),
    "nonce_mismatch",
  )
}

// ════════════════════ §3.2 🔴 form-encoded 回退分支 ════════════════════

///| 组一个带显式 content-type 的 200 响应。
fn t02_resp_200(ctype : String, body : String) -> @core.HttpResponse {
  { status: 200, headers: Map([("Content-Type", ctype)]), body, }
}

///|
/// 🔴 **form-encoded 分支确实存在且可用**：content-type 为 form-urlencoded 的响应体
/// 必须被正确解析为 `TokenSet`。
async test "T02 §3.2 form-encoded body parses (branch exists)" {
  let client = @contract.MockHttpClient::new([
    t02_resp_200(
      "application/x-www-form-urlencoded",
      "access_token=at-2&token_type=bearer&expires_in=60&refresh_token=rt-2",
    ),
  ])
  let oauth = @oauth.StandardOAuthAuthCode::new().with_http(client)
  let token = oauth.exchange(@contract.token_exchange_request())
  @debug.assert_eq(token.access_token, "at-2")
  @debug.assert_eq(token.token_type, Some("bearer"))
  @debug.assert_eq(token.expires_in, Some(60))
  @debug.assert_eq(token.refresh_token, Some("rt-2"))
}

///|
/// **content-type 大小写不敏感**（`Application/X-WWW-Form-Urlencoded`）。
async test "T02 §3.2 form branch tolerates mixed-case content-type" {
  let client = @contract.MockHttpClient::new([
    t02_resp_200("Application/X-WWW-Form-Urlencoded", "access_token=at-3&scope=openid"),
  ])
  let oauth = @oauth.StandardOAuthAuthCode::new().with_http(client)
  let token = oauth.exchange(@contract.token_exchange_request())
  @debug.assert_eq(token.access_token, "at-3")
  @debug.assert_eq(token.scope, Some("openid"))
}

///|
/// **content-type 带参数**（`; charset=utf-8`）。
async test "T02 §3.2 form branch tolerates content-type parameters" {
  let client = @contract.MockHttpClient::new([
    t02_resp_200(
      "application/x-www-form-urlencoded; charset=utf-8",
      "access_token=at-4",
    ),
  ])
  let oauth = @oauth.StandardOAuthAuthCode::new().with_http(client)
  let token = oauth.exchange(@contract.token_exchange_request())
  @debug.assert_eq(token.access_token, "at-4")
}

///|
/// **百分号解码 + `+`→空格**：form 值必须被解码（QQ/微信 token 端点常返回转义值）。
async test "T02 §3.2 form values are percent-decoded and + becomes space" {
  let client = @contract.MockHttpClient::new([
    t02_resp_200(
      "application/x-www-form-urlencoded",
      "access_token=at%2D5&scope=openid+email&refresh_token=rt%2Fslug",
    ),
  ])
  let oauth = @oauth.StandardOAuthAuthCode::new().with_http(client)
  let token = oauth.exchange(@contract.token_exchange_request())
  @debug.assert_eq(token.access_token, "at-5")
  @debug.assert_eq(token.scope, Some("openid email"))
  @debug.assert_eq(token.refresh_token, Some("rt/slug"))
}

///|
/// **⚠️ 行为如实记录**：实现**不读 content-type**，而是「先试 JSON、失败再试 form」。
/// 因此 content-type 声称 `application/json` 但体是 form 时，仍会被解析（更宽松）。
/// 此用例锁定该行为，供 ARCH 复核「是否要按 content-type 分派」。
async test "T02 §3.2 implementation ignores content-type (JSON-first trial)" {
  let client = @contract.MockHttpClient::new([
    t02_resp_200(
      "application/json",
      "access_token=at-6&token_type=bearer",
    ),
  ])
  let oauth = @oauth.StandardOAuthAuthCode::new().with_http(client)
  let token = oauth.exchange(@contract.token_exchange_request())
  @debug.assert_eq(token.access_token, "at-6")
}

///|
/// **JSON 体（content-type=json）**仍走 JSON 分支且字段完整。
async test "T02 §3.2 JSON body still parses under application/json" {
  let client = @contract.MockHttpClient::new([
    t02_resp_200(
      "application/json; charset=utf-8",
      "{\"access_token\":\"at-7\",\"expires_in\":99}",
    ),
  ])
  let oauth = @oauth.StandardOAuthAuthCode::new().with_http(client)
  let token = oauth.exchange(@contract.token_exchange_request())
  @debug.assert_eq(token.access_token, "at-7")
  @debug.assert_eq(token.expires_in, Some(99))
}

///|
/// **form 体缺 `access_token`** → `ParseError`（不应静默返回空 TokenSet）。
async test "T02 §3.2 form body missing access_token raises parse_error" {
  let client = @contract.MockHttpClient::new([
    t02_resp_200("application/x-www-form-urlencoded", "token_type=bearer&state=x"),
  ])
  let oauth = @oauth.StandardOAuthAuthCode::new().with_http(client)
  let code = try {
    let _ = oauth.exchange(@contract.token_exchange_request())
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "parse_error")
}

// ════════════════════ §3.3 JWKS 缓存与轮转 ════════════════════

///|
/// **kid 未命中 → 恰好重取一次**：缓存命中 kid-1 后，用 kid-2 触发一次重取并成功；
/// 断言队列恰好被消费 1 条。
async test "T02 §3.3 unknown kid refetches exactly once" {
  let client = @contract.MockHttpClient::new([
    @contract.jwks_response(),
    @contract.jwks_rotated_response(),
  ])
  let v = t02_verifier(client, @contract.fixed_now_unix())
  let _ = v.verify(@contract.fixed_token_ok, @contract.expectations())
  @debug.assert_eq(client.remaining(), 1)
  let _ = v.verify(@contract.fixed_token_kid2(), @contract.expectations())
  @debug.assert_eq(client.remaining(), 0)
}

///|
/// **重取失败不静默**：缓存 kid-1 后，用 kid-2 触发重取，但重取返回仍在的旧 JWKS
/// （不含 kid-2）→ 无可选 key → `KeyError`（**绝不**用旧 key 硬验）。
async test "T02 §3.3 refetch that still lacks the kid raises key_error (no silent fallback)" {
  let client = @contract.MockHttpClient::new([
    @contract.jwks_response(),
    @contract.jwks_response(), // 重取回来的还是 kid-1
  ])
  let v = t02_verifier(client, @contract.fixed_now_unix())
  let _ = v.verify(@contract.fixed_token_ok, @contract.expectations())
  @debug.assert_eq(
    t02_code(v, @contract.fixed_token_kid2(), @contract.expectations()),
    "key_error",
  )
}

///|
/// **TTL 边界**：`cache_valid` 用 `now - cached_at < ttl`。ttl=60 时，
/// 前进 59 秒 → 命中缓存（不重取）；前进到 60 秒 → 过期重取。
async test "T02 §3.3 ttl boundary is strict (59 valid, 60 expired)" {
  let clock = @contract.FixedClock::new(@contract.fixed_now_unix())
  let client = @contract.MockHttpClient::new([
    @contract.jwks_response(),
    @contract.jwks_response(),
  ])
  let v = @oidc.JwksIdTokenVerifier::new_with_http(client)
    .with_clock(clock)
    .with_ttl(60L)
  let _ = v.verify(@contract.fixed_token_ok, @contract.expectations())
  @debug.assert_eq(client.remaining(), 1)
  clock.advance(59L)
  let _ = v.verify(@contract.fixed_token_ok, @contract.expectations())
  @debug.assert_eq(client.remaining(), 1)
  clock.advance(1L) // 累计 60
  let _ = v.verify(@contract.fixed_token_ok, @contract.expectations())
  @debug.assert_eq(client.remaining(), 0)
}

///|
/// **重取失败（非 2xx）→ `KeyError`，且缓存不被污染**：先成功缓存一次，
/// 再让 TTL 过期并让重取返回 500 → `KeyError`。
async test "T02 §3.3 failing refetch surfaces key_error" {
  let clock = @contract.FixedClock::new(@contract.fixed_now_unix())
  let client = @contract.MockHttpClient::new([
    @contract.jwks_response(),
    @contract.status_response(500, "boom"),
  ])
  let v = @oidc.JwksIdTokenVerifier::new_with_http(client)
    .with_clock(clock)
    .with_ttl(60L)
  let _ = v.verify(@contract.fixed_token_ok, @contract.expectations())
  clock.advance(61L)
  @debug.assert_eq(
    t02_code(v, @contract.fixed_token_ok, @contract.expectations()),
    "key_error",
  )
}

// ════════════════════ §3.4 MooncryptSecretSigner ════════════════════

///|
/// 🔴 **ES256 签名字节长度运行时实测 = 64**（raw `r‖s`，非 DER）——Apple client secret 前提。
/// 签名须能被**独立派生的公钥**验签通过。
async test "T02 §3.4 ES256 signature is exactly 64 bytes (raw r||s) and verifies" {
  let signer = @oauth.MooncryptSecretSigner::new()
  let sk = t02_ec_key()
  let msg = @utf8.encode("qa_verify-es256")
  let sig = signer.sign(
    @core.SignAlg::ES256,
    @core.SigningKey::Der(t02_hex(t02_ec_scalar_hex)),
    msg,
  )
  @debug.assert_eq(sig.length(), 64)
  // 用运行时从私钥派生的公钥独立验签
  assert_true(sk.public().verify(msg[:], sig[:]))
}

///|
/// **ES256 PEM（PKCS#8）路径**：同一私钥的 PEM 形态同样签出 64 字节可验签签名。
async test "T02 §3.4 ES256 accepts PEM key and yields 64-byte sig" {
  let signer = @oauth.MooncryptSecretSigner::new()
  let sk = t02_ec_key()
  // mooncrypt 无常量 PEM 导出；用本地最小 PEM 包装 PKCS#8 体（标准 base64）。
  let pkcs8 = @oauth.base64_std_encode(sk.bytes())
  let pem = @core.SigningKey::Pem(
    "-----BEGIN PRIVATE KEY-----\n" + pkcs8 + "\n-----END PRIVATE KEY-----\n",
  )
  let msg = @utf8.encode("qa_verify-es256-pem")
  let sig = signer.sign(@core.SignAlg::ES256, pem, msg)
  @debug.assert_eq(sig.length(), 64)
  assert_true(sk.public().verify(msg[:], sig[:]))
}

///| 固定 RS256（RSA-2048）私钥 PKCS#1 体（标准 base64；公开测试密钥）。
let t02_rsa_pkcs1_b64 : String = "MIIEpAIBAAKCAQEAoT66btCxc2vTvxzdFOrUT5eZkcp1PAGbKYxJREtQG3DOCNHc8l9J1a2kN1BLVeLphMwuWBFKUYANkiKLaMDLpeSlW06n8uEborA+LE7b+q8hL007YN6f850j17/Vq41FuvDYN6xSy8O3WIRzza9znhgTq2MukyzrHOiGijI7L4SusMsOKKQGV2DiZIjNYn8bfhUnxJRyKSFNqBQ/wOZBUo38pHut2ojX4SNDLx7YvrbtCVYE+1sp79THzp8rzaLhIwEf5QLq8IojLVf041eLp28Nlu5qHMPC1lnSO1kQpmPnYju1aPKYNBcGPniX/rzGBUOywLV8UMUHDJZySnjSXwIDAQABAoIBAB/GPzHIITfH902RUAWnstfOXX5Lwadl/6AD24pANxR5ObimNl5ypZecZKBby8Ssduzq2XUUTytZSxNRiFxHpbnWoTkpelITxwDbrxzHG3U+XpE2LG3N4QI+JIqG7IGmUKfifxEVfalWs4IXc8SD/woX34RmAo8RCnHDZoPEG0KlGDROGKKj7/iySxdku9Z4kK5nip7pQIubIXtVFKBBiiFmPzwTh2lH7k52/53luuy2mQmCXavY5xWaB6SN/PQuoPE7Di8w9OoXPKMoTRzfBOSCs1V1vMMVaKtk8F9WP9uGFTGwV/NTJDlzH3/sYkvyR2JIrIMx79UbMU7GkrKev4kCgYEA0bt1iZTln1KypvHshkfUZD7vfa21tWJm+/DR+lBwgnWB2qXgqer7lxaFkGeGf5LJCaeapMAogKmJyKmpeu2OPW0xeyIpy2n1jEq7Bg1Bziia7uQkNJGZJfxo5c/LwHa2JMPDlg1YW0TaDU0aeQMLeAm8XnQ8Or8p3ZNb1d6hj9cCgYEAxND5Kko/7nbI27hjx02kjs8a3E0WbhpWHSMNqaVsQLQG23gNyffUs8PcP0juZGb7BpMm3F3WKPjiFI0bAcc4qizYqiNaIIabbwEKw9t205PKCw0Kh4OSK9icX98x8lcbdGIocUWOzyyufO5lhTtfF+o456c5D1FC3RPbrkSLILkCgYBhkWukjXglHjuuHm2CKnhMClsvhFg8AYMXQXjtke5FQpUeOnzBj2drajbIbuDLCGYt76Kpchtlf3lxuDv3y/uX5+xU9BetYaWxljJbJl+uoIUzDT8qlXFBkqLaBkkrSA6EG+4pKBwqmWU3Ot9N3HTBawYOitRaIARB6AOZAvD2EQKBgQCDgEy6oNmObvdNNyoTpCDq+h2sTCVMc3ROC3m5e7mUkbRzNwefhmMrqRWjgwslMllOz0sLufa5cXE84frFeWK28TfilbRGPynjRQL4Uc5XF0vLjm8WlCY5/YSd2fb5QJIrdNootJzyd5wuBOr31e93fxt+TBCn11ehdv80tL9woQKBgQDGX9ASVzVzflcCGhAK+1qQEdt52rR82JVsqzTEtTJE06CjZIIRpBBFuwNNbO7pJJMqNdieEWr3OcZSIQLNAFd4rCYR/+gRPwXUNf1kuRGs4ggxqjzqi0xWKMJns0t5gH0fjwdGIf4JaIDPknVb+guF0HWI3zFaVebjtJUHsLuzyQ=="

///|
/// **RS256 自签自验**：PKCS#1 DER 形态 → 256 字节签名，自派生公钥验签通过；
/// 且 PKCS#1 v1.5 对同输入**确定性**（两次签名相同）。
async test "T02 §3.4 RS256 signs deterministically (256 bytes) and verifies" {
  let signer = @oauth.MooncryptSecretSigner::new()
  let der = @oauth.base64_std_decode(t02_rsa_pkcs1_b64) catch {
    _ => abort("qa_verify: bad rsa key base64")
  }
  let msg = @utf8.encode("qa_verify-rs256")
  let s1 = signer.sign(@core.SignAlg::RS256, @core.SigningKey::Der(der), msg)
  let s2 = signer.sign(@core.SignAlg::RS256, @core.SigningKey::Der(der), msg)
  @debug.assert_eq(s1.length(), 256)
  @debug.assert_eq(s1, s2)
  // 自派生公钥验签
  let (n, e, _d) = t02_rsa_parts(der)
  let pk = @rsa.PublicKey::new(
    n[:],
    e[:],
    digest=@rsa.Digest::Sha256,
    scheme=@rsa.Scheme::Pkcs1,
  ) catch {
    _ => abort("qa_verify: rsa public key build failed")
  }
  assert_true(pk.verify(msg[:], s1[:]))
}

///|
/// **RS256 PEM（PKCS#1）路径**同样可加载。
async test "T02 §3.4 RS256 accepts a PKCS#1 PEM key" {
  let signer = @oauth.MooncryptSecretSigner::new()
  let pem = @core.SigningKey::Pem(
    "-----BEGIN RSA PRIVATE KEY-----\n" +
    t02_rsa_pkcs1_b64 +
    "\n-----END RSA PRIVATE KEY-----\n",
  )
  let msg = @utf8.encode("qa_verify-rs256-pem")
  let sig = signer.sign(@core.SignAlg::RS256, pem, msg)
  @debug.assert_eq(sig.length(), 256)
}

///| 读 `buf[pos]` 处 TLV，返回 `(tag, content_start, content_len, next_pos)`。
fn t02_tlv(buf : Bytes, pos : Int) -> (Int, Int, Int, Int) {
  let tag = buf[pos].to_int()
  let mut p = pos + 1
  let l0 = buf[p].to_int()
  p = p + 1
  let len = if (l0 & 0x80) == 0 {
    l0
  } else {
    let cnt = l0 & 0x7F
    let mut v = 0
    let mut k = 0
    while k < cnt {
      v = (v << 8) | buf[p].to_int()
      p = p + 1
      k = k + 1
    }
    v
  }
  (tag, p, len, p + len)
}

///| 简易 PKCS#1 私有材料提取（本地独立实现，仅用于验签公钥派生）。
fn t02_rsa_parts(der : Bytes) -> (Bytes, Bytes, Bytes) {
  // 外层 SEQUENCE：取内容区间，再逐个读 INTEGER。
  let (_t0, s0, _l0, e0) = t02_tlv(der, 0)
  let ints : Array[Bytes] = []
  let mut pos = s0
  while pos < e0 && ints.length() < 4 {
    let (t, s, l, nx) = t02_tlv(der, pos)
    if t == 0x02 {
      ints.push(der[s : s + l].to_owned())
    }
    pos = nx
  }
  if ints.length() >= 4 {
    (t02_strip0(ints[1]), t02_strip0(ints[2]), t02_strip0(ints[3]))
  } else {
    (Bytes::from_array([]), Bytes::from_array([]), Bytes::from_array([]))
  }
}

///| 去掉前导 0x00。
fn t02_strip0(b : Bytes) -> Bytes {
  let mut s = 0
  while s + 1 < b.length() && b[s] == b'\x00' {
    s = s + 1
  }
  b[s:].to_owned()
}

///|
/// **非法密钥 → `KeyError`**（不是 panic、不是 `ParseError`）。
async test "T02 §3.4 malformed keys raise key_error" {
  let signer = @oauth.MooncryptSecretSigner::new()
  let msg = @utf8.encode("x")
  let c1 = try {
    let _ = signer.sign(@core.SignAlg::ES256, @core.SigningKey::Der(b"\x00\x01"), msg)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(c1, "key_error")
  let c2 = try {
    let _ = signer.sign(@core.SignAlg::RS256, @core.SigningKey::Der(b"not-der"), msg)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(c2, "key_error")
  let c3 = try {
    let _ = signer.sign(
      @core.SignAlg::RS256,
      @core.SigningKey::Pem("-----BEGIN X-----\n@@@@\n-----END X-----\n"),
      msg,
    )
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(c3, "key_error")
}

// ════════════════════ §3.5 PKCE + lexical ════════════════════

///|
/// **RFC 7636 附录 B 官方向量独立复算**（不引用工程师的断言）。
async test "T02 §3.5 PKCE RFC 7636 appendix B (independent)" {
  let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  let expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
  let got = @oauth.s256_challenge(verifier)
  @debug.assert_eq(got, expected_challenge)
  // 独立复算：base64url(sha256(verifier)) 应等于上面的挑战
  let manual = @oauth.base64url_encode(
    @otp.sha256(@utf8.encode(verifier)[:]),
  )
  @debug.assert_eq(manual, expected_challenge)
  assert_true(@oauth.verify_s256(verifier, expected_challenge))
  assert_false(@oauth.verify_s256("wrong", expected_challenge))
}

///|
/// 🔴 **行为锁非空（独立复算）**：默认 `String::compare` 的序 ≠ 字典序期望序。
/// 若未来工具链把默认比较改成字典序，本用例会失败——证明该快照真的能预警。
async test "T02 §3.5 default String order differs from lexicographic (lock is live)" {
  // 默认比较：长度优先 → "zeta"(4) < "alpha"(5)
  assert_true("zeta".compare("alpha") < 0)
  // 字典序：'z' > 'a' → "zeta" > "alpha"
  assert_true(@core.lexicographic_compare("zeta", "alpha") > 0)
  // 默认 sort 与字典序 sort 在等长/异长混合输入上确实不同
  let xs : Array[String] = ["zeta", "alpha", "beta"]
  let default_sorted = xs.copy()
  default_sorted.sort()
  let lex_sorted = @core.sort_lexicographic(xs)
  assert_true(default_sorted != lex_sorted)
  @debug.assert_eq(lex_sorted, ["alpha", "beta", "zeta"])
}

///|
/// **`sort_lexicographic` 不改原数组**（实测）。
async test "T02 §3.5 sort_lexicographic does not mutate its input" {
  let original : Array[String] = ["zeta", "alpha", "beta"]
  let _ = @core.sort_lexicographic(original)
  @debug.assert_eq(original, ["zeta", "alpha", "beta"])
}
