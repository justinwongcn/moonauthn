//! moonauth / oidc —— 黑盒测试：`JwksIdTokenVerifier` 的验签、缓存与轮转。
//!
//! 🔴 本文件是**黑盒测试**（`*_test.mbt`）：被测包以 `@oidc.` 限定引用。
//!
//! 全部向量来自 `@contract` 的**固定字面量**（固定 JWKS + 固定 id_token），
//! 配合 `@contract.MockHttpClient`（预置响应，**零真实网络**）与
//! `@contract.FixedClock`（固定时钟），使验签结果完全确定：
//! - 正常向量 → 归一化 `IdTokenClaims`；
//! - 错误向量 → 分别命中 `SignatureInvalid` / `TokenExpired` / `IssuerMismatch` /
//!   `AudienceMismatch` / `NonceMismatch`；
//! - **JWKS 轮转**：先以 kid-1 填充缓存，再以 kid-2 触发「未命中 → 重取」。

///|
/// 构造「固定时钟 + 预置 HTTP」的验签器，供各用例复用。
fn verifier_for(
  client : &@core.HttpClient,
  now : Int64,
) -> @oidc.JwksIdTokenVerifier {
  @oidc.JwksIdTokenVerifier::new_with_http(client).with_clock(
    @contract.FixedClock::new(now),
  )
}

// ════════ 正常命中 ════════

///|
/// 固定 JWKS + 固定 id_token → 确定性的归一化 claims（无 `@json.Json` 泄漏）。
async test "jwks verifier: fixed vector yields deterministic claims" {
  let client = @contract.MockHttpClient::new([@contract.jwks_response()])
  let v = verifier_for(client, @contract.fixed_now_unix())
  let claims = v.verify(@contract.fixed_token_ok, @contract.expectations())
  @debug.assert_eq(claims.subject, "user-1")
  @debug.assert_eq(claims.issuer, "https://issuer.example")
  @debug.assert_eq(claims.audience, ["client-1"])
  @debug.assert_eq(claims.expires_at, 1700003600L)
  @debug.assert_eq(claims.issued_at, 1699999000L)
  @debug.assert_eq(claims.nonce, Some("nonce-1"))
  @debug.assert_eq(claims.email, Some("alice@example.com"))
  @debug.assert_eq(claims.email_verified, Some(true))
  // 附加声明以字符串视图进 `raw`（编译期即保证无第三方类型）
  @debug.assert_eq(claims.raw.get("email"), Some("alice@example.com"))
  @debug.assert_eq(claims.raw.get("email_verified"), Some("true"))
  // 只抓取一次 JWKS（缓存生效）
  @debug.assert_eq(client.remaining(), 0)
}

///|
/// 相同输入 → 等价输出（确定性重放）：两个独立实例产出相同 claims。
async test "jwks verifier: repeated verification is deterministic" {
  let c1 = @contract.MockHttpClient::new([@contract.jwks_response()])
  let c2 = @contract.MockHttpClient::new([@contract.jwks_response()])
  let a = verifier_for(c1, @contract.fixed_now_unix()).verify(
    @contract.fixed_token_ok,
    @contract.expectations(),
  )
  let b = verifier_for(c2, @contract.fixed_now_unix()).verify(
    @contract.fixed_token_ok,
    @contract.expectations(),
  )
  @debug.assert_eq(a.raw, b.raw)
  @debug.assert_eq(a.expires_at, b.expires_at)
  @debug.assert_eq(a.audience, b.audience)
}

// ════════ 错误向量 ════════

///|
/// 每条错误向量分别命中其分类码。
async test "jwks verifier: each error vector maps to its auth code" {
  let vectors : Array[(String, String)] = [
    (@contract.fixed_token_bad_sig, "signature_invalid"),
    (@contract.fixed_token_expired, "token_expired"),
    (@contract.fixed_token_bad_iss, "issuer_mismatch"),
    (@contract.fixed_token_bad_aud, "audience_mismatch"),
    (@contract.fixed_token_bad_nonce, "nonce_mismatch"),
  ]
  for pair in vectors {
    let (token, want) = pair
    let client = @contract.MockHttpClient::new([@contract.jwks_response()])
    let v = verifier_for(client, @contract.fixed_now_unix())
    let got = try {
      let _ = v.verify(token, @contract.expectations())
      "no-error"
    } catch {
      e => @core.auth_error_code(e)
    }
    @debug.assert_eq(got, want)
  }
}

///|
/// 缺少 `jwks_uri` → `InvalidInput`（在触网之前即拒绝）。
async test "jwks verifier: missing jwks_uri is rejected as invalid_input" {
  let client = @contract.MockHttpClient::new([])
  let v = verifier_for(client, @contract.fixed_now_unix())
  let exp : @core.IdTokenExpectations = {
    issuers: ["https://issuer.example"],
    audiences: ["client-1"],
    nonce: Some("nonce-1"),
    jwks_uri: None,
    leeway_seconds: Some(0),
    algorithms: [],
  }
  let code = try {
    let _ = v.verify(@contract.fixed_token_ok, exp)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "invalid_input")
}

///|
/// JWKS 响应非 2xx → `KeyError`。
async test "jwks verifier: non-2xx JWKS fetch maps to key_error" {
  let client = @contract.MockHttpClient::new([
    @contract.status_response(500, "boom"),
  ])
  let v = verifier_for(client, @contract.fixed_now_unix())
  let code = try {
    let _ = v.verify(@contract.fixed_token_ok, @contract.expectations())
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "key_error")
}

// ════════ JWKS 缓存与轮转 ════════

///|
/// **轮转**：缓存里找不到 token 的 `kid` 时强制重取一次 JWKS，换 `kid` 后仍能验签成功。
async test "jwks verifier: rotation refetches when the kid is unknown" {
  let client = @contract.MockHttpClient::new([
    @contract.jwks_response(),
    @contract.jwks_rotated_response(),
  ])
  let v = verifier_for(client, @contract.fixed_now_unix())
  // 第一次：kid=test-rsa-1 —— 抓取并缓存（消费 1 条响应）
  let c1 = v.verify(@contract.fixed_token_ok, @contract.expectations())
  @debug.assert_eq(c1.subject, "user-1")
  @debug.assert_eq(client.remaining(), 1)
  // 第二次：kid=test-rsa-2 —— 缓存未命中 → 重取 → 命中（消费第 2 条响应）
  let c2 = v.verify(@contract.fixed_token_kid2(), @contract.expectations())
  @debug.assert_eq(c2.subject, "user-1")
  @debug.assert_eq(client.remaining(), 0)
}

///|
/// **TTL**：由注入时钟判定；未过期命中缓存不重取，过期后重取。
async test "jwks verifier: cache honours the injected ttl" {
  let clock = @contract.FixedClock::new(@contract.fixed_now_unix())
  let client = @contract.MockHttpClient::new([
    @contract.jwks_response(),
    @contract.jwks_response(),
  ])
  let v = @oidc.JwksIdTokenVerifier::new_with_http(client)
    .with_clock(clock)
    .with_ttl(60L)
  // 首次抓取
  let _ = v.verify(@contract.fixed_token_ok, @contract.expectations())
  @debug.assert_eq(client.remaining(), 1)
  // 未过期：命中缓存，不再抓取
  clock.advance(10L)
  let _ = v.verify(@contract.fixed_token_ok, @contract.expectations())
  @debug.assert_eq(client.remaining(), 1)
  // 超过 TTL：重取
  clock.advance(60L)
  let _ = v.verify(@contract.fixed_token_ok, @contract.expectations())
  @debug.assert_eq(client.remaining(), 0)
}

// ════════ 契约：对默认实现跑参数化断言集 ════════

///|
/// `IdTokenVerifier` 契约对**库自实现**（`JwksIdTokenVerifier`）100% 通过。
///
/// 🔴 契约函数只调用一次 `make()`，对同一实例触发 6 次 `verify`；所有固定 token 的
/// `kid` 相同（`test-rsa-1`），故首次抓取后全部命中缓存——只需预置 1 条 JWKS 响应。
async test "id_token contract: JwksIdTokenVerifier passes every case" {
  let cases = @contract.run_id_token(fn() {
    let client = @contract.MockHttpClient::new([@contract.jwks_response()])
    let subject : &@core.IdTokenVerifier = @oidc.JwksIdTokenVerifier::new_with_http(
      client,
    ).with_clock(@contract.FixedClock::new(@contract.fixed_now_unix()))
    subject
  })
  @contract.assert_all_pass(cases)
}

// ════════ 现签 ES256 向量：算法白名单 + `exp` 必须存在 ════════
//
// 契约包的固定 token 只有 RS256 且全部带 `exp`；这两条 P1 防线需要**不带 exp** 与
// **非白名单算法**的向量，故在测试内用 `@ecdsa`（RFC 6979 确定性签名，raw r‖s =
// JOSE 线格式）现签。P-256 私钥标量为固定字节，全程零随机、可重放。

///|
/// 测试专用 P-256 私钥（固定标量 0x01..0x20，合法：1 ≤ d < n）。
fn es256_test_key() -> @ecdsa.PrivateKey raise @core.AuthError {
  let scalar : Bytes = Bytes::from_array([
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
  ])
  @ecdsa.PrivateKey::new(scalar[:]) catch {
    _ => raise @core.KeyError("moonauth(test): bad test scalar")
  }
}

///|
/// RFC 4648 §5 base64url（无填充）——仅测试用。
fn test_b64url(data : Bytes) -> String {
  let alphabet = @utf8.encode(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
  )
  let out : Array[Byte] = []
  let n = data.length()
  let mut i = 0
  while i < n {
    let has1 = i + 1 < n
    let has2 = i + 2 < n
    let b0 = data[i].to_int()
    let b1 = if has1 { data[i + 1].to_int() } else { 0 }
    let b2 = if has2 { data[i + 2].to_int() } else { 0 }
    out.push(alphabet[b0 >> 2])
    out.push(alphabet[((b0 & 0x03) << 4) | (b1 >> 4)])
    if has1 {
      out.push(alphabet[((b1 & 0x0F) << 2) | (b2 >> 6)])
    }
    if has2 {
      out.push(alphabet[b2 & 0x3F])
    }
    i = i + 3
  }
  @utf8.decode_lossy(Bytes::from_array(out))
}

///|
/// 由测试私钥构造的 EC JWKS 响应（`kid = ec-test-1`）。
fn ec_jwks_response() -> @core.HttpResponse raise @core.AuthError {
  let key = es256_test_key().public()
  let (x, y) = key.xy()
  let body = "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"alg\":\"ES256\",\"x\":\"" +
    test_b64url(x) +
    "\",\"y\":\"" +
    test_b64url(y) +
    "\",\"kid\":\"ec-test-1\",\"use\":\"sig\"}]}"
  { status: 200, headers: Map([("Content-Type", "application/json")]), body }
}

///|
/// 现签一枚 ES256 id_token（`kid = ec-test-1`）。`payload` 由调用方拼（决定有无 `exp`）。
fn mint_es256(payload : String) -> String raise @core.AuthError {
  let header = "{\"alg\":\"ES256\",\"typ\":\"JWT\",\"kid\":\"ec-test-1\"}"
  let signing_input = test_b64url(@utf8.encode(header)) +
    "." +
    test_b64url(@utf8.encode(payload))
  let sig = @spec.Signer::sign(es256_test_key(), @utf8.encode(signing_input)[:])
  signing_input + "." + test_b64url(sig)
}

///|
/// 与现签向量配套的期望值（`algorithms` 由用例决定）。
fn ec_expectations(algorithms : Array[String]) -> @core.IdTokenExpectations {
  {
    issuers: ["https://issuer.example"],
    audiences: ["client-1"],
    nonce: Some("nonce-1"),
    jwks_uri: Some("mock://jwks"),
    leeway_seconds: Some(0),
    algorithms,
  }
}

///|
/// 基准 payload（`exp` 在 FixedClock 之后，未过期）。
let ec_payload_ok : String = "{\"iss\":\"https://issuer.example\",\"aud\":\"client-1\",\"sub\":\"user-1\",\"iat\":1699999000,\"exp\":1700003600,\"nonce\":\"nonce-1\"}"

///|
/// 🔴 正例（白名单对照组）：带 `exp` 的 ES256 token 在空白名单下通过全链路——
/// 证明现签链路本身有效，排除下面负例「因向量坏而碰巧通过」的可能。
async test "jwks verifier: freshly minted ES256 token with exp verifies" {
  let client = @contract.MockHttpClient::new([ec_jwks_response()])
  let v = verifier_for(client, @contract.fixed_now_unix())
  let claims = v.verify(mint_es256(ec_payload_ok), ec_expectations([]))
  @debug.assert_eq(claims.subject, "user-1")
  @debug.assert_eq(claims.expires_at, 1700003600L)
}

///|
/// 🔴 白名单正例：`algorithms: ["ES256"]` 精确接受现签算法。
async test "jwks verifier: allowlist accepts the listed algorithm" {
  let client = @contract.MockHttpClient::new([ec_jwks_response()])
  let v = verifier_for(client, @contract.fixed_now_unix())
  let claims = v.verify(
    mint_es256(ec_payload_ok),
    ec_expectations(["ES256"]),
  )
  @debug.assert_eq(claims.subject, "user-1")
}

///|
/// 🔴 RFC 8725 §3.1：token 头声明的算法不在白名单 → `unsupported_alg`（不触网）。
async test "jwks verifier: algorithm outside the allowlist is rejected" {
  // RS256 契约向量 vs 仅允许 ES256 的白名单。
  let client = @contract.MockHttpClient::new([])
  let v = verifier_for(client, @contract.fixed_now_unix())
  let code = try {
    let _ = v.verify(@contract.fixed_token_ok, ec_expectations(["ES256"]))
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "unsupported_alg")
}

///|
/// 🔴 OIDC Core：`exp` 为 REQUIRED——缺失即拒绝，不得静默放行。
async test "jwks verifier: token without exp is rejected" {
  let payload = "{\"iss\":\"https://issuer.example\",\"aud\":\"client-1\",\"sub\":\"user-1\",\"iat\":1699999000,\"nonce\":\"nonce-1\"}"
  let client = @contract.MockHttpClient::new([ec_jwks_response()])
  let v = verifier_for(client, @contract.fixed_now_unix())
  let code = try {
    let _ = v.verify(mint_es256(payload), ec_expectations([]))
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "parse_error")
}

// ════════ 缓存健壮性：坏体不入缓存 / 强制重取节流 / 空期望 fail-closed ════════

///|
/// 🔴 200 + 不可解析体（网关故障页）→ `key_error` 且**不写入缓存**：
/// 第二次 verify 仍会重新抓取（错误可自愈），而不是拿坏体撞满一个 TTL。
async test "jwks verifier: unparseable 200 body is not cached" {
  let bad : @core.HttpResponse = {
    status: 200,
    headers: Map([("Content-Type", "text/html")]),
    body: "<html>blocked by captive portal</html>",
  }
  let client = @contract.MockHttpClient::new([bad, bad])
  let v = verifier_for(client, @contract.fixed_now_unix())
  for _i in [1, 2] {
    let code = try {
      let _ = v.verify(@contract.fixed_token_ok, @contract.expectations())
      "no-error"
    } catch {
      e => @core.auth_error_code(e)
    }
    @debug.assert_eq(code, "key_error")
  }
  // 两次 verify 各抓取一次（坏体未入缓存，第二次没有「命中缓存」可依赖）。
  @debug.assert_eq(client.recorded_requests().length(), 2)
}

///|
/// 🔴 强制重取节流：60 秒窗口内的第二次 kid 未命中**不再出站**（防伪造 kid 放大）。
async test "jwks verifier: forced refetch is throttled within the window" {
  let client = @contract.MockHttpClient::new([
    @contract.jwks_response(),
    @contract.jwks_response(),
  ])
  let v = verifier_for(client, @contract.fixed_now_unix())
  // 第一次 kid-2：缓存未命中 → 允许强制重取（两次出站后仍无 kid-2）→ key_error。
  let first = try {
    let _ = v.verify(@contract.fixed_token_kid2(), @contract.expectations())
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(first, "key_error")
  // 第二次 kid-2（时钟未推进）：命中缓存但选不到键 → 节流生效，不再出站 → key_error。
  let second = try {
    let _ = v.verify(@contract.fixed_token_kid2(), @contract.expectations())
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(second, "key_error")
  // 出站请求恰好 2 次（无节流时第二次会再发 1 次强制重取，共 3 次）。
  @debug.assert_eq(client.recorded_requests().length(), 2)
}

///|
/// 🔴 fail-closed：空 `issuers` / 空 `audiences` 一律拒绝（不存在合法的「跳过校验」）。
async test "jwks verifier: empty issuers or audiences are rejected" {
  let client = @contract.MockHttpClient::new([])
  let v = verifier_for(client, @contract.fixed_now_unix())
  let base : @core.IdTokenExpectations = {
    issuers: ["https://issuer.example"],
    audiences: ["client-1"],
    nonce: None,
    jwks_uri: Some("mock://jwks"),
    leeway_seconds: Some(0),
    algorithms: ["RS256"],
  }
  let no_issuers = { ..base, issuers: [] }
  let no_audiences = { ..base, audiences: [] }
  for exp in [no_issuers, no_audiences] {
    let code = try {
      let _ = v.verify(@contract.fixed_token_ok, exp)
      "no-error"
    } catch {
      e => @core.auth_error_code(e)
    }
    @debug.assert_eq(code, "invalid_input")
  }
}

///|
/// 🔴 轮转契约：kid 未命中 → 恰好强制重取一次 → 命中新 kid——provider 轮换签名
/// 密钥后，同一验签器实例无需重建即可继续验签。
async test "id_token contract: rotation refetches once and continues" {
  let cases = @contract.run_id_token_rotation(fn() {
    let client = @contract.MockHttpClient::new([
      @contract.jwks_response(),
      @contract.jwks_rotated_response(),
    ])
    let subject : &@core.IdTokenVerifier = @oidc.JwksIdTokenVerifier::new_with_http(
      client,
    ).with_clock(@contract.FixedClock::new(@contract.fixed_now_unix()))
    subject
  })
  @contract.assert_all_pass(cases)
}
