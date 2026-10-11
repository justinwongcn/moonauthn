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
