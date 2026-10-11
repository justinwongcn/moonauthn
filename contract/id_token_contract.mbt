//! moonauth / contract —— `IdTokenVerifier` 的参数化契约（SDK-04 / LIB-17）。
//!
//! 契约函数 `run(make)` 把**同一套断言**跑在任意实现上：
//! - 库自实现：`@oidc.JwksIdTokenVerifier`；
//! - 官方 SDK 适配层：任何实现了 `@core.IdTokenVerifier` 的包。
//!
//! ## 固定向量（离线确定性，LIB-15 ③）
//! 全部向量是**字面量**（固定 RSA 公钥 + 固定 JWKS + 固定 id_token），**零真实网络**：
//! 调用方只需把被测实现接到一个返回 `jwks_response()` 的 `HttpClient`（如
//! `@contract.MockHttpClient`）与固定时钟即可。
//!
//! 断言集：正常命中 / 错签名 / 过期 / 错 iss / 错 aud / 错 nonce。
//! 任一断言满足即通过；期望错误的用例用 `auth_error_code` 归类后比对（对
//! 「同类错误的不同子类」留出空间，见 ARCH §8.2「已知差异清单」）。

///|
/// 固定 RSA 公钥模数（base64url，无填充）。
let fixed_rsa_modulus : String = "4ihI16DapgOE6r1z0OQ8_YPzuR27LIVe1vSctRoBmpMQ2dxwDmdAMf4ZqqeE3bYgGFWnXsiuu6Ygy4q61tjvsrdFs4uAu5L0cvXm7jWeQIWBWf0ICw2eth59wB6rYl7ODS0n8yNxxokmUKpElTBEGPiPyVh3vgJwbBCGl402gD8"

///|
/// 固定 id_token —— 正常命中（RS256，kid=test-rsa-1，iss/aud/nonce 均符合期望）。
///
/// 🔴 `pub`：既供本包的 `run_id_token` 使用，也供下游（如 `oidc` 的黑盒测试）直接
/// 以「单条向量」驱动被测实现，无需重复字面量。
pub let fixed_token_ok : String = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3QtcnNhLTEifQ.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoiY2xpZW50LTEiLCJzdWIiOiJ1c2VyLTEiLCJpYXQiOjE2OTk5OTkwMDAsImV4cCI6MTcwMDAwMzYwMCwibm9uY2UiOiJub25jZS0xIiwiZW1haWwiOiJhbGljZUBleGFtcGxlLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlfQ.E44Pi6I60jSWlYDNscpDqapn7SOFSExQXfdJWffgDim1nMmnWnYYSgu_Dh7bhbi_2E7Lskvnl0HT5Tv1euuqGLpKxyLSNJDJ9bjqEwvbcDsgokiNsrU1XVZAm67x8r4bh9r4ZAAMCSI2L7UU49IjpvAFrO4AQwmheIRwVUQITdo"

///|
/// 固定 id_token —— 错签名（用不在 JWKS 里的另一把私钥对同一 claims 签名）。
pub let fixed_token_bad_sig : String = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3QtcnNhLTEifQ.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoiY2xpZW50LTEiLCJzdWIiOiJ1c2VyLTEiLCJpYXQiOjE2OTk5OTkwMDAsImV4cCI6MTcwMDAwMzYwMCwibm9uY2UiOiJub25jZS0xIiwiZW1haWwiOiJhbGljZUBleGFtcGxlLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlfQ.KZoUQBkD3Sxebm62YjcIArk-h-1I9CvVWapVhrGL478JjyV4ZhCu2RPQqZ6eMn-NPxqD2KOXKVoajsbtPig77v39hhf6z_O0vx3jb2IHzfT3xo_Jat4vvNRsrI_N0i4sxPjqpt6ikT7xbSCye5gj3rLLg_KJqrHIrkhzKqRPU6m7oDJtf8tb2I48cya2WMHcILe0YQ5M2SmwVemX5-sg9ElTHhRoJnk9bY2jWGMdveQ5XIFN7Ui1TAEWcDuVW2PMq6C6WNwW7XVAT5FLng7cBFgDamTPdbdMZx3I8d1zTX5rziHaVhwZG2xGJS9ZgIa5ndumGyP8o2RPdjN7RKYhRQ"

///|
/// 固定 id_token —— 已过期（`exp` 远早于固定时钟）。
pub let fixed_token_expired : String = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3QtcnNhLTEifQ.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoiY2xpZW50LTEiLCJzdWIiOiJ1c2VyLTEiLCJpYXQiOjE2OTk5OTkwMDAsImV4cCI6MTYwMDAwMDAwMCwibm9uY2UiOiJub25jZS0xIiwiZW1haWwiOiJhbGljZUBleGFtcGxlLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlfQ.gO451d-MGJKYxG0FkvsRh8wSugcI4vNQR4xkrKxQiVFqBM-R6fIlbl3ihLUjWe_4QGhUb6PinpqwAWAoi4E6IDSqAkEWPuGx8evdv05ocGVpK_z_tSXjVYJOyqeMPv828DxU7n88sGQGvWDV4RY6lU7XXJB9r_uta4aICov2ziM"

///|
/// 固定 id_token —— 错 issuer。
pub let fixed_token_bad_iss : String = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3QtcnNhLTEifQ.eyJpc3MiOiJodHRwczovL2V2aWwuZXhhbXBsZSIsImF1ZCI6ImNsaWVudC0xIiwic3ViIjoidXNlci0xIiwiaWF0IjoxNjk5OTk5MDAwLCJleHAiOjE3MDAwMDM2MDAsIm5vbmNlIjoibm9uY2UtMSIsImVtYWlsIjoiYWxpY2VAZXhhbXBsZS5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZX0.OvcOUojCszcb0n2DrUCK5RPkRWYe0LAGVzuMSispOMeNS8nygcU9L2D3EQJWPXyegZGjkG3mz7DtmbC_f__mnWrtwrF-bnE01RUL3_qKcOJUWqHStXroEndFKYyxqmUv_esQo3ofap6ZnlN2zLyR6xmuUIc0PtIkvvfyeXjWQRI"

///|
/// 固定 id_token —— 错 audience。
pub let fixed_token_bad_aud : String = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3QtcnNhLTEifQ.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoiY2xpZW50LTIiLCJzdWIiOiJ1c2VyLTEiLCJpYXQiOjE2OTk5OTkwMDAsImV4cCI6MTcwMDAwMzYwMCwibm9uY2UiOiJub25jZS0xIiwiZW1haWwiOiJhbGljZUBleGFtcGxlLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlfQ.oqxW0jfdvPrbG_lrxrqWZxRAQjECjlJs6MxvE_UOJo9sSBcAgqjXYcO4Y_45D1LwdpnW6bPDam1AmB0pfwCyEnPJ_r7-SlGi5PVxUJ42s5AdkJClaZPx_Wn9Xe6n-66xJj2bj9Fl9Nm0SFgAbslukSw6BTfBtRJn0_nna9xCsPo"

///|
/// 固定 id_token —— 错 nonce。
pub let fixed_token_bad_nonce : String = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3QtcnNhLTEifQ.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoiY2xpZW50LTEiLCJzdWIiOiJ1c2VyLTEiLCJpYXQiOjE2OTk5OTkwMDAsImV4cCI6MTcwMDAwMzYwMCwibm9uY2UiOiJub25jZS0yIiwiZW1haWwiOiJhbGljZUBleGFtcGxlLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlfQ.e-H8HAjcQoTiIQD6YprPidu5DUo3EfbDdoPdC1SUXfuW3Ek_Ki7HHSEEyFnNO8ac7O3T9bm-U7OxOUcAroU0ceGmXAvSi2KzVFaofoCcznz5X1xwpnmL9Slo1lQ1-BpdyivowkNyqTbiOVNC9Q0w7sn5uc1_GBV0qjtIczptUY4"

///|
/// 固定基准时钟（Unix 秒）。所有时间断言都相对它判定。
pub fn fixed_now_unix() -> Int64 {
  1700000000L
}

///|
/// 固定 id_token —— 头部 `kid=test-rsa-2`（claims 与 `fixed_token_ok` 一致）。
///
/// 用于 **JWKS 轮转**用例：先以 `fixed_token_ok`（kid=test-rsa-1）填充缓存，
/// 再以本 token 触发「kid 未命中 → 重取 JWKS」的轮转路径。
pub fn fixed_token_kid2() -> String {
  "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3QtcnNhLTIifQ.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoiY2xpZW50LTEiLCJzdWIiOiJ1c2VyLTEiLCJpYXQiOjE2OTk5OTkwMDAsImV4cCI6MTcwMDAwMzYwMCwibm9uY2UiOiJub25jZS0xIiwiZW1haWwiOiJhbGljZUBleGFtcGxlLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlfQ.EC5LZKcR_anKbv2xn_KbrZ0kmV7er8Zbq4cQ0HuBt8M8K6HCz60iBZMRVIbE2GEnzWiAbTow8CAUhwEiKNRCHWMZ8gIvigCxXHJGlAK3yGlfUTvBKBL4diz_Ae3NisCAjUIptm3w9nQsId3-QJ7zeDJ9XpjL2lf8lT2X7J0FEJ8"
}

///|
/// 轮转后的 JWKS（同一把公钥，`kid=test-rsa-2`）——即「provider 换了 kid」。
pub fn jwks_rotated_response() -> @core.HttpResponse {
  {
    status: 200,
    headers: Map([("Content-Type", "application/json")]),
    body: "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"" +
    fixed_rsa_modulus +
    "\",\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\"test-rsa-2\",\"use\":\"sig\"}]}",
  }
}

///|
/// 固定 JWKS 文本（kid = `test-rsa-1`，alg = RS256，use = sig）。
pub fn fixed_jwks() -> String {
  "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"" +
  fixed_rsa_modulus +
  "\",\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\"test-rsa-1\",\"use\":\"sig\"}]}"
}

///|
/// JWKS 端点的固定响应（调用方据此构造被测实现的 `HttpClient`）。
pub fn jwks_response() -> @core.HttpResponse {
  {
    status: 200,
    headers: Map([("Content-Type", "application/json")]),
    body: fixed_jwks(),
  }
}

///|
/// 固定期望值（与所有 `fixed_token_*` 配套）。
pub fn expectations() -> @core.IdTokenExpectations {
  {
    issuers: ["https://issuer.example"],
    audiences: ["client-1"],
    nonce: Some("nonce-1"),
    jwks_uri: Some("mock://jwks"),
    leeway_seconds: Some(0),
  }
}

///|
/// 对该 `IdTokenVerifier` 实现跑完整断言集。
///
/// 🔴 **调用方契约**：`make()` 产出的实现必须接一个返回 `jwks_response()` 的
/// `HttpClient`（如 `@contract.MockHttpClient::new([@contract.jwks_response()])`）
/// 与固定时钟（`@contract.FixedClock::new(@contract.fixed_now_unix())`）。
/// `make()` **只被调用一次**——JWKS 缓存于实例内，全部用例共享同一次抓取。
pub async fn run_id_token(make : () -> &@core.IdTokenVerifier) -> Array[CaseResult] {
  let v = make()
  let exp = expectations()
  let out : Array[CaseResult] = []
  out.push(yield_claims(v, fixed_token_ok, exp))
  out.push(
    expect_error(v, fixed_token_bad_sig, exp, "signature_invalid", "wrong signature"),
  )
  out.push(expect_error(v, fixed_token_expired, exp, "token_expired", "expired"))
  out.push(
    expect_error(v, fixed_token_bad_iss, exp, "issuer_mismatch", "wrong issuer"),
  )
  out.push(
    expect_error(v, fixed_token_bad_aud, exp, "audience_mismatch", "wrong audience"),
  )
  out.push(
    expect_error(v, fixed_token_bad_nonce, exp, "nonce_mismatch", "wrong nonce"),
  )
  out
}

///|
/// 正常命中：断言 claims 归一化正确。
async fn yield_claims(
  v : &@core.IdTokenVerifier,
  token : String,
  exp : @core.IdTokenExpectations,
) -> CaseResult {
  let name = "id_token: valid token yields normalized claims"
  try {
    let claims = @core.IdTokenVerifier::verify(v, token, exp)
    if claims.subject == "user-1" &&
      claims.issuer == "https://issuer.example" &&
      claims.audience == ["client-1"] &&
      claims.email == Some("alice@example.com") &&
      claims.email_verified == Some(true) &&
      claims.nonce == Some("nonce-1") &&
      claims.expires_at == 1700003600L {
      CaseResult::pass(name)
    } else {
      CaseResult::fail(name, "claims did not match the fixed vector")
    }
  } catch {
    e => CaseResult::fail(name, "unexpected error: " + @core.auth_error_message(e))
  }
}

///|
/// 期望错误：断言实现抛出的 `AuthError` 归类为 `code`。
async fn expect_error(
  v : &@core.IdTokenVerifier,
  token : String,
  exp : @core.IdTokenExpectations,
  code : String,
  what : String,
) -> CaseResult {
  let name = "id_token: " + what + " is rejected as " + code
  try {
    let _ = @core.IdTokenVerifier::verify(v, token, exp)
    CaseResult::fail(name, "expected an error but verification succeeded")
  } catch {
    e => {
      let actual = @core.auth_error_code(e)
      if actual == code {
        CaseResult::pass(name)
      } else {
        CaseResult::fail(name, "expected " + code + " but got " + actual)
      }
    }
  }
}
