//! moonauth / provider/google —— 黑盒测试（facade / 归一化 / SDK-01 组合 A/B/C）。
//!
//! 全部**离线、确定性**：HTTP 走 `@contract.MockHttpClient`，时钟走 `@contract.FixedClock`，
//! `id_token` 用 `@contract` 的固定向量（RS256 + 固定 JWKS），零真实网络。

// ════════ 测试辅助 ════════

///|
/// 返回固定字节序列的 `RandomSource`（确定性重放）。
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
/// 固定 token 响应：`access_token` + 固定的正常 `id_token`。
fn google_token_ok() -> @core.HttpResponse {
  let body = "{\"access_token\":\"at-1\",\"token_type\":\"Bearer\",\"id_token\":\"" +
    @contract.fixed_token_ok +
    "\"}"
  { status: 200, headers: Map([("Content-Type", "application/json")]), body }
}

///|
/// 一条「固定向量」配置：mock 队列 = [token 成功, JWKS]，端点指向固定 issuer。
fn google_fixed_config() -> @google.GoogleConfig {
  let client : &@core.HttpClient = @contract.MockHttpClient::new([
    google_token_ok(),
    @contract.jwks_response(),
  ])
  let clock : &@core.Clock = @contract.FixedClock::new(@contract.fixed_now_unix())
  @google.GoogleConfig::new("client-1", "https://app.example/cb").with_endpoints(
    @contract.google_authorization_endpoint,
    "mock://token",
    "mock://jwks",
    "https://issuer.example",
  ).with_http(client).with_clock(clock)
}

// ════════ 组合 A：默认装配（零注入） ════════

///|
/// 🅰 默认装配：`GoogleConfig::new` 直接可用；组 URL 走 Google 官方端点。
async test "google(A): default config assembles the official authorization URL" {
  let config = @google.GoogleConfig::new("client-1", "https://app.example/cb")
  let secrets : @core.SuppliedSecrets = {
    state: Some("st-123"),
    code_verifier: Some("verifier-1"),
    nonce: Some("nonce-1"),
  }
  let start = @google.begin_auth(config, secrets)
  let url = start.url
  assert_true(url.has_prefix(@contract.google_authorization_endpoint + "?"))
  assert_true(url.contains("client_id=client-1"))
  assert_true(url.contains("redirect_uri=https%3A%2F%2Fapp.example%2Fcb"))
  assert_true(url.contains("response_type=code"))
  assert_true(url.contains("scope=openid%20email%20profile"))
  assert_true(url.contains("state=st-123"))
  assert_true(url.contains("nonce=nonce-1"))
  assert_true(url.contains("code_challenge_method=S256"))
  @debug.assert_eq(start.state, "st-123")
  @debug.assert_eq(start.code_verifier, Some("verifier-1"))
  @debug.assert_eq(start.nonce, Some("nonce-1"))
}

// ════════ 组合 B：注入能力 seam ════════

///|
/// 🅱 注入 `HttpClient` / `Clock` / `RandomSource`：固定向量 → 确定性 `ExternalIdentity`。
async test "google(B): complete_auth yields a deterministic identity" {
  let config = google_fixed_config()
  let secrets : @core.SuppliedSecrets = {
    state: Some("st-123"),
    code_verifier: Some("verifier-1"),
    nonce: Some("nonce-1"),
  }
  let start = @google.begin_auth(config, secrets)
  let callback = @core.CallbackParams::from_query_string(
    "code=auth-code-1&state=st-123",
  )
  let identity = @google.complete_auth(config, callback, start)
  @debug.assert_eq(identity.provider, "google")
  @debug.assert_eq(identity.uid, "user-1")
  match identity.uid_kind {
    @core.UidKind::Stable => ()
    @core.UidKind::Degraded => abort("google uid must be Stable")
  }
  @debug.assert_eq(identity.email, Some("alice@example.com"))
  @debug.assert_eq(identity.email_verified, true)
  @debug.assert_eq(identity.extra.get("email"), Some("alice@example.com"))
}

// ════════ 组合 C：整 provider 替换（SDK-01） ════════

///|
/// 一个「完全自造」的 Google 实现，演示整替换点。
struct StubGoogleProvider {}

///|
impl @google.GoogleProvider for StubGoogleProvider with fn begin_auth(self, secrets) {
  let _ = self
  let _ = secrets
  {
    url: "https://stub.example/authorize?client_id=stub",
    state: "stub-state",
    code_verifier: None,
    nonce: None,
  }
}

///|
impl @google.GoogleProvider for StubGoogleProvider with fn complete_auth(
  self,
  callback,
  expected,
) {
  let _ = self
  let _ = callback
  let _ = expected
  {
    provider: "google",
    uid: "stub-uid",
    uid_kind: @core.UidKind::Stable,
    email: None,
    email_verified: false,
    display_name: Some("Stub User"),
    avatar: None,
    extra: Map([]),
  }
}

///|
/// 对 `GoogleProvider` trait **泛型**的业务代码：与具体实现无关。
async fn drive_google(
  provider : &@google.GoogleProvider,
  secrets : @core.SuppliedSecrets,
) -> @core.AuthStart {
  provider.begin_auth(secrets)
}

///|
/// 🅲 整替换：把 `StubGoogleProvider` 喂给对 trait 泛型的业务代码，行为随之改变。
async test "google(C): a replacement provider plugs in via the trait" {
  let provider : &@google.GoogleProvider = StubGoogleProvider::{  }
  let secrets : @core.SuppliedSecrets = {
    state: None,
    code_verifier: None,
    nonce: None,
  }
  let start = drive_google(provider, secrets)
  @debug.assert_eq(start.url, "https://stub.example/authorize?client_id=stub")
  @debug.assert_eq(start.state, "stub-state")
}

// ════════ 错误向量 ════════

///|
/// `state` 不符 → `StateMismatch`（且**不**发起任何网络请求）。
async test "google: state mismatch is rejected" {
  let config = google_fixed_config()
  let start = @google.begin_auth(config, {
    state: Some("st-123"),
    code_verifier: Some("verifier-1"),
    nonce: Some("nonce-1"),
  })
  let callback = @core.CallbackParams::from_query_string("code=c&state=WRONG")
  let code = try {
    let _ = @google.complete_auth(config, callback, start)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "state_mismatch")
}

///|
/// 回调缺 `code` → `MissingParam`。
async test "google: missing code is rejected as missing_param" {
  let config = google_fixed_config()
  let start = @google.begin_auth(config, {
    state: Some("st-123"),
    code_verifier: Some("verifier-1"),
    nonce: Some("nonce-1"),
  })
  let callback = @core.CallbackParams::from_query_string("state=st-123")
  let code = try {
    let _ = @google.complete_auth(config, callback, start)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "missing_param")
}

///|
/// `nonce` 不符 → `NonceMismatch`（facade 把 begin 的 nonce 透传给验签）。
async test "google: nonce mismatch is rejected" {
  let config = google_fixed_config()
  let start = @google.begin_auth(config, {
    state: Some("st-123"),
    code_verifier: Some("verifier-1"),
    nonce: Some("WRONG-NONCE"),
  })
  let callback = @core.CallbackParams::from_query_string(
    "code=c&state=st-123",
  )
  let code = try {
    let _ = @google.complete_auth(config, callback, start)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "nonce_mismatch")
}

///|
/// token 端点非 2xx → provider 业务错误码归一为 `ProviderError`。
async test "google: token endpoint error is normalized to provider_error" {
  let client : &@core.HttpClient = @contract.MockHttpClient::new([
    {
      status: 400,
      headers: Map([("Content-Type", "application/json")]),
      body: "{\"error\":\"invalid_grant\",\"error_description\":\"code expired\"}",
    },
  ])
  let clock : &@core.Clock = @contract.FixedClock::new(@contract.fixed_now_unix())
  let config = @google.GoogleConfig::new("client-1", "https://app.example/cb").with_endpoints(
    @contract.google_authorization_endpoint,
    "mock://token",
    "mock://jwks",
    "https://issuer.example",
  ).with_http(client).with_clock(clock)
  let start = @google.begin_auth(config, {
    state: Some("st-123"),
    code_verifier: Some("verifier-1"),
    nonce: Some("nonce-1"),
  })
  let callback = @core.CallbackParams::from_query_string(
    "code=c&state=st-123",
  )
  let code = try {
    let _ = @google.complete_auth(config, callback, start)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "provider_error")
}

// ════════ 契约：对默认 facade 跑参数化断言集 ════════

///|
/// `google` facade 契约对**库默认装配** 100% 通过。
async test "google contract: default facade passes every case" {
  let cases = @contract.run_google(@contract.google_mock_config)
  @contract.assert_all_pass(cases)
}

///|
/// 随机源仅经注入 seam：缺省项由 `FixedRandomSource` 生成，结果可重放。
async test "google: default secrets come from the injected RandomSource" {
  let random : &@core.RandomSource = FixedRandomSource::{
    data: Bytes::from_array([b'a', b'b', b'c', b'd']),
  }
  let config = @google.GoogleConfig::new("client-1", "https://app.example/cb").with_random(
    random,
  )
  let a = @google.begin_auth(config, {
    state: None,
    code_verifier: None,
    nonce: None,
  })
  let b = @google.begin_auth(config, {
    state: None,
    code_verifier: None,
    nonce: None,
  })
  @debug.assert_eq(a.state, b.state)
  @debug.assert_eq(a.code_verifier, b.code_verifier)
  @debug.assert_eq(a.nonce, b.nonce)
}
