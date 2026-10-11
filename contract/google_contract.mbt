//! moonauth / contract —— `provider/google` facade 的参数化契约（SDK-04 / LIB-17）。
//!
//! 契约函数 `run_google(make_config)` 把**同一套断言**跑在任意装配上：
//! - 库默认装配（`@google.GoogleConfig::new` + 固定 Mock）；
//! - 下游自造装配（换端点 / 换 HTTP / 换时钟）。
//!
//! ## 固定向量（离线确定性，LIB-15 ③）
//! 复用本包既有的字面量：`fixed_token_ok`（RS256 / kid=test-rsa-1 / nonce=nonce-1 /
//! aud=client-1 / iss=https://issuer.example）与 `jwks_response()`（固定 JWKS）。
//!
//! 🔴 **调用方契约**：`make_config()` **每次调用**都必须产出一个「重新接好 Mock」的
//! `GoogleConfig`——mock 队列为 `[google_token_ok_response(), jwks_response()]`，
//! 端点指向固定 issuer（`https://issuer.example`）、`jwks_uri = mock://jwks`。
//! 契约会**多次**调用 `make_config()`（每个需要 I/O 的用例各一次），故不得复用同一
//! Mock 队列。便捷起手：直接用本包的 `google_mock_config`。
//!
//! 🔴 **命名**：本包顶层标识符与 T04 的 `run_webauthn` / `run_totp` 共存，故此处只用
//! `run_google` / `google_*`，绝不占用对方的命名空间。
//!
//! 说明：id_token 的**密码学**错误（错签名 / 过期 / 错 iss / 错 aud）已由
//! `run_id_token` 覆盖，此处不重复；本契约只断言 facade 层的责任——
//! 组 URL、state 校验、缺参、nonce 透传。

///|
/// 固定 token 响应：`access_token` + 固定的正常 `id_token`（供 facade 契约使用）。
pub fn google_token_ok_response() -> @core.HttpResponse {
  let body = "{\"access_token\":\"at-1\",\"token_type\":\"Bearer\",\"id_token\":\"" +
    fixed_token_ok +
    "\"}"
  { status: 200, headers: Map([("Content-Type", "application/json")]), body }
}

///|
/// 便捷起手：产出「已按契约接好固定向量」的 `GoogleConfig`（每次调用独立 Mock 队列）。
pub fn google_mock_config() -> @google.GoogleConfig {
  let client : &@core.HttpClient = MockHttpClient::new([
    google_token_ok_response(),
    jwks_response(),
  ])
  let clock : &@core.Clock = FixedClock::new(fixed_now_unix())
  @google.GoogleConfig::new("client-1", "https://app.example/cb").with_endpoints(
    google_authorization_endpoint,
    "mock://token",
    "mock://jwks",
    "https://issuer.example",
  ).with_http(client).with_clock(clock)
}

///|
/// 对该 facade 跑完整断言集。
pub async fn run_google(
  make_config : () -> @google.GoogleConfig,
) -> Array[CaseResult] {
  let out : Array[CaseResult] = []
  out.push(google_begin_case(make_config()))
  out.push(google_identity_case(make_config()))
  out.push(google_state_case(make_config()))
  out.push(google_missing_code_case(make_config()))
  out.push(google_nonce_case(make_config()))
  out
}

///|
/// 固定临时态（与固定 token 的 nonce 匹配）。
fn google_fixed_secrets() -> @core.SuppliedSecrets {
  {
    state: Some("st-c1"),
    code_verifier: Some("verifier-1"),
    nonce: Some("nonce-1"),
  }
}

///|
/// 用例：组授权 URL（Google 官方端点前缀 + 关键参数）。
async fn google_begin_case(config : @google.GoogleConfig) -> CaseResult {
  let name = "google: begin_auth assembles the authorization URL"
  try {
    let start = @google.begin_auth(config, google_fixed_secrets())
    let url = start.url
    if url.has_prefix(google_authorization_endpoint + "?") &&
      url.contains("client_id=client-1") &&
      url.contains("response_type=code") &&
      url.contains("state=st-c1") &&
      url.contains("nonce=nonce-1") &&
      url.contains("code_challenge_method=S256") &&
      start.code_verifier == Some("verifier-1") {
      CaseResult::pass(name)
    } else {
      CaseResult::fail(name, "unexpected url: " + url)
    }
  } catch {
    e => CaseResult::fail(name, "unexpected error: " + @core.auth_error_message(e))
  }
}

///|
/// 用例：固定向量 → 确定性 `ExternalIdentity`。
async fn google_identity_case(config : @google.GoogleConfig) -> CaseResult {
  let name = "google: fixed vectors yield a deterministic identity"
  try {
    let start = @google.begin_auth(config, google_fixed_secrets())
    let callback = @core.CallbackParams::from_query_string(
      "code=auth-code-1&state=st-c1",
    )
    let identity = @google.complete_auth(config, callback, start)
    if identity.provider == "google" &&
      identity.uid == "user-1" &&
      identity.email == Some("alice@example.com") &&
      identity.email_verified {
      CaseResult::pass(name)
    } else {
      CaseResult::fail(name, "unexpected identity: uid=" + identity.uid)
    }
  } catch {
    e => CaseResult::fail(name, "unexpected error: " + @core.auth_error_message(e))
  }
}

///|
/// 用例：`state` 不符 → `StateMismatch`。
async fn google_state_case(config : @google.GoogleConfig) -> CaseResult {
  let name = "google: state mismatch is rejected as state_mismatch"
  let code = try {
    let start = @google.begin_auth(config, google_fixed_secrets())
    let callback = @core.CallbackParams::from_query_string(
      "code=c&state=WRONG",
    )
    let _ = @google.complete_auth(config, callback, start)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  if code == "state_mismatch" {
    CaseResult::pass(name)
  } else {
    CaseResult::fail(name, "expected state_mismatch but got " + code)
  }
}

///|
/// 用例：缺 `code` → `missing_param`。
async fn google_missing_code_case(config : @google.GoogleConfig) -> CaseResult {
  let name = "google: missing code is rejected as missing_param"
  let code = try {
    let start = @google.begin_auth(config, google_fixed_secrets())
    let callback = @core.CallbackParams::from_query_string("state=st-c1")
    let _ = @google.complete_auth(config, callback, start)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  if code == "missing_param" {
    CaseResult::pass(name)
  } else {
    CaseResult::fail(name, "expected missing_param but got " + code)
  }
}

///|
/// 用例：`nonce` 不符 → `nonce_mismatch`（facade 把 begin 的 nonce 透传给验签）。
async fn google_nonce_case(config : @google.GoogleConfig) -> CaseResult {
  let name = "google: nonce mismatch is rejected as nonce_mismatch"
  let code = try {
    let secrets : @core.SuppliedSecrets = {
      state: Some("st-c1"),
      code_verifier: Some("verifier-1"),
      nonce: Some("WRONG-NONCE"),
    }
    let start = @google.begin_auth(config, secrets)
    let callback = @core.CallbackParams::from_query_string("code=c&state=st-c1")
    let _ = @google.complete_auth(config, callback, start)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  if code == "nonce_mismatch" {
    CaseResult::pass(name)
  } else {
    CaseResult::fail(name, "expected nonce_mismatch but got " + code)
  }
}
