//! moonauth / provider/microsoft —— 黑盒测试（per-tenant issuer 派生 / 租户白名单 /
//! 错误归一 / 归一化）。
//!
//! 全部离线确定性：HTTP 走 `@contract.MockHttpClient`，时钟走 `@contract.FixedClock`，
//! `id_token` 由测试内**固定 RSA 钥匙现场签发**（与 alipay 测试同一把测试钥匙），
//! JWKS 由同一钥匙的模数构造——保证 per-tenant issuer 派生路径被真实验签覆盖。

// ════════ 测试辅助 ════════

///|
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
/// 固定 RSA 私钥（PKCS#1，标准 base64；与 alipay 测试同一把测试钥匙）。
let msft_rsa_pkcs1_b64 : String = "MIIEpAIBAAKCAQEAoT66btCxc2vTvxzdFOrUT5eZkcp1PAGbKYxJREtQG3DOCNHc8l9J1a2kN1BLVeLphMwuWBFKUYANkiKLaMDLpeSlW06n8uEborA+LE7b+q8hL007YN6f850j17/Vq41FuvDYN6xSy8O3WIRzza9znhgTq2MukyzrHOiGijI7L4SusMsOKKQGV2DiZIjNYn8bfhUnxJRyKSFNqBQ/wOZBUo38pHut2ojX4SNDLx7YvrbtCVYE+1sp79THzp8rzaLhIwEf5QLq8IojLVf041eLp28Nlu5qHMPC1lnSO1kQpmPnYju1aPKYNBcGPniX/rzGBUOywLV8UMUHDJZySnjSXwIDAQABAoIBAB/GPzHIITfH902RUAWnstfOXX5Lwadl/6AD24pANxR5ObimNl5ypZecZKBby8Ssduzq2XUUTytZSxNRiFxHpbnWoTkpelITxwDbrxzHG3U+XpE2LG3N4QI+JIqG7IGmUKfifxEVfalWs4IXc8SD/woX34RmAo8RCnHDZoPEG0KlGDROGKKj7/iySxdku9Z4kK5nip7pQIubIXtVFKBBiiFmPzwTh2lH7k52/53luuy2mQmCXavY5xWaB6SN/PQuoPE7Di8w9OoXPKMoTRzfBOSCs1V1vMMVaKtk8F9WP9uGFTGwV/NTJDlzH3/sYkvyR2JIrIMx79UbMU7GkrKev4kCgYEA0bt1iZTln1KypvHshkfUZD7vfa21tWJm+/DR+lBwgnWB2qXgqer7lxaFkGeGf5LJCaeapMAogKmJyKmpeu2OPW0xeyIpy2n1jEq7Bg1Bziia7uQkNJGZJfxo5c/LwHa2JMPDlg1YW0TaDU0aeQMLeAm8XnQ8Or8p3ZNb1d6hj9cCgYEAxND5Kko/7nbI27hjx02kjs8a3E0WbhpWHSMNqaVsQLQG23gNyffUs8PcP0juZGb7BpMm3F3WKPjiFI0bAcc4qizYqiNaIIabbwEKw9t205PKCw0Kh4OSK9icX98x8lcbdGIocUWOzyyufO5lhTtfF+o456c5D1FC3RPbrkSLILkCgYBhkWukjXglHjuuHm2CKnhMClsvhFg8AYMXQXjtke5FQpUeOnzBj2drajbIbuDLCGYt76Kpchtlf3lxuDv3y/uX5+xU9BetYaWxljJbJl+uoIUzDT8qlXFBkqLaBkkrSA6EG+4pKBwqmWU3Ot9N3HTBawYOitRaIARB6AOZAvD2EQKBgQCDgEy6oNmObvdNNyoTpCDq+h2sTCVMc3ROC3m5e7mUkbRzNwefhmMrqRWjgwslMllOz0sLufa5cXE84frFeWK28TfilbRGPynjRQL4Uc5XF0vLjm8WlCY5/YSd2fb5QJIrdNootJzyd5wuBOr31e93fxt+TBCn11ehdv80tL9woQKBgQDGX9ASVzVzflcCGhAK+1qQEdt52rR82JVsqzTEtTJE06CjZIIRpBBFuwNNbO7pJJMqNdieEWr3OcZSIQLNAFd4rCYR/+gRPwXUNf1kuRGs4ggxqjzqi0xWKMJns0t5gH0fjwdGIf4JaIDPknVb+guF0HWI3zFaVebjtJUHsLuzyQ=="

///|
/// 固定 RSA 公钥模数（hex，与上面私钥配对）。
let msft_rsa_n_hex : String = "a13eba6ed0b1736bd3bf1cdd14ead44f979991ca753c019b298c49444b501b70ce08d1dcf25f49d5ada437504b55e2e984cc2e58114a51800d92228b68c0cba5e4a55b4ea7f2e11ba2b03e2c4edbfaaf212f4d3b60de9ff39d23d7bfd5ab8d45baf0d837ac52cbc3b7588473cdaf739e1813ab632e932ceb1ce8868a323b2f84aeb0cb0e28a4065760e26488cd627f1b7e1527c4947229214da8143fc0e641528dfca47badda88d7e123432f1ed8beb6ed095604fb5b29efd4c7ce9f2bcda2e123011fe502eaf08a232d57f4e3578ba76f0d96ee6a1cc3c2d659d23b5910a663e7623bb568f2983417063e7897febcc60543b2c0b57c50c5070c96724a78d25f"

///|
/// 测试租户 ID。
let msft_tid : String = "11111111-2222-3333-4444-555555555555"

///|
/// hex（可含大写）→ 字节。
fn msft_hex_to_bytes(s : String) -> Bytes {
  let src = @utf8.encode(s)
  let out : Array[Byte] = []
  let mut i = 0
  while i + 1 < src.length() {
    let hi = msft_hex_val(src[i].to_int())
    let lo = msft_hex_val(src[i + 1].to_int())
    out.push((hi * 16 + lo).to_byte())
    i = i + 2
  }
  Bytes::from_array(out)
}

///|
fn msft_hex_val(c : Int) -> Int {
  if c >= 97 {
    c - 87
  } else if c >= 65 {
    c - 55
  } else {
    c - 48
  }
}

///|
/// RS256 现场签发一枚 id_token（header `kid=msft-1`）。
fn msft_mint_token(claims_json : String) -> String raise @core.AuthError {
  let header = @oauth.base64url_encode(
    @utf8.encode("{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"msft-1\"}"),
  )
  let payload = @oauth.base64url_encode(@utf8.encode(claims_json))
  let signing_input = header + "." + payload
  let sig = @core.SecretSigner::sign(
    @oauth.MooncryptSecretSigner::new(),
    @core.SignAlg::RS256,
    @core.SigningKey::Der(@oauth.base64_std_decode(msft_rsa_pkcs1_b64)),
    @utf8.encode(signing_input),
  )
  signing_input + "." + @oauth.base64url_encode(sig)
}

///|
/// 与测试钥匙配对的 JWKS（kid = `msft-1`）。
fn msft_jwks() -> String {
  "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"" +
  @oauth.base64url_encode(msft_hex_to_bytes(msft_rsa_n_hex)) +
  "\",\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\"msft-1\",\"use\":\"sig\"}]}"
}

///|
fn msft_jwks_response() -> @core.HttpResponse {
  { status: 200, headers: Map([("Content-Type", "application/json")]), body: msft_jwks() }
}

///|
/// token 响应：access_token + 由测试钥匙签发的 id_token。
fn msft_token_ok(claims_json : String) -> @core.HttpResponse raise @core.AuthError {
  let body = "{\"access_token\":\"at-msft\",\"token_type\":\"Bearer\",\"id_token\":\"" +
    msft_mint_token(claims_json) +
    "\"}"
  { status: 200, headers: Map([("Content-Type", "application/json")]), body }
}

///|
/// 快乐路径 claims：tid / oid / aud / nonce / exp 全部对齐固定向量。
fn msft_claims_ok() -> String {
  "{\"iss\":\"https://login.microsoftonline.com/" +
  msft_tid +
  "/v2.0\",\"aud\":\"client-1\",\"sub\":\"user-msft\",\"tid\":\"" +
  msft_tid +
  "\",\"oid\":\"oid-msft-1\",\"name\":\"Dev\",\"preferred_username\":\"dev@contoso.com\",\"email\":\"dev@contoso.com\",\"email_verified\":true,\"nonce\":\"nonce-1\",\"iat\":1699999000,\"exp\":1700003600}"
}

///|
/// 一条「固定向量」配置：mock 队列 = [token, JWKS]；issuer 模板保持官方 per-tenant
/// 形态（`{tid}` 派生路径被真实覆盖）。
fn msft_fixed_config() -> @microsoft.MicrosoftConfig raise @core.AuthError {
  let client : &@core.HttpClient = @contract.MockHttpClient::new([
    msft_token_ok(msft_claims_ok()),
    msft_jwks_response(),
  ])
  let clock : &@core.Clock = @contract.FixedClock::new(@contract.fixed_now_unix())
  @microsoft.MicrosoftConfig::new("client-1", "https://app.example/cb")
  .with_client_secret("secret-1")
  .with_endpoints("mock://authorize", "mock://token", "mock://jwks")
  .with_http(client).with_clock(clock)
}

///|
/// 无 tid 的 claims（issuer 模板含 `{tid}` 时的 fail-closed 观察）。
fn msft_claims_no_tid() -> String {
  "{\"iss\":\"https://login.microsoftonline.com/common/v2.0\",\"aud\":\"client-1\",\"sub\":\"user-msft\",\"nonce\":\"nonce-1\",\"iat\":1699999000,\"exp\":1700003600}"
}

// ════════ 组合 A：默认装配 ════════

///|
/// 🅰 默认装配（tenant=common）：端点按模板展开 + nonce / PKCE 恒发。
async test "microsoft(A): default config assembles the common-tenant authorize URL" {
  let config = @microsoft.MicrosoftConfig::new("client-1", "https://app.example/cb")
  let secrets : @core.SuppliedSecrets = {
    state: Some("st-123"),
    code_verifier: Some("verifier-1abcdefghijklmnopqrstuvwxyz0123456789-._~"),
    nonce: Some("nonce-1"),
  }
  let start = @microsoft.begin_auth(config, secrets)
  assert_true(
    start.url.has_prefix(
      "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?",
    ),
  )
  assert_true(start.url.contains("client_id=client-1"))
  assert_true(start.url.contains("scope=openid%20profile%20email"))
  assert_true(start.url.contains("state=st-123"))
  assert_true(start.url.contains("nonce=nonce-1"))
  assert_true(start.url.contains("code_challenge_method=S256"))
  @debug.assert_eq(start.nonce, Some("nonce-1"))
}

///|
/// 🅰 `with_tenant` 重算端点（organizations → 仅组织账号）。
async test "microsoft(A): with_tenant recomputes endpoints" {
  let config = @microsoft.MicrosoftConfig::new("client-1", "https://app.example/cb")
  .with_tenant("organizations")
  let secrets : @core.SuppliedSecrets = {
    state: Some("st-123"),
    code_verifier: None,
    nonce: None,
  }
  let start = @microsoft.begin_auth(config, secrets)
  assert_true(
    start.url.has_prefix(
      "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?",
    ),
  )
}

// ════════ 组合 B：per-tenant issuer 派生 ════════

///|
/// 🔴 快乐路径：tid → `{tid}` 模板派生精确 issuer → 真实验签通过 → 身份归一
/// （uid=sub、Stable、extra 携带 tid / oid）。
async test "microsoft(B): per-tenant issuer derivation verifies a valid token" {
  let config = msft_fixed_config()
  let secrets : @core.SuppliedSecrets = {
    state: Some("st-123"),
    code_verifier: Some("verifier-1abcdefghijklmnopqrstuvwxyz0123456789-._~"),
    nonce: Some("nonce-1"),
  }
  let start = @microsoft.begin_auth(config, secrets)
  let callback = @core.CallbackParams::from_query_string(
    "code=auth-code-1&state=st-123",
  )
  let identity = @microsoft.complete_auth(config, callback, start)
  @debug.assert_eq(identity.provider, "microsoft")
  @debug.assert_eq(identity.uid, "user-msft")
  match identity.uid_kind {
    @core.UidKind::Stable => ()
    @core.UidKind::Degraded => abort("microsoft uid must be Stable")
  }
  @debug.assert_eq(identity.email, Some("dev@contoso.com"))
  assert_true(identity.email_verified)
  @debug.assert_eq(identity.display_name, Some("Dev"))
  @debug.assert_eq(identity.extra.get("tid"), Some(msft_tid))
  @debug.assert_eq(identity.extra.get("oid"), Some("oid-msft-1"))
  @debug.assert_eq(identity.extra.get("preferred_username"), Some("dev@contoso.com"))
}

///|
/// 🔴 租户白名单：`allowed_tenant_ids` 非空且 tid 不命中 → `tenant_not_allowed`
/// （在验签**之前**拒绝——mock 队列只需 token 响应）。
async test "microsoft: tid outside the allowlist is tenant_not_allowed" {
  let client : &@core.HttpClient = @contract.MockHttpClient::new([
    msft_token_ok(msft_claims_ok()),
  ])
  let config = @microsoft.MicrosoftConfig::new("client-1", "https://app.example/cb")
  .with_client_secret("secret-1")
  .with_endpoints("mock://authorize", "mock://token", "mock://jwks")
  .with_allowed_tenant_ids(["99999999-8888-7777-6666-555555555555"])
  .with_http(client)
  let secrets : @core.SuppliedSecrets = {
    state: Some("st-123"),
    code_verifier: Some("verifier-1abcdefghijklmnopqrstuvwxyz0123456789-._~"),
    nonce: Some("nonce-1"),
  }
  let start = @microsoft.begin_auth(config, secrets)
  let callback = @core.CallbackParams::from_query_string(
    "code=auth-code-1&state=st-123",
  )
  let outcome = try {
    let _ = @microsoft.complete_auth(config, callback, start)
    "no-error"
  } catch {
    e => @core.auth_error_code(e) + "|" + @core.auth_error_message(e)
  }
  assert_true(outcome.has_prefix("provider_error|"))
  assert_true(outcome.contains("tenant_not_allowed"))
}

///|
/// 🔴 fail-closed：issuer 模板要求 `{tid}` 但 token 缺 tid → `InvalidInput`。
async test "microsoft: missing tid with tid-requiring template is rejected" {
  let client : &@core.HttpClient = @contract.MockHttpClient::new([
    msft_token_ok(msft_claims_no_tid()),
  ])
  let config = @microsoft.MicrosoftConfig::new("client-1", "https://app.example/cb")
  .with_client_secret("secret-1")
  .with_endpoints("mock://authorize", "mock://token", "mock://jwks")
  .with_http(client)
  let secrets : @core.SuppliedSecrets = {
    state: Some("st-123"),
    code_verifier: Some("verifier-1abcdefghijklmnopqrstuvwxyz0123456789-._~"),
    nonce: Some("nonce-1"),
  }
  let start = @microsoft.begin_auth(config, secrets)
  let callback = @core.CallbackParams::from_query_string(
    "code=auth-code-1&state=st-123",
  )
  let code = try {
    let _ = @microsoft.complete_auth(config, callback, start)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "invalid_input")
}

// ════════ 回调错误 / state ════════

///|
/// 失败回调（`error=invalid_grant`，AADSTS 细节在 description）→ `provider_error`，
/// 在换 token **之前**归一（mock 队列为空即可命中）。
async test "microsoft: callback error params are normalized to provider_error" {
  let config = @microsoft.MicrosoftConfig::new("client-1", "https://app.example/cb")
  let secrets : @core.SuppliedSecrets = {
    state: Some("st-123"),
    code_verifier: Some("verifier-1abcdefghijklmnopqrstuvwxyz0123456789-._~"),
    nonce: Some("nonce-1"),
  }
  let start = @microsoft.begin_auth(config, secrets)
  let callback = @core.CallbackParams::from_query_string(
    "error=invalid_grant&error_description=AADSTS700016%3A%20application%20not%20found&state=st-123",
  )
  let outcome = try {
    let _ = @microsoft.complete_auth(config, callback, start)
    "no-error"
  } catch {
    e => @core.auth_error_code(e) + "|" + @core.auth_error_message(e)
  }
  assert_true(outcome.has_prefix("provider_error|"))
  assert_true(outcome.contains("AADSTS700016"))
}

///|
/// `state` 不符 → `StateMismatch`（最先校验，零网络请求）。
async test "microsoft: state mismatch is rejected" {
  let config = @microsoft.MicrosoftConfig::new("client-1", "https://app.example/cb")
  let secrets : @core.SuppliedSecrets = {
    state: Some("st-123"),
    code_verifier: Some("verifier-1abcdefghijklmnopqrstuvwxyz0123456789-._~"),
    nonce: Some("nonce-1"),
  }
  let start = @microsoft.begin_auth(config, secrets)
  let callback = @core.CallbackParams::from_query_string("code=c&state=WRONG")
  let code = try {
    let _ = @microsoft.complete_auth(config, callback, start)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "state_mismatch")
}
