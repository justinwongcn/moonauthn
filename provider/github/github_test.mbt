//! moonauth / provider/github —— 黑盒测试（facade / 归一化 / SDK-01 组合 A/B/C）。
//!
//! 全部**离线、确定性**：HTTP 走 `@contract.MockHttpClient`，时钟走 `@contract.FixedClock`，
//! 随机走固定重放的 `FixedRandomSource`，零真实网络。

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
/// `/user` 固定向量：公开邮箱在场的形态。
fn github_user_with_email() -> @core.HttpResponse {
  let body = "{\"login\":\"octocat\",\"id\":583231,\"name\":\"The Octocat\"," +
    "\"avatar_url\":\"https://github.com/images/octocat.gif\"," +
    "\"email\":\"octocat@github.com\"}"
  { status: 200, headers: Map([("Content-Type", "application/json")]), body }
}

///|
/// `/user` 固定向量：私有邮箱（`email: null`）形态。
fn github_user_without_email() -> @core.HttpResponse {
  let body = "{\"login\":\"octocat\",\"id\":583231,\"name\":\"The Octocat\"," +
    "\"avatar_url\":\"https://github.com/images/octocat.gif\",\"email\":null}"
  { status: 200, headers: Map([("Content-Type", "application/json")]), body }
}

///|
/// `/user/emails` 固定向量：首个 primary+verified 项应被选中。
fn github_emails_ok() -> @core.HttpResponse {
  let body = "[" +
    "{\"email\":\"private@example.com\",\"primary\":true,\"verified\":true,\"visibility\":\"private\"}," +
    "{\"email\":\"other@example.com\",\"primary\":false,\"verified\":true,\"visibility\":\"public\"}" +
    "]"
  { status: 200, headers: Map([("Content-Type", "application/json")]), body }
}

///|
/// token 响应（GitHub 在 `Accept: application/json` 下回 JSON；seam 固定发送该头）。
fn github_token_ok() -> @core.HttpResponse {
  let body = "{\"access_token\":\"gho_at-1\",\"token_type\":\"bearer\",\"scope\":\"read:user,user:email\"}"
  { status: 200, headers: Map([("Content-Type", "application/json")]), body }
}

///|
/// 一条「固定向量」配置：mock 队列 = [token 成功, /user]，端点指向 mock。
fn github_fixed_config(responses : Array[@core.HttpResponse]) -> @github.GitHubConfig {
  let client : &@core.HttpClient = @contract.MockHttpClient::new(responses)
  let clock : &@core.Clock = @contract.FixedClock::new(@contract.fixed_now_unix())
  @github.GitHubConfig::new("client-1", "https://app.example/cb").with_endpoints(
    "mock://authorize",
    "mock://token",
    "mock://user",
    "mock://emails",
  ).with_http(client).with_clock(clock)
}

// ════════ 组合 A：默认装配（零注入） ════════

///|
/// 🅰 默认装配：`GitHubConfig::new` 直接可用；组 URL 走 GitHub 官方端点（含 PKCE）。
async test "github(A): default config assembles the official authorization URL" {
  let config = @github.GitHubConfig::new("client-1", "https://app.example/cb")
  let secrets : @core.SuppliedSecrets = {
    state: Some("st-123"),
    code_verifier: Some("verifier-1"),
    nonce: None,
  }
  let start = @github.begin_auth(config, secrets)
  let url = start.url
  assert_true(url.has_prefix("https://github.com/login/oauth/authorize?"))
  assert_true(url.contains("client_id=client-1"))
  assert_true(url.contains("redirect_uri=https%3A%2F%2Fapp.example%2Fcb"))
  assert_true(url.contains("response_type=code"))
  assert_true(url.contains("scope=read%3Auser%20user%3Aemail"))
  assert_true(url.contains("state=st-123"))
  assert_true(url.contains("code_challenge_method=S256"))
  @debug.assert_eq(start.state, "st-123")
  @debug.assert_eq(start.code_verifier, Some("verifier-1"))
  // GitHub 无 OIDC id_token，无 nonce 语义。
  @debug.assert_eq(start.nonce, None)
}

// ════════ 组合 B：注入能力 seam ════════

///|
/// 🅱 注入 `HttpClient` / `Clock` / `RandomSource`：固定向量 → 确定性 `ExternalIdentity`。
async test "github(B): complete_auth yields a deterministic identity" {
  let config = github_fixed_config([github_token_ok(), github_user_with_email()])
  let start = @github.begin_auth(config, {
    state: Some("st-123"),
    code_verifier: Some("verifier-1"),
    nonce: None,
  })
  let callback = @core.CallbackParams::from_query_string(
    "code=auth-code-1&state=st-123",
  )
  let identity = @github.complete_auth(config, callback, start)
  @debug.assert_eq(identity.provider, "github")
  // id 是 JSON 数值：必须保留原始书写形态成为 uid。
  @debug.assert_eq(identity.uid, "583231")
  match identity.uid_kind {
    @core.UidKind::Stable => ()
    @core.UidKind::Degraded => abort("github uid must be Stable")
  }
  @debug.assert_eq(identity.email, Some("octocat@github.com"))
  @debug.assert_eq(identity.display_name, Some("The Octocat"))
  @debug.assert_eq(identity.avatar, Some("https://github.com/images/octocat.gif"))
  @debug.assert_eq(identity.extra.get("login"), Some("octocat"))
}

///|
/// 私有邮箱：`/user.email = null` → 补拉 `/user/emails` 取 primary+verified 项。
async test "github: private email falls back to /user/emails primary" {
  let config = github_fixed_config([
    github_token_ok(),
    github_user_without_email(),
    github_emails_ok(),
  ])
  let start = @github.begin_auth(config, {
    state: Some("st-123"),
    code_verifier: Some("verifier-1"),
    nonce: None,
  })
  let callback = @core.CallbackParams::from_query_string(
    "code=c&state=st-123",
  )
  let identity = @github.complete_auth(config, callback, start)
  @debug.assert_eq(identity.email, Some("private@example.com"))
  @debug.assert_eq(identity.email_verified, true)
}

///|
/// 公开邮箱在场时**不**发 `/user/emails` 请求（mock 队列应恰好耗尽）。
async test "github: no /user/emails call when /user carries a public email" {
  let client = @contract.MockHttpClient::new([
    github_token_ok(),
    github_user_with_email(),
  ])
  let clock : &@core.Clock = @contract.FixedClock::new(@contract.fixed_now_unix())
  let config = @github.GitHubConfig::new("client-1", "https://app.example/cb").with_endpoints(
    "mock://authorize",
    "mock://token",
    "mock://user",
    "mock://emails",
  ).with_http(client).with_clock(clock)
  let start = @github.begin_auth(config, {
    state: Some("st-123"),
    code_verifier: Some("verifier-1"),
    nonce: None,
  })
  let callback = @core.CallbackParams::from_query_string(
    "code=c&state=st-123",
  )
  let _ = @github.complete_auth(config, callback, start)
  @debug.assert_eq(client.remaining(), 0)
}

///|
/// 🔴 `/user` 请求必须带 `User-Agent`（GitHub API 强制，缺失 403）。
async test "github: /user request carries User-Agent header" {
  let client = @contract.MockHttpClient::new([
    github_token_ok(),
    github_user_with_email(),
  ])
  let clock : &@core.Clock = @contract.FixedClock::new(@contract.fixed_now_unix())
  let config = @github.GitHubConfig::new("client-1", "https://app.example/cb").with_endpoints(
    "mock://authorize",
    "mock://token",
    "mock://user",
    "mock://emails",
  ).with_http(client).with_clock(clock)
  let start = @github.begin_auth(config, {
    state: Some("st-123"),
    code_verifier: Some("verifier-1"),
    nonce: None,
  })
  let callback = @core.CallbackParams::from_query_string(
    "code=c&state=st-123",
  )
  let _ = @github.complete_auth(config, callback, start)
  let reqs = client.recorded_requests()
  @debug.assert_eq(reqs.length(), 2)
  let user_req = reqs[1]
  @debug.assert_eq(user_req.url, "mock://user")
  @debug.assert_eq(user_req.headers.get("User-Agent"), Some("moonauth"))
  @debug.assert_eq(
    user_req.headers.get("Authorization"),
    Some("Bearer gho_at-1"),
  )
}

///|
/// `/user/emails` 非 2xx（未授予 `user:email` scope）：**可选增强失败不失败登录**。
async test "github: /user/emails failure does not fail the login" {
  let config = github_fixed_config([
    github_token_ok(),
    github_user_without_email(),
    { status: 403, headers: Map([]), body: "{\"message\":\"Not Found\"}" },
  ])
  let start = @github.begin_auth(config, {
    state: Some("st-123"),
    code_verifier: Some("verifier-1"),
    nonce: None,
  })
  let callback = @core.CallbackParams::from_query_string(
    "code=c&state=st-123",
  )
  let identity = @github.complete_auth(config, callback, start)
  @debug.assert_eq(identity.uid, "583231")
  @debug.assert_eq(identity.email, None)
  @debug.assert_eq(identity.email_verified, false)
}

// ════════ 错误向量 ════════

///|
/// `state` 不符 → `StateMismatch`（且**不**发起任何网络请求）。
async test "github: state mismatch is rejected" {
  let config = github_fixed_config([github_token_ok(), github_user_with_email()])
  let start = @github.begin_auth(config, {
    state: Some("st-123"),
    code_verifier: Some("verifier-1"),
    nonce: None,
  })
  let callback = @core.CallbackParams::from_query_string("code=c&state=WRONG")
  let code = try {
    let _ = @github.complete_auth(config, callback, start)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "state_mismatch")
}

///|
/// 回调缺 `code` → `MissingParam`。
async test "github: missing code is rejected as missing_param" {
  let config = github_fixed_config([github_token_ok(), github_user_with_email()])
  let start = @github.begin_auth(config, {
    state: Some("st-123"),
    code_verifier: Some("verifier-1"),
    nonce: None,
  })
  let callback = @core.CallbackParams::from_query_string("state=st-123")
  let code = try {
    let _ = @github.complete_auth(config, callback, start)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "missing_param")
}

///|
/// token 端点非 2xx → provider 业务错误码归一为 `ProviderError`。
async test "github: token endpoint error is normalized to provider_error" {
  let config = github_fixed_config([
    {
      status: 400,
      headers: Map([("Content-Type", "application/json")]),
      body: "{\"error\":\"bad_verification_code\",\"error_description\":\"The code passed is incorrect or expired.\"}",
    },
  ])
  let start = @github.begin_auth(config, {
    state: Some("st-123"),
    code_verifier: Some("verifier-1"),
    nonce: None,
  })
  let callback = @core.CallbackParams::from_query_string(
    "code=c&state=st-123",
  )
  let code = try {
    let _ = @github.complete_auth(config, callback, start)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "provider_error")
}

// ════════ 组合 C：整 provider 替换（SDK-01） ════════

///|
/// 一个「完全自造」的 GitHub 实现，演示整替换点。
struct StubGitHubProvider {}

///|
impl @github.GitHubProvider for StubGitHubProvider with fn begin_auth(self, secrets) {
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
impl @github.GitHubProvider for StubGitHubProvider with fn complete_auth(
  self,
  callback,
  expected,
) {
  let _ = self
  let _ = callback
  let _ = expected
  {
    provider: "github",
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
/// 🅲 整替换：把 `StubGitHubProvider` 喂给对 trait 泛型的业务代码，行为随之改变。
async test "github(C): a replacement provider plugs in via the trait" {
  let provider : &@github.GitHubProvider = StubGitHubProvider::{  }
  let start = drive_github(provider, {
    state: None,
    code_verifier: None,
    nonce: None,
  })
  @debug.assert_eq(start.url, "https://stub.example/authorize?client_id=stub")
  @debug.assert_eq(start.state, "stub-state")
}

///|
/// 对 `GitHubProvider` trait **泛型**的业务代码：与具体实现无关。
async fn drive_github(
  provider : &@github.GitHubProvider,
  secrets : @core.SuppliedSecrets,
) -> @core.AuthStart {
  provider.begin_auth(secrets)
}

///|
/// 随机源仅经注入 seam：缺省项由 `FixedRandomSource` 生成，结果可重放。
async test "github: default secrets come from the injected RandomSource" {
  let random : &@core.RandomSource = FixedRandomSource::{
    data: Bytes::from_array([b'a', b'b', b'c', b'd']),
  }
  let config = @github.GitHubConfig::new("client-1", "https://app.example/cb").with_random(
    random,
  )
  let a = @github.begin_auth(config, {
    state: None,
    code_verifier: None,
    nonce: None,
  })
  let b = @github.begin_auth(config, {
    state: None,
    code_verifier: None,
    nonce: None,
  })
  @debug.assert_eq(a.state, b.state)
  @debug.assert_eq(a.code_verifier, b.code_verifier)
}

// ════════ 回调错误参数 + 邮箱回退档 ════════

///|
/// GitHub 失败回调携带 `error` / `error_description` / `error_uri`——state 通过后
/// 必须归一为 `provider_error`（`error_uri` 并入消息）。
async test "github: callback error params are normalized to provider_error" {
  let config = github_fixed_config([])
  let start = @github.begin_auth(config, {
    state: Some("st-1"),
    code_verifier: Some("verifier-1"),
    nonce: None,
  })
  let callback = @core.CallbackParams::from_query_string(
    "error=verification_failed&error_description=humana%20verification%20failed&error_uri=https://docs.github.com/troubleshooting&state=st-1",
  )
  let outcome = try {
    let _ = @github.complete_auth(config, callback, start)
    "no-error"
  } catch {
    e => @core.auth_error_code(e) + "|" + @core.auth_error_message(e)
  }
  assert_true(outcome.has_prefix("provider_error|"))
  assert_true(outcome.contains("verification_failed"))
  assert_true(outcome.contains("https://docs.github.com/troubleshooting"))
}

///|
/// `/user.email` 为 null 且 `/user/emails` **无 primary** 项 → 回退首个
/// `verified=true`（GitHub 私密邮箱场景；调研核对补充的选择规则）。
async test "github: falls back to first verified email when no primary" {
  let emails_body = "[" +
    "{\"email\":\"unverified@example.com\",\"primary\":false,\"verified\":false,\"visibility\":\"private\"}," +
    "{\"email\":\"verified-a@example.com\",\"primary\":false,\"verified\":true,\"visibility\":\"private\"}," +
    "{\"email\":\"verified-b@example.com\",\"primary\":false,\"verified\":true,\"visibility\":\"private\"}" +
    "]"
  let config = github_fixed_config([
    github_token_ok(),
    github_user_without_email(),
    { status: 200, headers: Map([("Content-Type", "application/json")]), body: emails_body },
  ])
  let start = @github.begin_auth(config, {
    state: Some("st-1"),
    code_verifier: Some("verifier-1"),
    nonce: None,
  })
  let cb = @core.CallbackParams::from_query_string("code=CODE1&state=st-1")
  let identity = @github.complete_auth(config, cb, start)
  @debug.assert_eq(identity.email, Some("verified-a@example.com"))
  assert_true(identity.email_verified)
}
