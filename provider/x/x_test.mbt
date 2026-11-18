//! moonauth / provider/x —— 黑盒测试（PKCE / 数值 user id / 错误）。
//!
//! 全部离线确定性：HTTP 走 `@contract.MockHttpClient`，零真实网络。

// ════════ 测试辅助 ════════

///|
/// token 成功响应。
fn x_token_ok() -> @core.HttpResponse {
  {
    status: 200,
    headers: Map([("Content-Type", "application/json")]),
    body: "{\"access_token\":\"at-1\",\"token_type\":\"bearer\",\"scope\":\"users.read\"}",
  }
}

///|
/// `/2/users/me` 成功响应。
fn x_userinfo_ok() -> @core.HttpResponse {
  {
    status: 200,
    headers: Map([("Content-Type", "application/json")]),
    body: "{\"data\":{\"id\":\"2244994945\",\"name\":\"X Dev\",\"username\":\"XDevelopers\"}}",
  }
}

///|
/// 接好固定向量的 X 配置。
fn x_fixed_config() -> @x.XConfig {
  let client : &@core.HttpClient = @contract.MockHttpClient::new([
    x_token_ok(),
    x_userinfo_ok(),
  ])
  @x.XConfig::new("client-1", "https://app.example/cb").with_endpoints(
    "https://twitter.com/i/oauth2/authorize",
    "mock://token",
    "mock://userinfo",
  ).with_http(client)
}

// ════════ begin_auth ════════

///|
/// `begin_auth` 组 PKCE S256 URL。
async test "x: begin_auth assembles a PKCE authorization URL" {
  let config = @x.XConfig::new("client-1", "https://app.example/cb")
  let start = @x.begin_auth(config, {
    state: Some("st-1"),
    code_verifier: Some("verifier-1abcdefghijklmnopqrstuvwxyz0123456789-._~"),
    nonce: None,
  })
  let url = start.url
  assert_true(url.has_prefix("https://twitter.com/i/oauth2/authorize?"))
  assert_true(url.contains("client_id=client-1"))
  assert_true(url.contains("response_type=code"))
  assert_true(url.contains("state=st-1"))
  assert_true(url.contains("code_challenge_method=S256"))
  @debug.assert_eq(start.code_verifier, Some("verifier-1abcdefghijklmnopqrstuvwxyz0123456789-._~"))
  @debug.assert_eq(start.nonce, None)
}

// ════════ complete_auth ════════

///|
/// `complete_auth` 取数值用户 ID 作为 `uid`（`Stable`）。
async test "x: complete_auth uses the numeric user id as uid" {
  let start = @x.begin_auth(@x.XConfig::new("client-1", "https://app.example/cb"), {
    state: Some("st-1"),
    code_verifier: Some("verifier-1abcdefghijklmnopqrstuvwxyz0123456789-._~"),
    nonce: None,
  })
  let cb = @core.CallbackParams::from_query_string("code=auth-code-1&state=st-1")
  let identity = @x.complete_auth(x_fixed_config(), cb, start)
  @debug.assert_eq(identity.provider, "x")
  @debug.assert_eq(identity.uid, "2244994945")
  match identity.uid_kind {
    @core.UidKind::Stable => ()
    @core.UidKind::Degraded => abort("x uid must be Stable")
  }
  @debug.assert_eq(identity.display_name, Some("X Dev"))
  @debug.assert_eq(identity.extra.get("username"), Some("XDevelopers"))
}

// ════════ 错误向量 ════════

///|
/// `state` 不符 → `StateMismatch`。
async test "x: state mismatch is rejected" {
  let start = @x.begin_auth(@x.XConfig::new("client-1", "https://app.example/cb"), {
    state: Some("st-1"),
    code_verifier: Some("verifier-1abcdefghijklmnopqrstuvwxyz0123456789-._~"),
    nonce: None,
  })
  let cb = @core.CallbackParams::from_query_string("code=c&state=WRONG")
  let code = try {
    let _ = @x.complete_auth(x_fixed_config(), cb, start)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "state_mismatch")
}

///|
/// token 端点业务错误码 → `provider_error`。
async test "x: token endpoint error is normalized" {
  let client : &@core.HttpClient = @contract.MockHttpClient::new([
    {
      status: 400,
      headers: Map([("Content-Type", "application/json")]),
      body: "{\"error\":\"invalid_request\",\"error_description\":\"code expired\"}",
    },
  ])
  let config = @x.XConfig::new("client-1", "https://app.example/cb").with_endpoints(
    "https://twitter.com/i/oauth2/authorize",
    "mock://token",
    "mock://userinfo",
  ).with_http(client)
  let start = @x.begin_auth(config, {
    state: Some("st-1"),
    code_verifier: Some("verifier-1abcdefghijklmnopqrstuvwxyz0123456789-._~"),
    nonce: None,
  })
  let cb = @core.CallbackParams::from_query_string("code=c&state=st-1")
  let code = try {
    let _ = @x.complete_auth(config, cb, start)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "provider_error")
}

///|
/// userinfo 缺 `data.id` → `ParseError`。
async test "x: userinfo without data.id is a parse error" {
  let client : &@core.HttpClient = @contract.MockHttpClient::new([
    x_token_ok(),
    {
      status: 200,
      headers: Map([("Content-Type", "application/json")]),
      body: "{\"data\":{\"name\":\"no id\"}}",
    },
  ])
  let config = @x.XConfig::new("client-1", "https://app.example/cb").with_endpoints(
    "https://twitter.com/i/oauth2/authorize",
    "mock://token",
    "mock://userinfo",
  ).with_http(client)
  let start = @x.begin_auth(config, {
    state: Some("st-1"),
    code_verifier: Some("verifier-1abcdefghijklmnopqrstuvwxyz0123456789-._~"),
    nonce: None,
  })
  let cb = @core.CallbackParams::from_query_string("code=c&state=st-1")
  let code = try {
    let _ = @x.complete_auth(config, cb, start)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "parse_error")
}
