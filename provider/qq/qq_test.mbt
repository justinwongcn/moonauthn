//! moonauth / provider/qq —— 黑盒测试（JSON / form 回退 / JSONP 剥壳 / 错误）。
//!
//! 全部离线确定性：HTTP 走 `@contract.MockHttpClient`，零真实网络。

// ════════ 固定向量 ════════

///|
/// openid JSONP（正常）。
fn qq_me_jsonp() -> @core.HttpResponse {
  {
    status: 200,
    headers: Map([]),
    body: "callback( {\"client_id\":\"101\",\"openid\":\"OPENID-QQ\"} );",
  }
}

///|
/// 用户信息（ret=0）。
fn qq_userinfo_ok() -> @core.HttpResponse {
  {
    status: 200,
    headers: Map([("Content-Type", "application/json")]),
    body: "{\"ret\":0,\"msg\":\"\",\"nickname\":\"QQ用户\",\"figureurl_qq_1\":\"https://q.qlogo.cn/a\"}",
  }
}

///|
/// 一条 QQ 配置（接好 mock）。
fn qq_config(responses : Array[@core.HttpResponse]) -> @qq.QQConfig {
  let client : &@core.HttpClient = @contract.MockHttpClient::new(responses)
  @qq.QQConfig::new("101", "APPSECRET", "https://app.example/cb").with_http(client)
}

// ════════ begin_auth ════════

///|
/// `begin_auth` 组 QQ 授权 URL。
async test "qq: begin_auth assembles the authorization URL" {
  let config = @qq.QQConfig::new("101", "APPSECRET", "https://app.example/cb")
  let start = @qq.begin_auth(config, {
    state: Some("st-1"),
    code_verifier: None,
    nonce: None,
  })
  let url = start.url
  assert_true(url.has_prefix("https://graph.qq.com/oauth2.0/authorize?"))
  assert_true(url.contains("response_type=code"))
  assert_true(url.contains("client_id=101"))
  assert_true(url.contains("redirect_uri=https%3A%2F%2Fapp.example%2Fcb"))
  assert_true(url.contains("state=st-1"))
  assert_true(url.contains("scope=get_user_info"))
}

// ════════ 两类响应体 ════════

///|
/// token 回 JSON（`fmt=json` 生效）→ 正常解出身份（`uid = openid`）。
async test "qq: JSON token response yields an identity" {
  let token : @core.HttpResponse = {
    status: 200,
    headers: Map([("Content-Type", "application/json")]),
    body: "{\"access_token\":\"AT\",\"expires_in\":\"7776000\",\"refresh_token\":\"RT\"}",
  }
  let config = qq_config([token, qq_me_jsonp(), qq_userinfo_ok()])
  let start = @qq.begin_auth(config, {
    state: Some("st-1"),
    code_verifier: None,
    nonce: None,
  })
  let cb = @core.CallbackParams::from_query_string("code=CODE&state=st-1")
  let identity = @qq.complete_auth(config, cb, start)
  @debug.assert_eq(identity.provider, "qq")
  @debug.assert_eq(identity.uid, "OPENID-QQ")
  @debug.assert_eq(identity.display_name, Some("QQ用户"))
  @debug.assert_eq(identity.avatar, Some("https://q.qlogo.cn/a"))
  match identity.uid_kind {
    @core.UidKind::Stable => ()
    @core.UidKind::Degraded => abort("qq uid must be Stable")
  }
}

///|
/// token 回 form-encoded（`fmt=json` 未生效）→ 回退解析，同样解出身份。
async test "qq: form-encoded token response falls back correctly" {
  let token : @core.HttpResponse = {
    status: 200,
    headers: Map([("Content-Type", "text/html")]),
    body: "access_token=AT&expires_in=7776000&refresh_token=RT",
  }
  let config = qq_config([token, qq_me_jsonp(), qq_userinfo_ok()])
  let start = @qq.begin_auth(config, {
    state: Some("st-1"),
    code_verifier: None,
    nonce: None,
  })
  let cb = @core.CallbackParams::from_query_string("code=CODE&state=st-1")
  let identity = @qq.complete_auth(config, cb, start)
  @debug.assert_eq(identity.uid, "OPENID-QQ")
}

// ════════ JSONP 错误分支 ════════

///|
/// JSONP 错误体 `callback( {"error":N,...} );` → `provider_error`。
async test "qq: JSONP error branch is normalized to provider_error" {
  let token : @core.HttpResponse = {
    status: 200,
    headers: Map([("Content-Type", "application/json")]),
    body: "{\"access_token\":\"AT\",\"expires_in\":\"7776000\"}",
  }
  let me : @core.HttpResponse = {
    status: 200,
    headers: Map([]),
    body: "callback( {\"error\":100016,\"error_description\":\"access token check failed\"} );",
  }
  let config = qq_config([token, me])
  let start = @qq.begin_auth(config, {
    state: Some("st-1"),
    code_verifier: None,
    nonce: None,
  })
  let cb = @core.CallbackParams::from_query_string("code=CODE&state=st-1")
  let code = try {
    let _ = @qq.complete_auth(config, cb, start)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "provider_error")
}

///|
/// `state` 不符 → `StateMismatch`。
async test "qq: state mismatch is rejected" {
  let config = @qq.QQConfig::new("101", "APPSECRET", "https://app.example/cb")
  let start = @qq.begin_auth(config, {
    state: Some("st-1"),
    code_verifier: None,
    nonce: None,
  })
  let cb = @core.CallbackParams::from_query_string("code=c&state=WRONG")
  let code = try {
    let _ = @qq.complete_auth(config, cb, start)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "state_mismatch")
}
