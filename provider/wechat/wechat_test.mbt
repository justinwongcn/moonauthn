//! moonauth / provider/wechat —— 黑盒测试（严格 URL 顺序 / unionid 降级 / 错误）。
//!
//! 全部离线确定性：HTTP 走 `@contract.MockHttpClient`，零真实网络。

// ════════ 授权 URL 严格顺序 ════════

///|
/// 🔴 参数顺序必须与微信官方**逐字节一致**（`appid→redirect_uri→response_type→scope→state→#wechat_redirect`）。
async test "wechat: authorize URL uses the strict official order + #wechat_redirect" {
  let config = @wechat.WeChatConfig::new(
    "wx123",
    "SECRET",
    "https://app.example/cb",
  )
  let start = @wechat.begin_auth(config, {
    state: Some("st-1"),
    code_verifier: None,
    nonce: None,
  })
  @debug.assert_eq(
    start.url,
    "https://open.weixin.qq.com/connect/qrconnect?appid=wx123&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&response_type=code&scope=snsapi_login&state=st-1#wechat_redirect",
  )
  @debug.assert_eq(start.state, "st-1")
  @debug.assert_eq(start.code_verifier, None)
}

// ════════ unionid 优先 / openid 兜底 ════════

///|
/// 有 `unionid` → `uid = unionid`，`Stable`。
async test "wechat: unionid present yields a Stable uid" {
  let client : &@core.HttpClient = @contract.MockHttpClient::new([
    {
      status: 200,
      headers: Map([("Content-Type", "application/json")]),
      body: "{\"access_token\":\"at-1\",\"openid\":\"OPENID1\",\"unionid\":\"UNION1\",\"expires_in\":7200,\"refresh_token\":\"rt-1\"}",
    },
    {
      status: 200,
      headers: Map([("Content-Type", "application/json")]),
      body: "{\"openid\":\"OPENID1\",\"nickname\":\"小明\",\"headimgurl\":\"https://wx.example/a.png\",\"unionid\":\"UNION1\"}",
    },
  ])
  let config = @wechat.WeChatConfig::new(
    "wx123",
    "SECRET",
    "https://app.example/cb",
  ).with_http(client)
  let start = @wechat.begin_auth(config, {
    state: Some("st-1"),
    code_verifier: None,
    nonce: None,
  })
  let cb = @wechat.wechat_callback("code=CODE1&state=st-1")
  let identity = @wechat.complete_auth(config, cb, start)
  @debug.assert_eq(identity.provider, "wechat")
  @debug.assert_eq(identity.uid, "UNION1")
  match identity.uid_kind {
    @core.UidKind::Stable => ()
    @core.UidKind::Degraded => abort("wechat with unionid must be Stable")
  }
  @debug.assert_eq(identity.display_name, Some("小明"))
  @debug.assert_eq(identity.avatar, Some("https://wx.example/a.png"))
}

///|
/// 无 `unionid` → `uid = openid`，`Degraded`。
async test "wechat: missing unionid degrades to openid" {
  let client : &@core.HttpClient = @contract.MockHttpClient::new([
    {
      status: 200,
      headers: Map([("Content-Type", "application/json")]),
      body: "{\"access_token\":\"at-1\",\"openid\":\"OPENID2\",\"expires_in\":7200}",
    },
    {
      status: 200,
      headers: Map([("Content-Type", "application/json")]),
      body: "{\"openid\":\"OPENID2\",\"nickname\":\"no-union\"}",
    },
  ])
  let config = @wechat.WeChatConfig::new(
    "wx123",
    "SECRET",
    "https://app.example/cb",
  ).with_http(client)
  let start = @wechat.begin_auth(config, {
    state: Some("st-1"),
    code_verifier: None,
    nonce: None,
  })
  let cb = @wechat.wechat_callback("code=CODE2&state=st-1")
  let identity = @wechat.complete_auth(config, cb, start)
  @debug.assert_eq(identity.uid, "OPENID2")
  match identity.uid_kind {
    @core.UidKind::Degraded => ()
    @core.UidKind::Stable => abort("wechat without unionid must be Degraded")
  }
}

///|
/// 🔴 **unionid 兜底链顺序**：`userinfo.unionid` → **`token.unionid`** → `openid(Degraded)`。
///
/// token 带 `unionid` 而 `/sns/userinfo` 未带（罕见但可能）→ 仍取 unionid，判为
/// `Stable`；修复前会因只看 userinfo 而被**低估为 `Degraded`**。
async test "wechat: token unionid elevates to Stable when userinfo omits it" {
  let client : &@core.HttpClient = @contract.MockHttpClient::new([
    {
      status: 200,
      headers: Map([("Content-Type", "application/json")]),
      body: "{\"access_token\":\"at-1\",\"openid\":\"OPENID3\",\"unionid\":\"UNION-FROM-TOKEN\",\"expires_in\":7200}",
    },
    {
      status: 200,
      headers: Map([("Content-Type", "application/json")]),
      body: "{\"openid\":\"OPENID3\",\"nickname\":\"no-union-in-userinfo\"}",
    },
  ])
  let config = @wechat.WeChatConfig::new(
    "wx123",
    "SECRET",
    "https://app.example/cb",
  ).with_http(client)
  let start = @wechat.begin_auth(config, {
    state: Some("st-1"),
    code_verifier: None,
    nonce: None,
  })
  let cb = @wechat.wechat_callback("code=CODE3&state=st-1")
  let identity = @wechat.complete_auth(config, cb, start)
  @debug.assert_eq(identity.uid, "UNION-FROM-TOKEN")
  match identity.uid_kind {
    @core.UidKind::Stable => ()
    @core.UidKind::Degraded =>
      abort("token unionid must elevate the login to Stable")
  }
}

// ════════ 错误向量 ════════

///|
/// 微信错误体（HTTP 200 但含 `errcode`）→ `provider_error`。
async test "wechat: errcode body is normalized to provider_error" {
  let client : &@core.HttpClient = @contract.MockHttpClient::new([
    {
      status: 200,
      headers: Map([("Content-Type", "application/json")]),
      body: "{\"errcode\":40029,\"errmsg\":\"invalid code\"}",
    },
  ])
  let config = @wechat.WeChatConfig::new(
    "wx123",
    "SECRET",
    "https://app.example/cb",
  ).with_http(client)
  let start = @wechat.begin_auth(config, {
    state: Some("st-1"),
    code_verifier: None,
    nonce: None,
  })
  let cb = @wechat.wechat_callback("code=BAD&state=st-1")
  let code = try {
    let _ = @wechat.complete_auth(config, cb, start)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "provider_error")
}

///|
/// `state` 不符 → `StateMismatch`。
async test "wechat: state mismatch is rejected" {
  let config = @wechat.WeChatConfig::new(
    "wx123",
    "SECRET",
    "https://app.example/cb",
  )
  let start = @wechat.begin_auth(config, {
    state: Some("st-1"),
    code_verifier: None,
    nonce: None,
  })
  let cb = @wechat.wechat_callback("code=c&state=WRONG")
  let code = try {
    let _ = @wechat.complete_auth(config, cb, start)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "state_mismatch")
}

// ════════ 小程序登录（code2Session）════════

///|
/// 成功形态（带 `unionid`）：`uid = unionid`（Stable，与网站链路同一主键口径）；
/// `session_key` 经专用字段返回且**不进** `extra`（敏感密钥防误落日志）。
async test "wechat: code2session with unionid yields Stable uid and session_key" {
  let client : &@core.HttpClient = @contract.MockHttpClient::new([
    {
      status: 200,
      headers: Map([("Content-Type", "application/json")]),
      body: "{\"openid\":\"MP-OPENID1\",\"unionid\":\"MP-UNION1\",\"session_key\":\"SK-1\"}",
    },
  ])
  let config = @wechat.WeChatConfig::new(
    "wxmp123",
    "SECRET",
    "https://app.example/cb",
  ).with_http(client)
  let result = @wechat.wechat_code2_session(config, "JS-CODE-1")
  @debug.assert_eq(result.identity.provider, "wechat")
  @debug.assert_eq(result.identity.uid, "MP-UNION1")
  match result.identity.uid_kind {
    @core.UidKind::Stable => ()
    @core.UidKind::Degraded => abort("unionid uid must be Stable")
  }
  @debug.assert_eq(result.identity.email, None)
  @debug.assert_eq(result.session_key, "SK-1")
  @debug.assert_eq(result.identity.extra.get("openid"), Some("MP-OPENID1"))
  @debug.assert_eq(result.identity.extra.get("unionid"), Some("MP-UNION1"))
  @debug.assert_eq(result.identity.extra.get("session_key"), None)
}

///|
/// 缺 `unionid` → `uid = openid` 且 `Degraded`（调用方据此决定绑定策略）。
async test "wechat: code2session without unionid yields Degraded openid uid" {
  let client : &@core.HttpClient = @contract.MockHttpClient::new([
    {
      status: 200,
      headers: Map([("Content-Type", "application/json")]),
      body: "{\"openid\":\"MP-OPENID2\",\"session_key\":\"SK-2\"}",
    },
  ])
  let config = @wechat.WeChatConfig::new(
    "wxmp123",
    "SECRET",
    "https://app.example/cb",
  ).with_http(client)
  let result = @wechat.wechat_code2_session(config, "JS-CODE-2")
  @debug.assert_eq(result.identity.uid, "MP-OPENID2")
  match result.identity.uid_kind {
    @core.UidKind::Stable => abort("openid-only uid must be Degraded")
    @core.UidKind::Degraded => ()
  }
}

///|
/// `errcode=40029`（code 无效）→ `ProviderError("40029", errmsg)`——HTTP 仍 200，
/// 必须先查 errcode（与整包微信错误口径一致）。
async test "wechat: code2session errcode is normalized to provider_error" {
  let client : &@core.HttpClient = @contract.MockHttpClient::new([
    {
      status: 200,
      headers: Map([("Content-Type", "application/json")]),
      body: "{\"errcode\":40029,\"errmsg\":\"invalid code\"}",
    },
  ])
  let config = @wechat.WeChatConfig::new(
    "wxmp123",
    "SECRET",
    "https://app.example/cb",
  ).with_http(client)
  let outcome = try {
    let _ = @wechat.wechat_code2_session(config, "BAD-CODE")
    "no-error"
  } catch {
    e => @core.auth_error_code(e) + "|" + @core.auth_error_message(e)
  }
  assert_true(outcome.has_prefix("provider_error|"))
  assert_true(outcome.contains("40029"))
}

///|
/// `js_code` / `appid` / `secret` 含特殊字符时必须被编码（动态值零信任口径，
/// 与 `wechat_fetch_token` 一致）；经 `recorded_requests` 断言实际发出的 URL。
async test "wechat: code2session encodes dynamic query values" {
  let mock = @contract.MockHttpClient::new([
    {
      status: 200,
      headers: Map([("Content-Type", "application/json")]),
      body: "{\"openid\":\"O\",\"session_key\":\"S\"}",
    },
  ])
  let client : &@core.HttpClient = mock
  let config = @wechat.WeChatConfig::new(
    "wx&mp=1",
    "sec ret",
    "https://app.example/cb",
  ).with_http(client).with_code2_session_endpoint("mock://jscode2session")
  let _result = @wechat.wechat_code2_session(config, "JS CODE&1")
  let reqs = mock.recorded_requests()
  @debug.assert_eq(reqs.length(), 1)
  let url = reqs[0].url
  assert_true(url.has_prefix("mock://jscode2session?appid=wx%26mp%3D1"))
  assert_true(url.contains("secret=sec%20ret"))
  assert_true(url.contains("js_code=JS%20CODE%261"))
  assert_true(url.contains("grant_type=authorization_code"))
}
