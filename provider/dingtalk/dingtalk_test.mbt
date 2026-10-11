//! moonauth / provider/dingtalk —— 黑盒测试（facade / 归一化 / SDK-01 组合）。
//!
//! 全部**离线、确定性**：HTTP 走 `@contract.MockHttpClient`，时钟走 `@contract.FixedClock`，
//! 随机走固定重放的 `FixedRandomSource`，零真实网络。
//!
//! 🔴 **无国际站用例**：国际站端点未从官方文档核实，库不内置预设（诚实优先），
//! 故无从断言；`with_endpoints` 的覆盖能力由本文件的 mock 端点改写路径间接覆盖。

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
/// token 响应固定向量（驼峰字段）。
fn dingtalk_token_ok() -> @core.HttpResponse {
  let body = "{\"expireIn\":7200,\"accessToken\":\"dt-at-1\",\"refreshToken\":\"dt-rt-1\"}"
  { status: 200, headers: Map([("Content-Type", "application/json")]), body }
}

///|
/// userinfo 固定向量：unionId 在场。
fn dingtalk_userinfo_ok() -> @core.HttpResponse {
  let body = "{\"nick\":\"张三\",\"avatarUrl\":\"https://static.example/avatar.png\"," +
    "\"openId\":\"o-123\",\"unionId\":\"u-456\",\"email\":\"zs@example.com\",\"stateCode\":\"86\"}"
  { status: 200, headers: Map([("Content-Type", "application/json")]), body }
}

///|
/// userinfo 固定向量：仅 openId（unionId 缺席 → Degraded）。
fn dingtalk_userinfo_openid_only() -> @core.HttpResponse {
  let body = "{\"nick\":\"李四\",\"openId\":\"o-789\"}"
  { status: 200, headers: Map([("Content-Type", "application/json")]), body }
}

///|
/// 一条「固定向量」配置：mock 队列 = [token 成功, userinfo]，端点指向 mock。
fn dingtalk_fixed_config(responses : Array[@core.HttpResponse]) -> @dingtalk.DingTalkConfig {
  let client : &@core.HttpClient = @contract.MockHttpClient::new(responses)
  let clock : &@core.Clock = @contract.FixedClock::new(@contract.fixed_now_unix())
  @dingtalk.DingTalkConfig::new("client-1", "secret-1", "https://app.example/cb").with_endpoints(
    "mock://authorize",
    "mock://token",
    "mock://me",
  ).with_http(client).with_clock(clock)
}

// ════════ 组合 A：默认装配（零注入）+ 国际版预设 ════════

///|
/// 🅰 默认装配走**国内站**端点；组 URL 含 PKCE（钉钉 v2 支持）。
async test "dingtalk(A): default config assembles the CN authorization URL" {
  let config = @dingtalk.DingTalkConfig::new(
    "client-1",
    "secret-1",
    "https://app.example/cb",
  )
  let secrets : @core.SuppliedSecrets = {
    state: Some("st-123"),
    code_verifier: Some("verifier-1"),
    nonce: None,
  }
  let start = @dingtalk.begin_auth(config, secrets)
  let url = start.url
  assert_true(url.has_prefix("https://login.dingtalk.com/oauth2/auth?"))
  assert_true(url.contains("client_id=client-1"))
  assert_true(url.contains("redirect_uri=https%3A%2F%2Fapp.example%2Fcb"))
  assert_true(url.contains("response_type=code"))
  assert_true(url.contains("scope=openid"))
  assert_true(url.contains("state=st-123"))
  assert_true(url.contains("code_challenge_method=S256"))
  @debug.assert_eq(start.state, "st-123")
  @debug.assert_eq(start.code_verifier, Some("verifier-1"))
  // 钉钉无 OIDC id_token，无 nonce 语义。
  @debug.assert_eq(start.nonce, None)
}

// ════════ 组合 B：注入能力 seam ════════

///|
/// 🅱 固定向量 → 确定性身份；换 token 是 **JSON 请求体**；userinfo 用**自定义头**鉴权。
async test "dingtalk(B): complete_auth yields a deterministic identity" {
  let client = @contract.MockHttpClient::new([
    dingtalk_token_ok(),
    dingtalk_userinfo_ok(),
  ])
  let clock : &@core.Clock = @contract.FixedClock::new(@contract.fixed_now_unix())
  let config = @dingtalk.DingTalkConfig::new("client-1", "secret-1", "https://app.example/cb").with_endpoints(
    "mock://authorize",
    "mock://token",
    "mock://me",
  ).with_http(client).with_clock(clock)
  let start = @dingtalk.begin_auth(config, {
    state: Some("st-123"),
    code_verifier: Some("verifier-1"),
    nonce: None,
  })
  let callback = @core.CallbackParams::from_query_string(
    "code=auth-code-1&state=st-123",
  )
  let identity = @dingtalk.complete_auth(config, callback, start)
  @debug.assert_eq(identity.provider, "dingtalk")
  // unionId 优先（跨应用稳定）。
  @debug.assert_eq(identity.uid, "u-456")
  match identity.uid_kind {
    @core.UidKind::Stable => ()
    @core.UidKind::Degraded => abort("unionId present must be Stable")
  }
  @debug.assert_eq(identity.display_name, Some("张三"))
  @debug.assert_eq(identity.avatar, Some("https://static.example/avatar.png"))
  @debug.assert_eq(identity.email, Some("zs@example.com"))
  let reqs = client.recorded_requests()
  @debug.assert_eq(reqs.length(), 2)
  // 请求 0：换 token —— JSON 体、驼峰字段、含 PKCE codeVerifier。
  let token_req = reqs[0]
  @debug.assert_eq(token_req.url, "mock://token")
  @debug.assert_eq(
    token_req.headers.get("Content-Type"),
    Some("application/json"),
  )
  let token_body = match token_req.body {
    Some(b) => b
    None => abort("dingtalk token request must carry a JSON body")
  }
  assert_true(token_body.contains("\"clientId\":\"client-1\""))
  assert_true(token_body.contains("\"clientSecret\":\"secret-1\""))
  assert_true(token_body.contains("\"grantType\":\"authorization_code\""))
  assert_true(token_body.contains("\"code\":\"auth-code-1\""))
  assert_true(token_body.contains("\"codeVerifier\":\"verifier-1\""))
  // 请求 1：userinfo —— 自定义头鉴权（非 Authorization）+ unionId=true。
  let me_req = reqs[1]
  @debug.assert_eq(me_req.url, "mock://me?unionId=true")
  @debug.assert_eq(
    me_req.headers.get("x-acs-dingtalk-access-token"),
    Some("dt-at-1"),
  )
  @debug.assert_eq(me_req.headers.get("Authorization"), None)
}

///|
/// 仅拿到 `openId`（unionId 缺席）→ `Degraded`（微信 unionid 先例）。
async test "dingtalk: openId-only identity is Degraded" {
  let client = @contract.MockHttpClient::new([
    dingtalk_token_ok(),
    dingtalk_userinfo_openid_only(),
  ])
  let clock : &@core.Clock = @contract.FixedClock::new(@contract.fixed_now_unix())
  let config = @dingtalk.DingTalkConfig::new("client-1", "secret-1", "https://app.example/cb").with_endpoints(
    "mock://authorize",
    "mock://token",
    "mock://me",
  ).with_http(client).with_clock(clock)
  let start = @dingtalk.begin_auth(config, {
    state: Some("st-123"),
    code_verifier: Some("verifier-1"),
    nonce: None,
  })
  let callback = @core.CallbackParams::from_query_string(
    "code=c&state=st-123",
  )
  let identity = @dingtalk.complete_auth(config, callback, start)
  @debug.assert_eq(identity.uid, "o-789")
  match identity.uid_kind {
    @core.UidKind::Degraded => ()
    @core.UidKind::Stable => abort("openId-only must be Degraded")
  }
}

// ════════ 错误向量 ════════

///|
/// `state` 不符 → `StateMismatch`（且**不**发起任何网络请求）。
async test "dingtalk: state mismatch is rejected" {
  let config = dingtalk_fixed_config([dingtalk_token_ok(), dingtalk_userinfo_ok()])
  let start = @dingtalk.begin_auth(config, {
    state: Some("st-123"),
    code_verifier: Some("verifier-1"),
    nonce: None,
  })
  let callback = @core.CallbackParams::from_query_string("code=c&state=WRONG")
  let code = try {
    let _ = @dingtalk.complete_auth(config, callback, start)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "state_mismatch")
}

///|
/// 回调缺 `code` → `MissingParam`。
async test "dingtalk: missing code is rejected as missing_param" {
  let config = dingtalk_fixed_config([dingtalk_token_ok(), dingtalk_userinfo_ok()])
  let start = @dingtalk.begin_auth(config, {
    state: Some("st-123"),
    code_verifier: Some("verifier-1"),
    nonce: None,
  })
  let callback = @core.CallbackParams::from_query_string("state=st-123")
  let code = try {
    let _ = @dingtalk.complete_auth(config, callback, start)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "missing_param")
}

///|
/// token 端点非 2xx：钉钉 v1.0 错误体 `{code, message}` → `ProviderError`。
async test "dingtalk: token endpoint error is normalized to provider_error" {
  let config = dingtalk_fixed_config([
    {
      status: 400,
      headers: Map([("Content-Type", "application/json")]),
      body: "{\"code\":\"InvalidParameter\",\"message\":\"invalid authCode\"}",
    },
  ])
  let start = @dingtalk.begin_auth(config, {
    state: Some("st-123"),
    code_verifier: Some("verifier-1"),
    nonce: None,
  })
  let callback = @core.CallbackParams::from_query_string(
    "code=c&state=st-123",
  )
  let code = try {
    let _ = @dingtalk.complete_auth(config, callback, start)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "provider_error")
}

// ════════ 随机源 ════════

///|
/// 随机源仅经注入 seam：缺省项由 `FixedRandomSource` 生成，结果可重放。
async test "dingtalk: default secrets come from the injected RandomSource" {
  let random : &@core.RandomSource = FixedRandomSource::{
    data: Bytes::from_array([b'a', b'b', b'c', b'd']),
  }
  let config = @dingtalk.DingTalkConfig::new(
    "client-1",
    "secret-1",
    "https://app.example/cb",
  ).with_random(random)
  let a = @dingtalk.begin_auth(config, {
    state: None,
    code_verifier: None,
    nonce: None,
  })
  let b = @dingtalk.begin_auth(config, {
    state: None,
    code_verifier: None,
    nonce: None,
  })
  @debug.assert_eq(a.state, b.state)
  @debug.assert_eq(a.code_verifier, b.code_verifier)
}

///|
/// 🔴 空 `unionId` 视为缺失（同微信 `non_empty_opt` 先例）：降级到 `openId` 且
/// `Degraded`——绝不允许 `uid=""` 且标 `Stable`。
async test "dingtalk: empty unionId falls back to openId as Degraded" {
  let identity = @dingtalk.dingtalk_identity(
    "{\"nick\":\"n\",\"unionId\":\"\",\"openId\":\"ou-1\"}",
  )
  @debug.assert_eq(identity.uid, "ou-1")
  match identity.uid_kind {
    @core.UidKind::Degraded => ()
    @core.UidKind::Stable => abort("empty unionId must not be Stable")
  }
}

///|
/// 🔴 信封 `code` 为**数值**形态（非字符串）时同样归一为 `ProviderError`。
async test "dingtalk: numeric envelope code is normalized to provider_error" {
  let code = try {
    let _ = @dingtalk.dingtalk_identity(
      "{\"code\":60104,\"message\":\"not exist\"}",
    )
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "provider_error")
}
