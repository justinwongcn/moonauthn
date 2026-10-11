//! moonauth / provider/feishu —— 黑盒测试（facade / 归一化 / 国际版预设 / SDK-01 组合）。
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
/// token 响应固定向量（v2 顶层、snake_case）。
fn feishu_token_ok() -> @core.HttpResponse {
  let body = "{\"access_token\":\"u-at-1\",\"token_type\":\"Bearer\",\"expires_in\":6900,\"refresh_token\":\"u-rt-1\",\"scope\":\"\"}"
  { status: 200, headers: Map([("Content-Type", "application/json")]), body }
}

///|
/// userinfo 固定向量：`{code,msg,data}` 信封 + union_id 在场。
fn feishu_userinfo_ok() -> @core.HttpResponse {
  let body = "{\"code\":0,\"msg\":\"success\",\"data\":{\"name\":\"李四\"," +
    "\"open_id\":\"ou-123\",\"union_id\":\"on-456\"," +
    "\"email\":\"ls@example.com\",\"avatar_url\":\"https://s3.example/a.png\"}}"
  { status: 200, headers: Map([("Content-Type", "application/json")]), body }
}

///|
/// userinfo 固定向量：仅 open_id（union_id 缺席 → Degraded）。
fn feishu_userinfo_openid_only() -> @core.HttpResponse {
  let body = "{\"code\":0,\"msg\":\"success\",\"data\":{\"name\":\"王五\",\"open_id\":\"ou-789\"}}"
  { status: 200, headers: Map([("Content-Type", "application/json")]), body }
}

///|
/// 一条「固定向量」配置：mock 队列 = [token 成功, userinfo]，端点指向 mock。
fn feishu_fixed_config(responses : Array[@core.HttpResponse]) -> @feishu.FeishuConfig {
  let client : &@core.HttpClient = @contract.MockHttpClient::new(responses)
  let clock : &@core.Clock = @contract.FixedClock::new(@contract.fixed_now_unix())
  @feishu.FeishuConfig::new("cli-1", "sec-1", "https://app.example/cb").with_endpoints(
    "mock://authorize",
    "mock://token",
    "mock://me",
  ).with_http(client).with_clock(clock)
}

// ════════ 组合 A：默认装配（零注入）+ 国际版预设 ════════

///|
/// 🅰 默认装配走**飞书**端点；scopes 默认空 → URL 不含 scope 参数。
async test "feishu(A): default config assembles the feishu.cn authorization URL" {
  let config = @feishu.FeishuConfig::new("cli-1", "sec-1", "https://app.example/cb")
  let secrets : @core.SuppliedSecrets = {
    state: Some("st-123"),
    code_verifier: Some("verifier-1"),
    nonce: None,
  }
  let start = @feishu.begin_auth(config, secrets)
  let url = start.url
  assert_true(url.has_prefix("https://accounts.feishu.cn/open-apis/authen/v1/authorize?"))
  assert_true(url.contains("client_id=cli-1"))
  assert_true(url.contains("redirect_uri=https%3A%2F%2Fapp.example%2Fcb"))
  assert_true(url.contains("response_type=code"))
  assert_true(url.contains("state=st-123"))
  assert_true(url.contains("code_challenge_method=S256"))
  @debug.assert_eq(start.code_verifier, Some("verifier-1"))
  @debug.assert_eq(start.nonce, None)
}

///|
/// 🅰 `with_lark()` 一键切 **Lark 国际版**（`*.larksuite.com`）端点预设，路径同构。
async test "feishu(A): with_lark switches to the larksuite.com preset" {
  let config = @feishu.FeishuConfig::new("cli-1", "sec-1", "https://app.example/cb").with_lark()
  let secrets : @core.SuppliedSecrets = {
    state: Some("st-123"),
    code_verifier: Some("verifier-1"),
    nonce: None,
  }
  let start = @feishu.begin_auth(config, secrets)
  assert_true(
    start.url.has_prefix("https://accounts.larksuite.com/open-apis/authen/v1/authorize?"),
  )
  assert_true(start.url.contains("client_id=cli-1"))
}

// ════════ 组合 B：注入能力 seam ════════

///|
/// 🅱 固定向量 → 确定性身份；换 token 是 **JSON 请求体**（snake_case）；
/// userinfo 信封壳解包；union_id 优先。
async test "feishu(B): complete_auth yields a deterministic identity" {
  let client = @contract.MockHttpClient::new([
    feishu_token_ok(),
    feishu_userinfo_ok(),
  ])
  let clock : &@core.Clock = @contract.FixedClock::new(@contract.fixed_now_unix())
  let config = @feishu.FeishuConfig::new("cli-1", "sec-1", "https://app.example/cb").with_endpoints(
    "mock://authorize",
    "mock://token",
    "mock://me",
  ).with_http(client).with_clock(clock)
  let start = @feishu.begin_auth(config, {
    state: Some("st-123"),
    code_verifier: Some("verifier-1"),
    nonce: None,
  })
  let callback = @core.CallbackParams::from_query_string(
    "code=auth-code-1&state=st-123",
  )
  let identity = @feishu.complete_auth(config, callback, start)
  @debug.assert_eq(identity.provider, "feishu")
  @debug.assert_eq(identity.uid, "on-456")
  match identity.uid_kind {
    @core.UidKind::Stable => ()
    @core.UidKind::Degraded => abort("union_id present must be Stable")
  }
  @debug.assert_eq(identity.display_name, Some("李四"))
  @debug.assert_eq(identity.avatar, Some("https://s3.example/a.png"))
  @debug.assert_eq(identity.email, Some("ls@example.com"))
  let reqs = client.recorded_requests()
  @debug.assert_eq(reqs.length(), 2)
  // 请求 0：换 token —— JSON 体、snake_case 字段、含 PKCE codeVerifier。
  let token_req = reqs[0]
  @debug.assert_eq(token_req.url, "mock://token")
  @debug.assert_eq(
    token_req.headers.get("Content-Type"),
    Some("application/json"),
  )
  let token_body = match token_req.body {
    Some(b) => b
    None => abort("feishu token request must carry a JSON body")
  }
  assert_true(token_body.contains("\"grant_type\":\"authorization_code\""))
  assert_true(token_body.contains("\"client_id\":\"cli-1\""))
  assert_true(token_body.contains("\"client_secret\":\"sec-1\""))
  assert_true(token_body.contains("\"code\":\"auth-code-1\""))
  assert_true(token_body.contains("\"redirect_uri\":\"https://app.example/cb\""))
  assert_true(token_body.contains("\"code_verifier\":\"verifier-1\""))
  // 请求 1：userinfo —— Bearer 鉴权。
  let me_req = reqs[1]
  @debug.assert_eq(me_req.url, "mock://me")
  @debug.assert_eq(me_req.headers.get("Authorization"), Some("Bearer u-at-1"))
}

///|
/// 仅拿到 `open_id`（union_id 缺席）→ `Degraded`（微信 unionid 先例）。
async test "feishu: open_id-only identity is Degraded" {
  let config = feishu_fixed_config([
    feishu_token_ok(),
    feishu_userinfo_openid_only(),
  ])
  let start = @feishu.begin_auth(config, {
    state: Some("st-123"),
    code_verifier: Some("verifier-1"),
    nonce: None,
  })
  let callback = @core.CallbackParams::from_query_string(
    "code=c&state=st-123",
  )
  let identity = @feishu.complete_auth(config, callback, start)
  @debug.assert_eq(identity.uid, "ou-789")
  match identity.uid_kind {
    @core.UidKind::Degraded => ()
    @core.UidKind::Stable => abort("open_id-only must be Degraded")
  }
}

// ════════ 错误向量 ════════

///|
/// `state` 不符 → `StateMismatch`（且**不**发起任何网络请求）。
async test "feishu: state mismatch is rejected" {
  let config = feishu_fixed_config([feishu_token_ok(), feishu_userinfo_ok()])
  let start = @feishu.begin_auth(config, {
    state: Some("st-123"),
    code_verifier: Some("verifier-1"),
    nonce: None,
  })
  let callback = @core.CallbackParams::from_query_string("code=c&state=WRONG")
  let code = try {
    let _ = @feishu.complete_auth(config, callback, start)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "state_mismatch")
}

///|
/// 回调缺 `code` → `MissingParam`。
async test "feishu: missing code is rejected as missing_param" {
  let config = feishu_fixed_config([feishu_token_ok(), feishu_userinfo_ok()])
  let start = @feishu.begin_auth(config, {
    state: Some("st-123"),
    code_verifier: Some("verifier-1"),
    nonce: None,
  })
  let callback = @core.CallbackParams::from_query_string("state=st-123")
  let code = try {
    let _ = @feishu.complete_auth(config, callback, start)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "missing_param")
}

///|
/// token 端点非 2xx：飞书 v2 标准 OAuth 错误体 → `ProviderError`。
async test "feishu: token endpoint error is normalized to provider_error" {
  let config = feishu_fixed_config([
    {
      status: 400,
      headers: Map([("Content-Type", "application/json")]),
      body: "{\"error\":\"invalid_grant\",\"error_description\":\"code has been used\"}",
    },
  ])
  let start = @feishu.begin_auth(config, {
    state: Some("st-123"),
    code_verifier: Some("verifier-1"),
    nonce: None,
  })
  let callback = @core.CallbackParams::from_query_string(
    "code=c&state=st-123",
  )
  let code = try {
    let _ = @feishu.complete_auth(config, callback, start)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "provider_error")
}

///|
/// userinfo 信封 `code != 0`（业务错误，HTTP 200）→ `ProviderError`。
async test "feishu: userinfo envelope error is normalized to provider_error" {
  let config = feishu_fixed_config([
    feishu_token_ok(),
    {
      status: 200,
      headers: Map([("Content-Type", "application/json")]),
      body: "{\"code\":99991663,\"msg\":\"token is invalid\"}",
    },
  ])
  let start = @feishu.begin_auth(config, {
    state: Some("st-123"),
    code_verifier: Some("verifier-1"),
    nonce: None,
  })
  let callback = @core.CallbackParams::from_query_string(
    "code=c&state=st-123",
  )
  let code = try {
    let _ = @feishu.complete_auth(config, callback, start)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "provider_error")
}

// ════════ 随机源 ════════

///|
/// 随机源仅经注入 seam：缺省项由 `FixedRandomSource` 生成，结果可重放。
async test "feishu: default secrets come from the injected RandomSource" {
  let random : &@core.RandomSource = FixedRandomSource::{
    data: Bytes::from_array([b'a', b'b', b'c', b'd']),
  }
  let config = @feishu.FeishuConfig::new("cli-1", "sec-1", "https://app.example/cb").with_random(
    random,
  )
  let a = @feishu.begin_auth(config, {
    state: None,
    code_verifier: None,
    nonce: None,
  })
  let b = @feishu.begin_auth(config, {
    state: None,
    code_verifier: None,
    nonce: None,
  })
  @debug.assert_eq(a.state, b.state)
  @debug.assert_eq(a.code_verifier, b.code_verifier)
}
