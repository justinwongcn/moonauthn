//! moonauth / provider/discord —— 黑盒测试（facade / 归一化 / SDK-01 组合 A/B/C）。
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
/// `/users/@me` 固定向量：带 global_name / email / 静态头像哈希。
fn discord_user_ok() -> @core.HttpResponse {
  let body = "{\"id\":\"80351110224678912\",\"username\":\"dll\"," +
    "\"global_name\":\"DLL\",\"avatar\":\"d5efa99b1407dd11fd6f5d4e3af38850\"," +
    "\"email\":\"dll@example.com\",\"verified\":true}"
  { status: 200, headers: Map([("Content-Type", "application/json")]), body }
}

///|
/// token 响应（标准 form 换取，回 JSON）。
fn discord_token_ok() -> @core.HttpResponse {
  let body = "{\"access_token\":\"dc_at-1\",\"token_type\":\"Bearer\",\"expires_in\":604800,\"scope\":\"identify email\"}"
  { status: 200, headers: Map([("Content-Type", "application/json")]), body }
}

///|
/// 一条「固定向量」配置：mock 队列 = [token 成功, /users/@me]，端点指向 mock。
fn discord_fixed_config(responses : Array[@core.HttpResponse]) -> @discord.DiscordConfig {
  let client : &@core.HttpClient = @contract.MockHttpClient::new(responses)
  let clock : &@core.Clock = @contract.FixedClock::new(@contract.fixed_now_unix())
  @discord.DiscordConfig::new("client-1", "https://app.example/cb").with_endpoints(
    "mock://authorize",
    "mock://token",
    "mock://me",
  ).with_http(client).with_clock(clock)
}

// ════════ 组合 A：默认装配（零注入） ════════

///|
/// 🅰 默认装配：`DiscordConfig::new` 直接可用；组 URL 走 Discord 官方端点（含 PKCE）。
async test "discord(A): default config assembles the official authorization URL" {
  let config = @discord.DiscordConfig::new("client-1", "https://app.example/cb")
  let secrets : @core.SuppliedSecrets = {
    state: Some("st-123"),
    code_verifier: Some("verifier-1abcdefghijklmnopqrstuvwxyz0123456789-._~"),
    nonce: None,
  }
  let start = @discord.begin_auth(config, secrets)
  let url = start.url
  assert_true(url.has_prefix("https://discord.com/oauth2/authorize?"))
  assert_true(url.contains("client_id=client-1"))
  assert_true(url.contains("redirect_uri=https%3A%2F%2Fapp.example%2Fcb"))
  assert_true(url.contains("response_type=code"))
  assert_true(url.contains("scope=identify%20email"))
  assert_true(url.contains("state=st-123"))
  assert_true(url.contains("code_challenge_method=S256"))
  @debug.assert_eq(start.state, "st-123")
  @debug.assert_eq(start.code_verifier, Some("verifier-1abcdefghijklmnopqrstuvwxyz0123456789-._~"))
  // Discord 无 OIDC id_token，无 nonce 语义。
  @debug.assert_eq(start.nonce, None)
}

// ════════ 组合 B：注入能力 seam ════════

///|
/// 🅱 注入 `HttpClient` / `Clock` / `RandomSource`：固定向量 → 确定性 `ExternalIdentity`。
async test "discord(B): complete_auth yields a deterministic identity" {
  let config = discord_fixed_config([discord_token_ok(), discord_user_ok()])
  let start = @discord.begin_auth(config, {
    state: Some("st-123"),
    code_verifier: Some("verifier-1abcdefghijklmnopqrstuvwxyz0123456789-._~"),
    nonce: None,
  })
  let callback = @core.CallbackParams::from_query_string(
    "code=auth-code-1&state=st-123",
  )
  let identity = @discord.complete_auth(config, callback, start)
  @debug.assert_eq(identity.provider, "discord")
  // id 是字符串雪片号。
  @debug.assert_eq(identity.uid, "80351110224678912")
  match identity.uid_kind {
    @core.UidKind::Stable => ()
    @core.UidKind::Degraded => abort("discord uid must be Stable")
  }
  @debug.assert_eq(identity.email, Some("dll@example.com"))
  @debug.assert_eq(identity.email_verified, true)
  @debug.assert_eq(identity.display_name, Some("DLL"))
  // 静态哈希 → .png。
  @debug.assert_eq(
    identity.avatar,
    Some("https://cdn.discordapp.com/avatars/80351110224678912/d5efa99b1407dd11fd6f5d4e3af38850.png"),
  )
}

///|
/// `global_name` 为 `null` 时 `display_name` 回退 `username`；`a_` 前缀哈希 → `.gif`。
async test "discord: global_name fallback and animated avatar extension" {
  let body = "{\"id\":\"1\",\"username\":\"only-name\",\"global_name\":null," +
    "\"avatar\":\"a_9f2c8d\"}"
  let identity = discord_identity_from(body)
  @debug.assert_eq(identity.display_name, Some("only-name"))
  @debug.assert_eq(
    identity.avatar,
    Some("https://cdn.discordapp.com/avatars/1/a_9f2c8d.gif"),
  )
}

///|
/// avatar 哈希为 `null` → `avatar = None`（默认头像公式需 64 位雪片运算，库不代算）。
async test "discord: null avatar hash yields no avatar" {
  let identity = discord_identity_from(
    "{\"id\":\"2\",\"username\":\"bare\",\"global_name\":null,\"avatar\":null}",
  )
  @debug.assert_eq(identity.avatar, None)
}

///|
/// 测试辅助：归一化一份 JSON 文本。
fn discord_identity_from(body : String) -> @core.ExternalIdentity raise {
  @discord.discord_identity(body)
}

// ════════ 错误向量 ════════

///|
/// `state` 不符 → `StateMismatch`（且**不**发起任何网络请求）。
async test "discord: state mismatch is rejected" {
  let config = discord_fixed_config([discord_token_ok(), discord_user_ok()])
  let start = @discord.begin_auth(config, {
    state: Some("st-123"),
    code_verifier: Some("verifier-1abcdefghijklmnopqrstuvwxyz0123456789-._~"),
    nonce: None,
  })
  let callback = @core.CallbackParams::from_query_string("code=c&state=WRONG")
  let code = try {
    let _ = @discord.complete_auth(config, callback, start)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "state_mismatch")
}

///|
/// 回调缺 `code` → `MissingParam`。
async test "discord: missing code is rejected as missing_param" {
  let config = discord_fixed_config([discord_token_ok(), discord_user_ok()])
  let start = @discord.begin_auth(config, {
    state: Some("st-123"),
    code_verifier: Some("verifier-1abcdefghijklmnopqrstuvwxyz0123456789-._~"),
    nonce: None,
  })
  let callback = @core.CallbackParams::from_query_string("state=st-123")
  let code = try {
    let _ = @discord.complete_auth(config, callback, start)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "missing_param")
}

///|
/// token 端点非 2xx → provider 业务错误码归一为 `ProviderError`。
async test "discord: token endpoint error is normalized to provider_error" {
  let config = discord_fixed_config([
    {
      status: 400,
      headers: Map([("Content-Type", "application/json")]),
      body: "{\"error\":\"invalid_grant\",\"error_description\":\"Invalid OAuth2 access_token\"}",
    },
  ])
  let start = @discord.begin_auth(config, {
    state: Some("st-123"),
    code_verifier: Some("verifier-1abcdefghijklmnopqrstuvwxyz0123456789-._~"),
    nonce: None,
  })
  let callback = @core.CallbackParams::from_query_string(
    "code=c&state=st-123",
  )
  let code = try {
    let _ = @discord.complete_auth(config, callback, start)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "provider_error")
}

// ════════ 组合 C：整 provider 替换（SDK-01） ════════

///|
/// 一个「完全自造」的 Discord 实现，演示整替换点。
struct StubDiscordProvider {}

///|
impl @discord.DiscordProvider for StubDiscordProvider with fn begin_auth(self, secrets) {
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
impl @discord.DiscordProvider for StubDiscordProvider with fn complete_auth(
  self,
  callback,
  expected,
) {
  let _ = self
  let _ = callback
  let _ = expected
  {
    provider: "discord",
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
/// 🅲 整替换：把 `StubDiscordProvider` 喂给对 trait 泛型的业务代码，行为随之改变。
async test "discord(C): a replacement provider plugs in via the trait" {
  let provider : &@discord.DiscordProvider = StubDiscordProvider::{  }
  let start = drive_discord(provider, {
    state: None,
    code_verifier: None,
    nonce: None,
  })
  @debug.assert_eq(start.url, "https://stub.example/authorize?client_id=stub")
  @debug.assert_eq(start.state, "stub-state")
}

///|
/// 对 `DiscordProvider` trait **泛型**的业务代码：与具体实现无关。
async fn drive_discord(
  provider : &@discord.DiscordProvider,
  secrets : @core.SuppliedSecrets,
) -> @core.AuthStart {
  provider.begin_auth(secrets)
}

///|
/// 随机源仅经注入 seam：缺省项由 `FixedRandomSource` 生成，结果可重放。
async test "discord: default secrets come from the injected RandomSource" {
  let random : &@core.RandomSource = FixedRandomSource::{
    data: Bytes::from_array([b'a', b'b', b'c', b'd']),
  }
  let config = @discord.DiscordConfig::new("client-1", "https://app.example/cb").with_random(
    random,
  )
  let a = @discord.begin_auth(config, {
    state: None,
    code_verifier: None,
    nonce: None,
  })
  let b = @discord.begin_auth(config, {
    state: None,
    code_verifier: None,
    nonce: None,
  })
  @debug.assert_eq(a.state, b.state)
  @debug.assert_eq(a.code_verifier, b.code_verifier)
}

///|
/// 🔴 头像 URL 的 uid / hash 必须百分号编码（黑客审计第 2 轮确认修复）：
/// 异常形态（含 `/` `?`）不得篡改 CDN URL。
async test "discord: avatar url components are percent-encoded" {
  let body = "{\"id\":\"12345\",\"global_name\":\"Dev\",\"username\":\"dev\",\"avatar\":\"a_hostile/path?x\"}"
  let identity = @discord.discord_identity(body)
  let avatar = match identity.avatar {
    Some(a) => a
    None => abort("discord: avatar should be present")
  }
  assert_true(avatar.has_prefix("https://cdn.discordapp.com/avatars/12345/"))
  assert_true(avatar.contains("a_hostile%2Fpath%3Fx"))
  assert_true(avatar.contains(".gif"))
  // 正常形态（hex 哈希）不受影响
  let normal = @discord.discord_identity("{\"id\":\"12345\",\"avatar\":\"abc123\"}")
  @debug.assert_eq(
    normal.avatar,
    Some("https://cdn.discordapp.com/avatars/12345/abc123.png"),
  )
}
