//! moonauth / qa_verify —— 扩展 provider（github / discord / dingtalk / feishu）的
//! **独立对抗性验证**（延续 t03 的形态：不读 provider 内部，只对公开 facade 出招）。
//!
//! 与各 provider 包内 `_test.mbt` 的分工：包内测试覆盖「happy path + 本包解析细节」；
//! 本文件站在**库外**视角复核：授权 URL（含国际版预设）、错误归一、`state` 防线、
//! 随机只经注入 seam。
//!
//! 全部**离线**：HTTP 走 `@contract.MockHttpClient`（队空即抛 `Network`，杜绝误走真网）。

// ════════ 公共构件 ════════

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
/// 统一取错误码（库外视角：只看 `auth_error_code`；仅用于同步函数）。
fn error_code(f : () -> Unit raise @core.AuthError) -> String {
  try {
    f()
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
}

// ════════ §1 授权 URL（每家一份，含国际版预设） ════════

///|
/// §1.1 github：官方端点 + PKCE + 无 nonce。
async test "ext/github: authorization URL is the official endpoint with PKCE" {
  let config = @github.GitHubConfig::new("cid", "https://app.example/cb")
  let start = @github.begin_auth(config, {
    state: Some("st"),
    code_verifier: Some("verifier-1"),
    nonce: None,
  })
  assert_true(start.url.has_prefix("https://github.com/login/oauth/authorize?"))
  assert_true(start.url.contains("client_id=cid"))
  assert_true(start.url.contains("code_challenge_method=S256"))
  assert_true(start.url.contains("state=st"))
  assert_true(!(start.url.contains("nonce=")))
}

///|
/// §1.2 discord：官方端点 + PKCE（仅 S256）。
async test "ext/discord: authorization URL is the official endpoint with PKCE" {
  let config = @discord.DiscordConfig::new("cid", "https://app.example/cb")
  let start = @discord.begin_auth(config, {
    state: Some("st"),
    code_verifier: Some("verifier-1"),
    nonce: None,
  })
  assert_true(start.url.has_prefix("https://discord.com/oauth2/authorize?"))
  assert_true(start.url.contains("client_id=cid"))
  assert_true(start.url.contains("code_challenge_method=S256"))
  assert_true(!(start.url.contains("nonce=")))
}

///|
/// §1.3 dingtalk：国内站端点 + PKCE。
///
/// 🔴 国际站不内置预设（OAuth2 端点未从官方文档核实，诚实优先不做推测实现），
/// 故无国际站断言；国际站部署用 `with_endpoints` 自行配置。
async test "ext/dingtalk: CN default endpoint with PKCE" {
  let secrets : @core.SuppliedSecrets = {
    state: Some("st"),
    code_verifier: Some("verifier-1"),
    nonce: None,
  }
  let cn = @dingtalk.DingTalkConfig::new("cid", "csec", "https://app.example/cb")
  let cn_start = @dingtalk.begin_auth(cn, secrets)
  assert_true(cn_start.url.has_prefix("https://login.dingtalk.com/oauth2/auth?"))
  assert_true(cn_start.url.contains("code_challenge_method=S256"))
}

///|
/// §1.4 feishu：飞书端点 + PKCE；`with_lark()` 切 Lark `larksuite.com`。
async test "ext/feishu: feishu.cn default and larksuite.com lark preset" {
  let secrets : @core.SuppliedSecrets = {
    state: Some("st"),
    code_verifier: Some("verifier-1"),
    nonce: None,
  }
  let cn = @feishu.FeishuConfig::new("aid", "asec", "https://app.example/cb")
  let cn_start = @feishu.begin_auth(cn, secrets)
  assert_true(
    cn_start.url.has_prefix("https://accounts.feishu.cn/open-apis/authen/v1/authorize?"),
  )
  assert_true(cn_start.url.contains("code_challenge_method=S256"))
  let lark = @feishu.FeishuConfig::new("aid", "asec", "https://app.example/cb").with_lark()
  let lark_start = @feishu.begin_auth(lark, secrets)
  assert_true(
    lark_start.url.has_prefix("https://accounts.larksuite.com/open-apis/authen/v1/authorize?"),
  )
}

// ════════ §2 state 防线（篡改 state 一律 `StateMismatch`，零网络请求） ════════

///|
/// §2 github / discord / dingtalk / feishu 四家统一：`state` 是库级安全语义。
async test "ext/four providers: tampered state is always state_mismatch" {
  // github
  let gh_config = @github.GitHubConfig::new("cid", "https://app.example/cb").with_endpoints(
    "mock://authz",
    "mock://token",
    "mock://user",
    "mock://emails",
  ).with_http(
    @contract.MockHttpClient::new([]),
  ).with_clock(@contract.FixedClock::new(1700000000))
  let gh_start = @github.begin_auth(gh_config, {
    state: Some("st"),
    code_verifier: Some("v"),
    nonce: None,
  })
  let gh_code = try {
    let _ = @github.complete_auth(
      gh_config,
      @core.CallbackParams::from_query_string("code=c&state=BAD"),
      gh_start,
    )
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(gh_code, "state_mismatch")
  // discord
  let dc_config = @discord.DiscordConfig::new("cid", "https://app.example/cb").with_endpoints(
    "mock://authz",
    "mock://token",
    "mock://me",
  ).with_http(
    @contract.MockHttpClient::new([]),
  ).with_clock(@contract.FixedClock::new(1700000000))
  let dc_start = @discord.begin_auth(dc_config, {
    state: Some("st"),
    code_verifier: Some("v"),
    nonce: None,
  })
  let dc_code = try {
    let _ = @discord.complete_auth(
      dc_config,
      @core.CallbackParams::from_query_string("code=c&state=BAD"),
      dc_start,
    )
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(dc_code, "state_mismatch")
  // dingtalk
  let dt_config = @dingtalk.DingTalkConfig::new("cid", "csec", "https://app.example/cb").with_endpoints(
    "mock://authz",
    "mock://token",
    "mock://me",
  ).with_http(
    @contract.MockHttpClient::new([]),
  ).with_clock(@contract.FixedClock::new(1700000000))
  let dt_start = @dingtalk.begin_auth(dt_config, {
    state: Some("st"),
    code_verifier: Some("v"),
    nonce: None,
  })
  let dt_code = try {
    let _ = @dingtalk.complete_auth(
      dt_config,
      @core.CallbackParams::from_query_string("code=c&state=BAD"),
      dt_start,
    )
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(dt_code, "state_mismatch")
  // feishu
  let fs_config = @feishu.FeishuConfig::new("aid", "asec", "https://app.example/cb").with_endpoints(
    "mock://authz",
    "mock://token",
    "mock://me",
  ).with_http(
    @contract.MockHttpClient::new([]),
  ).with_clock(@contract.FixedClock::new(1700000000))
  let fs_start = @feishu.begin_auth(fs_config, {
    state: Some("st"),
    code_verifier: Some("v"),
    nonce: None,
  })
  let fs_code = try {
    let _ = @feishu.complete_auth(
      fs_config,
      @core.CallbackParams::from_query_string("code=c&state=BAD"),
      fs_start,
    )
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(fs_code, "state_mismatch")
}

// ════════ §3 归一化对抗样本（不依赖 provider 包内测试的向量） ════════

///|
/// §3.1 dingtalk：unionId 缺席 → `Degraded`；错误体归一。
async test "ext/dingtalk: normalization and error shapes" {
  // unionId 缺席 → Degraded。
  let id1 = @dingtalk.dingtalk_identity("{\"nick\":\"n\",\"openId\":\"o-1\"}")
  @debug.assert_eq(id1.uid, "o-1")
  assert_true(id1.uid_kind is @core.UidKind::Degraded)
  // 错误体 → ProviderError。
  let code = error_code(() => {
    let _ = @dingtalk.dingtalk_parse_token(
      "{\"code\":\"AccessDenied\",\"message\":\"no\"}",
    )
    ()
  })
  @debug.assert_eq(code, "provider_error")
}

///|
/// §3.2 feishu：信封 `code != 0` → `ProviderError`；`union_id` 优先 → `Stable`。
async test "ext/feishu: envelope error and union_id preference" {
  let code = error_code(() => {
    let _ = @feishu.feishu_identity(
      "{\"code\":99991663,\"msg\":\"token is invalid\"}",
    )
    ()
  })
  @debug.assert_eq(code, "provider_error")
  let id1 = @feishu.feishu_identity(
    "{\"code\":0,\"msg\":\"success\",\"data\":{\"name\":\"n\",\"open_id\":\"ou-1\",\"union_id\":\"on-1\"}}",
  )
  @debug.assert_eq(id1.uid, "on-1")
  assert_true(id1.uid_kind is @core.UidKind::Stable)
}

///|
/// §3.3 discord：`global_name` 缺失回退 `username`；头像按哈希前缀选扩展名。
async test "ext/discord: display_name fallback and avatar extension" {
  let id1 = @discord.discord_identity(
    "{\"id\":\"42\",\"username\":\"u\",\"global_name\":null,\"avatar\":\"a_b\"}",
  )
  @debug.assert_eq(id1.display_name, Some("u"))
  @debug.assert_eq(id1.avatar, Some("https://cdn.discordapp.com/avatars/42/a_b.gif"))
}

///|
/// §3.4 discord：`global_name` 缺失回退 `username`；头像按哈希前缀选扩展名。
async test "ext/discord: display_name fallback and avatar extension" {
  let id1 = @discord.discord_identity(
    "{\"id\":\"42\",\"username\":\"u\",\"global_name\":null,\"avatar\":\"a_b\"}",
  )
  @debug.assert_eq(id1.display_name, Some("u"))
  @debug.assert_eq(id1.avatar, Some("https://cdn.discordapp.com/avatars/42/a_b.gif"))
}

// ════════ §4 随机只经注入 seam（缺省临时态可确定性重放） ════════

///|
/// §4 四家统一：同一 `FixedRandomSource` 下两次 `begin_auth` 结果逐字段一致。
async test "ext/four providers: default secrets are replayable via RandomSource" {
  let mk_random : () -> &@core.RandomSource = () =>
    FixedRandomSource::{ data: Bytes::from_array([b'1', b'2']) }
  let secrets : @core.SuppliedSecrets = { state: None, code_verifier: None, nonce: None }
  let gh = @github.GitHubConfig::new("c", "https://a/cb").with_random(mk_random())
  @debug.assert_eq(
    @github.begin_auth(gh, secrets).state,
    @github.begin_auth(gh, secrets).state,
  )
  let dc = @discord.DiscordConfig::new("c", "https://a/cb").with_random(mk_random())
  @debug.assert_eq(
    @discord.begin_auth(dc, secrets).state,
    @discord.begin_auth(dc, secrets).state,
  )
  let dt = @dingtalk.DingTalkConfig::new("c", "s", "https://a/cb").with_random(mk_random())
  @debug.assert_eq(
    @dingtalk.begin_auth(dt, secrets).state,
    @dingtalk.begin_auth(dt, secrets).state,
  )
  let fs = @feishu.FeishuConfig::new("a", "s", "https://a/cb").with_random(mk_random())
  @debug.assert_eq(
    @feishu.begin_auth(fs, secrets).state,
    @feishu.begin_auth(fs, secrets).state,
  )
}
