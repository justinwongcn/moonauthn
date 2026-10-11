//! 外部包实现 core 的全部 seam —— 验证 SDK-01 可替换性（跨包实现）
//!
//! core 的 I/O seam（`HttpClient` / `ChallengeStore`）与能力 seam（`IdTokenVerifier`）
//! 现为 async：实现侧写 `with fn`（**不是** `with async fn`），调用侧在 async 上下文内直接调用。
//! `Clock` 保持同步。

///| 自定义 HttpClient（async）
pub(all) struct MyHttp {}

///|
pub fn MyHttp::new() -> MyHttp { MyHttp::{} }

///|
pub impl @core.HttpClient for MyHttp with fn send(self, req) {
  let _ = self
  let _ = req
  { status: 200, headers: {}, body: "{\"ok\":true}" }
}

///|
pub extend MyHttp with @core.HttpClient::{send}

///| 自定义 Clock（固定时钟，保持同步）
pub(all) struct MyClock {}

///|
pub fn MyClock::new() -> MyClock { MyClock::{} }

///|
pub impl @core.Clock for MyClock with fn now_unix(self) {
  let _ = self
  1700000000L
}

///|
pub extend MyClock with @core.Clock::{now_unix}

///| 自定义 ChallengeStore（async）
pub(all) struct MyStore {
  mut v : String?
}

///|
pub fn MyStore::new() -> MyStore { { v: None } }

///|
pub impl @core.ChallengeStore for MyStore with fn put(self, key, value, ttl_seconds) {
  let _ = key
  let _ = ttl_seconds
  self.v = Some(value)
}

///|
pub impl @core.ChallengeStore for MyStore with fn take(self, key) {
  let _ = key
  let out = self.v
  self.v = None
  out
}

///|
pub impl @core.ChallengeStore for MyStore with fn peek(self, key) {
  let _ = key
  self.v
}

///|
pub extend MyStore with @core.ChallengeStore::{peek, put, take}

///| 故障 ChallengeStore（模拟 Redis 连接失败）：`take` / `peek` 抛 `Network`。
/// 用于验证 `ChallengeStore` 的 `raise AuthError` 契约——存储故障必须能与
/// 「值不存在（`None`）」区分开，而 `None` 只表达后者。
pub(all) struct MyFailingStore {}

///|
pub fn MyFailingStore::new() -> MyFailingStore { MyFailingStore::{} }

///|
pub impl @core.ChallengeStore for MyFailingStore with fn put(
  self,
  key,
  value,
  ttl_seconds,
) {
  let _ = self
  let _ = key
  let _ = value
  let _ = ttl_seconds
}

///|
pub impl @core.ChallengeStore for MyFailingStore with fn take(self, key) {
  let _ = self
  let _ = key
  raise @core.Network("moonauth: challenge store connection failed")
}

///|
pub impl @core.ChallengeStore for MyFailingStore with fn peek(self, key) {
  let _ = self
  let _ = key
  raise @core.Network("moonauth: challenge store connection failed")
}

///|
pub extend MyFailingStore with @core.ChallengeStore::{peek, put, take}

///| 泛型驱动：调用方把 `ChallengeStore` 的**存储故障**作为 `AuthError` 捕获，
/// 与「值不存在」（`None` → `"absent"`）区分开。证明 `raise AuthError` 契约可用。
pub async fn[S : @core.ChallengeStore] take_code(s : S, key : String) -> String {
  try {
    match @core.ChallengeStore::take(s, key) {
      Some(_) => "present"
      None => "absent"
    }
  } catch {
    e => @core.auth_error_code(e)
  }
}

///| 自定义 IdTokenVerifier（能力 seam —— 模拟「官方 JWT SDK 适配层」，async）
pub(all) struct MyVerifier {}

///|
pub fn MyVerifier::new() -> MyVerifier { MyVerifier::{} }

///|
pub impl @core.IdTokenVerifier for MyVerifier with fn verify(self, token, expect) {
  let _ = self
  let _ = token
  let _ = expect
  {
    subject: "official-sub",
    issuer: "https://issuer",
    audience: ["aud"],
    expires_at: 0L,
    issued_at: 0L,
    nonce: None,
    email: None,
    email_verified: None,
    raw: {},
  }
}

///|
pub extend MyVerifier with @core.IdTokenVerifier::{verify}

///| 泛型驱动：证明「换实现不改调用方代码」。
///
/// `H` / `V` 约束为 async seam 的实现，故本函数为 `async fn`；函数体内直接调用
/// `@core.HttpClient::send` / `@core.IdTokenVerifier::verify`，无需显式 `await`。
pub async fn[H : @core.HttpClient, C : @core.Clock, V : @core.IdTokenVerifier] drive(
  h : H,
  c : C,
  v : V,
) -> String raise @core.AuthError {
  let stamp = @core.Clock::now_unix(c)
  let claims = @core.IdTokenVerifier::verify(v, "tok", {
    issuers: [],
    audiences: [],
    nonce: None,
    jwks_uri: None,
    leeway_seconds: None,
    algorithms: [],
  })
  let resp = @core.HttpClient::send(h, {
    method: @core.HttpMethod::Get,
    url: "https://example.com",
    headers: {},
    body: None,
  })
  claims.subject + resp.body + stamp.to_string()
}
