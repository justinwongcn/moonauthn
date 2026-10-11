//! moonauth / oidc —— `JwksIdTokenVerifier` 的**实例内 JWKS 缓存**。
//!
//! 设计要点（ARCH §2.2 / T02.4）：
//! - **实例内**：缓存随 `JwksIdTokenVerifier` 实例存续，无跨调用全局可变状态
//!   （库的「零状态」约束针对*临时态*；JWKS 是**公开可缓存数据**，缓存于实例内合法）；
//! - **按 `kid` 轮转**：缓存里找不到 token 声明的 `kid` 时，强制重取一次 JWKS 再选——
//!   provider 轮换签名密钥后无需重启即可继续验签；
//! - **TTL**：由注入的 `Clock` 判定（`now - fetched_at < ttl_seconds`），
//!   使「过期重取」在测试里可用 `FixedClock` 确定性重放。
//!
//! 🔴 缓存只存**标准类型**（原始 JWKS 文本 + 抓取时刻）：既不把 `@jwk.Set` 这样的
//! 第三方类型放进结构体（即便字段私有也不），也让 `.mbti` 完全干净。

///|
/// 默认 `IdTokenVerifier` 实现（JWKS 缓存 + 轮转）。
///
/// 字段说明：
/// - `http` / `clock` 为注入 seam；
/// - `ttl_seconds` 为缓存有效期（默认 1 小时）；
/// - `forced_refetch_min_seconds` 为「kid 未命中强制重取」的最小间隔（默认 60 秒，
///   防未认证路径以伪造 `kid` 放大出站请求，见 `verify_token`）；
/// - `cached_body` / `cached_at` / `last_forced_refetch` 为实例内可变状态，**私有**，
///   不出现在 `.mbti`。
pub struct JwksIdTokenVerifier {
  http : &@core.HttpClient
  clock : &@core.Clock
  ttl_seconds : Int64
  forced_refetch_min_seconds : Int64
  priv mut cached_body : String?
  priv mut cached_at : Int64
  priv mut last_forced_refetch : Int64
}

///|
/// 默认 TTL：1 小时。JWKS 轮换远慢于此，取 1 小时足够新鲜又避免频繁拉取。
let default_jwks_ttl : Int64 = 3600L

///|
/// 默认「kid 未命中强制重取」最小间隔：60 秒。轮换场景下一次重取即命中；
/// 攻击者伪造随机 `kid` 时最多每分钟放大一次出站请求。
let default_forced_refetch_min : Int64 = 60L

///|
/// 构造默认验签器：`AsyncHttpClient` + `SystemClock`，默认 TTL，无缓存。
pub fn JwksIdTokenVerifier::new() -> JwksIdTokenVerifier {
  let http : &@core.HttpClient = @core.AsyncHttpClient::new()
  let clock : &@core.Clock = @core.SystemClock::new()
  {
    http,
    clock,
    ttl_seconds: default_jwks_ttl,
    forced_refetch_min_seconds: default_forced_refetch_min,
    cached_body: None,
    cached_at: 0L,
    last_forced_refetch: 0L,
  }
}

///|
/// 以指定 `HttpClient` 构造（时钟取 `SystemClock`）。
pub fn JwksIdTokenVerifier::new_with_http(
  http : &@core.HttpClient,
) -> JwksIdTokenVerifier {
  let clock : &@core.Clock = @core.SystemClock::new()
  {
    http,
    clock,
    ttl_seconds: default_jwks_ttl,
    forced_refetch_min_seconds: default_forced_refetch_min,
    cached_body: None,
    cached_at: 0L,
    last_forced_refetch: 0L,
  }
}

///|
/// 覆盖出站 HTTP（返回新实例）。
pub fn JwksIdTokenVerifier::with_http(
  self : JwksIdTokenVerifier,
  http : &@core.HttpClient,
) -> JwksIdTokenVerifier {
  { ..self, http }
}

///|
/// 覆盖时钟（返回新实例）——测试用 `FixedClock` 注入以确定性重放 TTL。
pub fn JwksIdTokenVerifier::with_clock(
  self : JwksIdTokenVerifier,
  clock : &@core.Clock,
) -> JwksIdTokenVerifier {
  { ..self, clock }
}

///|
/// 覆盖「kid 未命中强制重取」最小间隔（秒，返回新实例）。
pub fn JwksIdTokenVerifier::with_forced_refetch_min_seconds(
  self : JwksIdTokenVerifier,
  seconds : Int64,
) -> JwksIdTokenVerifier {
  { ..self, forced_refetch_min_seconds: seconds }
}

///|
/// 覆盖缓存 TTL（秒，返回新实例）。
pub fn JwksIdTokenVerifier::with_ttl(
  self : JwksIdTokenVerifier,
  ttl_seconds : Int64,
) -> JwksIdTokenVerifier {
  { ..self, ttl_seconds }
}

///|
/// 缓存是否仍在有效期内。
fn JwksIdTokenVerifier::cache_valid(self : JwksIdTokenVerifier, now : Int64) -> Bool {
  match self.cached_body {
    None => false
    Some(_) => now - self.cached_at < self.ttl_seconds
  }
}

///|
/// 抓取 JWKS（经注入的 `HttpClient`），成功则写入缓存。
///
/// 非 2xx 视为 `KeyError`（密钥 / JWKS 加载失败，ARCH §4.3）。
async fn JwksIdTokenVerifier::fetch_jwks(
  self : JwksIdTokenVerifier,
  jwks_uri : String,
) -> String raise @core.AuthError {
  let resp = self.http.send({
    method: @core.HttpMethod::Get,
    url: jwks_uri,
    headers: Map([("Accept", "application/json")]),
    body: None,
  })
  if resp.status < 200 || resp.status >= 300 {
    raise @core.KeyError(
      "moonauth: JWKS fetch failed with status " + resp.status.to_string(),
    )
  }
  // 🔴 先验证响应体确为可解析的 JWKS，**再**写缓存——否则网关返回 200 + HTML
  // （captive portal / 反向代理故障）会把坏体缓存整整一个 TTL，且后续每个 token
  // 都报误导性的「no JWKS key matches」。
  try {
    let _ = @jwk.Set::parse(resp.body[:])
  } catch {
    _ =>
      raise @core.KeyError(
        "moonauth: JWKS response is not parseable (status \{resp.status})",
      )
  }
  self.cached_body = Some(resp.body)
  self.cached_at = self.clock.now_unix()
  resp.body
}

///|
/// 取当前 JWKS 文本：命中有效缓存直接返回，否则抓取。
async fn JwksIdTokenVerifier::current_jwks(
  self : JwksIdTokenVerifier,
  jwks_uri : String,
) -> String raise @core.AuthError {
  let now = self.clock.now_unix()
  if self.cache_valid(now) {
    match self.cached_body {
      Some(body) => body
      None => self.fetch_jwks(jwks_uri)
    }
  } else {
    self.fetch_jwks(jwks_uri)
  }
}
