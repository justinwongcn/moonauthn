//! moonauth / core —— 默认 `HttpClient` 实现：`AsyncHttpClient`。
//!
//! 基于 `moonbitlang/async/http`。🔴 **只用 `async/http`，禁用 `async/socket`**
//! （`async/socket` 的 `Addr` 是 native 专有类型，引用它会破坏 js target）。
//!
//! seam `HttpClient::send` 现已声明为 `async fn`，因此本实现**直接**在调用方的 async
//! 上下文内执行真实请求——**不再桥接 `@async.run_async_main`**。这从根上消除了
//! 「在既有 async 上下文内嵌套 `run_async_main` → 进程 SIGABRT」的致命缺陷。
//!
//! 所有第三方（`@http` / `@io`）异常在边界处立即 `catch` 并转换为 `AuthError`。

///|
/// 默认 `HttpClient` 实现。
///
/// 目前仅保留一个可选的超时字段（留作后续扩展）；它的存在不改变 seam 契约。
pub(all) struct AsyncHttpClient {
  timeout_ms : Int?
}

///|
/// 构造 `AsyncHttpClient`。
pub fn AsyncHttpClient::new(timeout_ms? : Int) -> AsyncHttpClient {
  { timeout_ms: timeout_ms }
}

///|
/// 把 `@http` 的响应头（大小写不敏感键）映射为库自有的 `Map[String, String]`。
///
/// 🔴 键**保持服务器返回的原样**（不做大小写归一），与 `MockHttpClient` 的行为一致。
/// 保留原样是为了让下游能按 `content-type` 等做形态判断：
/// - QQ token 端点默认返回 `application/x-www-form-urlencoded`（可 `fmt=json` 绕开）；
/// - QQ `/oauth2.0/me` 默认返回 JSONP `callback( {...} );`，需按内容形态决定是否剥壳。
///
/// 该函数是**私有**的（非 `pub`），因此 `@http` / `@io` 类型不会出现在任何公开签名上。
///
/// 🔴 **已知限制（不在 T01 尝试修复）**：上游 `@http` 用
/// `Map[@http.CaseInsensitiveString, String]` 承载响应头，**同名多值头会被上游合并**
/// （后覆盖前）。因此 `Set-Cookie` 这类允许多值的头在本函数中将**静默丢失前序取值**，
/// 本函数无从挽救——它拿到的已是合并后的单值映射。
/// 修复需改上游数据结构（携带多值头的能力）或替换 HTTP 栈，超出 T01 范围；
/// 已作为已知限制记录，交由架构归档（ARCH 已知限制）。
fn map_response_headers(
  headers : Map[@http.CaseInsensitiveString, String],
) -> Map[String, String] {
  let out : Map[String, String] = Map([])
  for k, v in headers {
    out[k.0] = v
  }
  out
}

///|
/// 把库自有的 `HttpRequest` 映射为 `@http` 的一次真实请求，并归一为库自有的 `HttpResponse`。
///
/// 该函数是 `async` 的，由 `send`（同为 async）在其 async 上下文内直接调用；
/// 它**不是** `pub`，因此 `@http` / `@io` 类型不会出现在任何公开签名上。
async fn perform_http_request(req : HttpRequest) -> HttpResponse raise AuthError {
  let http_method = match req.method {
    Get => @http.RequestMethod::Get
    Post => @http.RequestMethod::Post
  }
  let headers : Map[@http.CaseInsensitiveString, String] = Map([])
  for k, v in req.headers {
    headers[@http.CaseInsensitiveString(k)] = v
  }
  let body = match req.body {
    Some(b) => b
    None => ""
  }
  let (resp, data) = @http.request(req.url, http_method, headers, body) catch {
    err => raise Network("moonauth: HTTP request failed: \{err}")
  }
  let text = data.text() catch {
    _ => raise ParseError("moonauth: failed to decode HTTP response body as text")
  }
  if resp.code < 200 || resp.code >= 300 {
    raise HttpStatus(resp.code, text)
  }
  { status: resp.code, headers: map_response_headers(resp.headers), body: text }
}

///|
/// 实现 seam：异步 `send`。**在调用方提供的 async 上下文内直接执行**，不启动新的事件循环，
/// 因此可安全地嵌套于任意既有 async 上下文中（native / js 均可）。
pub impl HttpClient for AsyncHttpClient with fn send(self, req) {
  let _ = self
  perform_http_request(req)
}

///|
/// 显式把 seam 方法提升为 `AsyncHttpClient` 的常规方法，避免隐式提升的弃用告警。
pub extend AsyncHttpClient with HttpClient::{send}
