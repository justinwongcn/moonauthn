//! moonauth / contract —— 参数化契约测试的**框架部分**（SDK-04 / LIB-17 的地基）。
//!
//! 本包提供 T02~T04 的契约函数复用的公共构件：
//! - `CaseResult` / `all_pass` / `assert_all_pass`：统一的用例结果与汇总；
//! - `MockHttpClient`：预置响应队列的 `HttpClient` 实现（零真实网络）；
//! - `FixedClock`：返回固定时间戳的 `Clock` 实现（确定性重放）。
//!
//! 设计目标：同一断言集可对「库自实现」与「官方 SDK 适配层」两套实现各跑一次
//! （一个 `run(make : () -> &Trait)` 形状的契约函数），从而证明行为一致（SDK-04）。

// ════════ 用例结果 ════════

///|
/// 单条契约用例的结果。
pub(all) struct CaseResult {
  name : String
  passed : Bool
  detail : String
}

///|
/// 构造一条「通过」用例。
pub fn CaseResult::pass(name : String) -> CaseResult {
  { name: name, passed: true, detail: "" }
}

///|
/// 构造一条「失败」用例，`detail` 说明失败原因。
pub fn CaseResult::fail(name : String, detail : String) -> CaseResult {
  { name: name, passed: false, detail: detail }
}

///|
/// 判断一组用例是否全部通过。
pub fn all_pass(cases : Array[CaseResult]) -> Bool {
  let mut ok = true
  for c in cases {
    if !c.passed {
      ok = false
    }
  }
  ok
}

///|
/// 打印每个用例的结果；若有失败则 `raise AuthError`。
///
/// 🔴 失败路径**可被调用方 `catch`**（与 HANDOVER §12.3「所有失败路径都可捕获」的
/// 记账一致）——在 `async test` 里直接调用即可，错误向上传播使该测试失败（CI 非零
/// 退出）；在长驻服务里误用时也不会不可捕获地崩掉进程。
pub fn assert_all_pass(cases : Array[CaseResult]) -> Unit raise @core.AuthError {
  let mut failures = 0
  for c in cases {
    if c.passed {
      println("[PASS] " + c.name)
    } else {
      failures = failures + 1
      println("[FAIL] " + c.name + " : " + c.detail)
    }
  }
  if failures > 0 {
    raise @core.Unsupported("\{failures} contract case(s) failed")
  }
}

// ════════ MockHttpClient ════════

///|
/// 预置响应队列的 `HttpClient` 实现：每次 `send` 从队首取出一条响应，并记录请求。
/// 队列为空时 `send` 抛 `Network`，以免误用真实网络。
pub struct MockHttpClient {
  queue : Array[@core.HttpResponse]
  log : Array[@core.HttpRequest]
}

///|
/// 以预置响应队列构造。**会复制**传入数组，避免多次构造共享同一队列。
pub fn MockHttpClient::new(responses : Array[@core.HttpResponse]) -> MockHttpClient {
  { queue: responses.copy(), log: [] }
}

///|
/// 追加一条预置响应到队尾。
pub fn MockHttpClient::push_response(
  self : MockHttpClient,
  resp : @core.HttpResponse,
) -> Unit {
  self.queue.push(resp)
}

///|
/// 队列中剩余的预置响应条数。
pub fn MockHttpClient::remaining(self : MockHttpClient) -> Int {
  self.queue.length()
}

///|
/// 已记录的请求（按调用顺序）。返回内部数组的引用（只读语义由调用方维护）。
pub fn MockHttpClient::recorded_requests(
  self : MockHttpClient,
) -> Array[@core.HttpRequest] {
  self.log
}

///|
/// 实现 seam（async）：从队首（FIFO）取响应并记录请求。
/// 内存队列无真正异步操作，但签名须与 async 的 `HttpClient::send` 对齐。
pub impl @core.HttpClient for MockHttpClient with fn send(self, req) {
  self.log.push(req)
  if self.queue.is_empty() {
    raise @core.Network("moonauth: MockHttpClient has no queued response")
  }
  self.queue.remove(0)
}

///|
/// 显式提升 seam 方法，避免隐式提升的弃用告警。
pub extend MockHttpClient with @core.HttpClient::{send}

// ════════ FixedClock ════════

///|
/// 返回固定时间戳的 `Clock` 实现，支持手动推进 / 设置，用于确定性重放。
pub struct FixedClock {
  mut current : Int64
}

///|
/// 以固定 Unix 秒构造。
pub fn FixedClock::new(now_unix : Int64) -> FixedClock {
  { current: now_unix }
}

///|
/// 前进 `seconds` 秒。
pub fn FixedClock::advance(self : FixedClock, seconds : Int64) -> Unit {
  self.current = self.current + seconds
}

///|
/// 设置为指定 Unix 秒。
pub fn FixedClock::set(self : FixedClock, now_unix : Int64) -> Unit {
  self.current = now_unix
}

///|
/// 只读当前时间戳。
pub fn FixedClock::peek(self : FixedClock) -> Int64 {
  self.current
}

///|
/// 实现 seam。
pub impl @core.Clock for FixedClock with fn now_unix(self) {
  self.current
}

///|
/// 显式提升 seam 方法，避免隐式提升的弃用告警。
pub extend FixedClock with @core.Clock::{now_unix}

// ════════ 便捷构件 ════════

///|
/// 构造一个 200 响应。
pub fn ok_response(body : String) -> @core.HttpResponse {
  { status: 200, headers: Map([]), body: body }
}

///|
/// 构造一个指定状态的响应。
pub fn status_response(status : Int, body : String) -> @core.HttpResponse {
  { status: status, headers: Map([]), body: body }
}

///|
/// 用固定 `MockHttpClient` + `FixedClock` 跑一次「同一输入」的确定性往返。
///
/// 相同入参两次调用应产生等价结果（LIB-19 ②：确定性重放）。
/// 为 `async`：`HttpClient::send` 现为 async，须在其 async 上下文内调用。
pub async fn replay_once(
  req : @core.HttpRequest,
  responses : Array[@core.HttpResponse],
  at_unix : Int64,
) -> (@core.HttpResponse, Int64) raise @core.AuthError {
  let client = MockHttpClient::new(responses)
  let clock = FixedClock::new(at_unix)
  let resp = client.send(req)
  (resp, clock.now_unix())
}
