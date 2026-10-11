//! moonauth / core —— `AsyncHttpClient` 的 async 验收测试。
//!
//! 核心验收项（T01 修订）：**在既有 async 上下文内调用 `AsyncHttpClient::send`**
//! 必须抛出**可捕获的** `AuthError`，而不是杀进程（旧实现因在 `send` 内部桥接
//! `@async.run_async_main`，在既有 async 上下文中会触发
//! `with_event_loop` 的 `guard!` → SIGABRT，且无法被 `catch` 捕获）。
//!
//! 这里使用 `async test`：工具链会自动生成本测试的 async 上下文
//! （等价于在 `@async.run_async_main` 内运行），因此正是「事件循环已存在时再调用 `send`」
//! 的场景。请求指向 `127.0.0.1:1`（无监听者，连接必然失败，无需外网）。

///|
/// 指向必然连接失败的本地地址的请求。
fn unreachable_request() -> @core.HttpRequest {
  {
    method: @core.HttpMethod::Get,
    url: "http://127.0.0.1:1/",
    headers: Map([]),
    body: None,
  }
}

///|
/// 核心验收：在 async 上下文内调用 `send`，必须得到**可捕获的** `AuthError(Network)`。
async test "async send inside an existing async context raises a catchable Network error" {
  let client = @core.AsyncHttpClient::new()
  let code = try {
    let resp = client.send(unreachable_request())
    // 到达这里说明既没抛错也没 abort —— 不是我们期望的路径
    "no-error:" + resp.status.to_string()
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "network")
}

///|
/// 连续多次调用（同一 async 上下文内）不应出现「事件循环嵌套」类问题：
/// 每次调用都必须独立地给出可捕获结果，进程存活。
async test "async send is repeatable within one async context (no abort)" {
  let client = @core.AsyncHttpClient::new()
  let mut network_count = 0
  for i = 0; i < 3; i = i + 1 {
    let code = try {
      let _ = client.send(unreachable_request())
      "no-error"
    } catch {
      e => @core.auth_error_code(e)
    }
    if code == "network" {
      network_count = network_count + 1
    }
  }
  // 三次都应得到可捕获的 Network（而非中途 abort 掉整个测试进程）
  @debug.assert_eq(network_count, 3)
}

///|
/// 非 2xx 归一：连接成功但状态码非 2xx 时应抛 `HttpStatus`。
/// 这里不引入真实服务器，仅验证 `auth_error_code` 对 `HttpStatus` 的稳定归类，
/// 作为 `send` 状态分支的补充锁定。
test "http status errors classify as http_status" {
  @debug.assert_eq(
    @core.auth_error_code(@core.HttpStatus(503, "down")),
    "http_status",
  )
}
