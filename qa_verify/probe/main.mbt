//! moonauth / qa_verify/probe —— 需要在**独立进程**中观察「进程级副作用」的探针。
//!
//! 用法：`moon run qa_verify/probe --target native -- <mode>`
//!   mode = nested_send | contract_fail
//!
//! - `nested_send`：**T01 修订的核心回归**。旧实现（`send` 内部桥接 `@async.run_async_main`）
//!   在既有 async 上下文内调用会 `with_event_loop` guard 失败 → 进程 SIGABRT（exit 134）。
//!   修订后 `send` 直接是 async，此场景应返回可捕获的 `AuthError(Network)`，进程正常退出。
//! - `contract_fail`：验证 `assert_all_pass` 对失败用例确实 abort（非空断言）。

///|
fn unreachable_request() -> @core.HttpRequest {
  {
    method: @core.HttpMethod::Get,
    // 端口 1 无监听者：连接应被立即拒绝（无需外网）
    url: "http://127.0.0.1:1/",
    headers: Map([]),
    body: None,
  }
}

///|
/// 场景 A（核心回归）：在**已有 async 上下文内**调用 `send`。
/// 旧实现 → SIGABRT；修订后 → 可捕获的 Network，进程存活、exit 0。
fn probe_nested_send() -> Unit {
  println("NESTED_START")
  let client = @core.AsyncHttpClient::new()
  @async.run_async_main(() => {
    println("NESTED_INSIDE_BEFORE")
    let outcome = try {
      let resp = client.send(unreachable_request())
      "no-error:" + resp.status.to_string()
    } catch {
      e => "caught:" + @core.auth_error_code(e)
    }
    println("NESTED_INSIDE_AFTER=" + outcome)
  })
  println("NESTED_END")
}

///|
/// 场景 B：`assert_all_pass` 收到失败用例时是否真的终止（非零退出）。
fn probe_contract_fail() -> Unit {
  println("CONTRACT_FAIL_START")
  let cases = [
    @contract.CaseResult::pass("a"),
    @contract.CaseResult::fail("b", "expected 200 got 500"),
  ]
  println("CONTRACT_FAIL_ALL_PASS=" + @contract.all_pass(cases).to_string())
  @contract.assert_all_pass(cases)
  println("CONTRACT_FAIL_REACHED_END")
}

///|
fn main {
  let args = @env.args()
  let mode = if args.length() > 1 {
    args[1]
  } else {
    "help"
  }
  match mode {
    "nested_send" => probe_nested_send()
    "contract_fail" => probe_contract_fail()
    _ => println("usage: probe <nested_send|contract_fail>")
  }
}
