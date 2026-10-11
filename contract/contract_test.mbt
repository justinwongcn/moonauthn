//! moonauth / contract —— 黑盒测试，验证契约框架构件本身可用。
//!
//! 由于 seam `HttpClient` 为 async，凡调用 `send` / `replay_once` 的用例一律写成
//! `async test`。

///|
fn get_req() -> @core.HttpRequest {
  {
    method: @core.HttpMethod::Get,
    url: "mock://example/token",
    headers: Map([]),
    body: None,
  }
}

///|
async test "deterministic replay: same input twice yields equivalent results" {
  let responses = [@contract.ok_response("{\"ok\":true}")]
  let a = @contract.replay_once(get_req(), responses, 1000L)
  let b = @contract.replay_once(get_req(), responses, 1000L)
  @debug.assert_eq(a.0.status, b.0.status)
  @debug.assert_eq(a.0.body, b.0.body)
  @debug.assert_eq(a.1, b.1)
  @debug.assert_eq(a.0.status, 200)
  @debug.assert_eq(a.1, 1000L)
}

///|
async test "mock http consumes the queue and records requests" {
  let client = @contract.MockHttpClient::new([
    @contract.ok_response("first"),
    @contract.status_response(400, "bad"),
  ])
  let req : @core.HttpRequest = {
    method: @core.HttpMethod::Post,
    url: "mock://x",
    headers: Map([]),
    body: Some("a=1"),
  }
  let r1 = client.send(req)
  @debug.assert_eq(r1.status, 200)
  @debug.assert_eq(r1.body, "first")
  let r2 = client.send(req)
  @debug.assert_eq(r2.status, 400)
  @debug.assert_eq(client.remaining(), 0)
  @debug.assert_eq(client.recorded_requests().length(), 2)
}

///|
async test "mock http raises Network when the queue is empty" {
  let client = @contract.MockHttpClient::new([])
  let err = try {
    let _ = client.send(get_req())
    "no error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(err, "network")
}

///|
/// 锁定响应头透传逻辑可用（`MockHttpClient` 原样返回预置响应，含自定义头）。
async test "mock http returns configured response headers verbatim" {
  let with_headers : @core.HttpResponse = {
    status: 200,
    headers: Map([
      ("Content-Type", "application/x-www-form-urlencoded"),
      ("X-Custom-Header", "abc"),
    ]),
    body: "access_token=t&expires_in=1",
  }
  let client = @contract.MockHttpClient::new([with_headers])
  let resp = client.send(get_req())
  @debug.assert_eq(
    resp.headers.get("Content-Type"),
    Some("application/x-www-form-urlencoded"),
  )
  @debug.assert_eq(resp.headers.get("X-Custom-Header"), Some("abc"))
}

///|
test "fixed clock advances deterministically" {
  let clock = @contract.FixedClock::new(100L)
  @debug.assert_eq(clock.peek(), 100L)
  clock.advance(5L)
  @debug.assert_eq(clock.peek(), 105L)
  clock.set(7L)
  @debug.assert_eq(clock.peek(), 7L)
}

///|
test "case result aggregation" {
  let cases = [
    @contract.CaseResult::pass("a"),
    @contract.CaseResult::pass("b"),
  ]
  assert_true(@contract.all_pass(cases))
  let bad = [@contract.CaseResult::fail("c", "expected 200 got 500")]
  assert_false(@contract.all_pass(bad))
}
