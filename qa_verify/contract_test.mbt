//! moonauth / qa_verify —— contract 复用件健壮性（async 版）。
//!
//! `HttpClient::send` / `replay_once` 现为 async，故调用它们的用例为 `async test`。

///|
fn sample_req() -> @core.HttpRequest {
  {
    method: @core.HttpMethod::Get,
    url: "mock://qa/verify",
    headers: Map([]),
    body: None,
  }
}

///|
async test "MockHttpClient is FIFO and records every request" {
  let client = @contract.MockHttpClient::new([
    @contract.ok_response("first"),
    @contract.status_response(400, "bad"),
    @contract.status_response(500, "err"),
  ])
  @debug.assert_eq(client.send(sample_req()).body, "first")
  @debug.assert_eq(client.send(sample_req()).status, 400)
  @debug.assert_eq(client.send(sample_req()).status, 500)
  @debug.assert_eq(client.remaining(), 0)
  @debug.assert_eq(client.recorded_requests().length(), 3)
}

///|
async test "MockHttpClient raises Network when exhausted and records the attempt" {
  let client = @contract.MockHttpClient::new([])
  let code = try {
    let _ = client.send(sample_req())
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "network")
  @debug.assert_eq(client.recorded_requests().length(), 1)
}

///|
async test "MockHttpClient::new copies the source array (later mutation is isolated)" {
  let src : Array[@core.HttpResponse] = [@contract.ok_response("a")]
  let client = @contract.MockHttpClient::new(src)
  src.push(@contract.ok_response("b"))
  @debug.assert_eq(client.remaining(), 1)
  @debug.assert_eq(client.send(sample_req()).body, "a")
  @debug.assert_eq(client.remaining(), 0)
  @debug.assert_eq(src.length(), 2)
}

///|
async test "replay_once is deterministic and does not mutate the shared response array" {
  let responses = [@contract.ok_response("{\"ok\":true}")]
  let a = @contract.replay_once(sample_req(), responses, 1000L)
  let b = @contract.replay_once(sample_req(), responses, 1000L)
  @debug.assert_eq(a.0.status, b.0.status)
  @debug.assert_eq(a.0.body, b.0.body)
  @debug.assert_eq(a.1, b.1)
  @debug.assert_eq(a.0.status, 200)
  @debug.assert_eq(a.0.body, "{\"ok\":true}")
  @debug.assert_eq(a.1, 1000L)
  @debug.assert_eq(responses.length(), 1)
}

///|
async test "MockHttpClient records request headers verbatim (case-sensitive keys)" {
  let client = @contract.MockHttpClient::new([@contract.ok_response("ok")])
  let req : @core.HttpRequest = {
    method: @core.HttpMethod::Post,
    url: "mock://h",
    headers: Map([
      ("Content-Type", "application/json"),
      ("content-type", "text/plain"),
    ]),
    body: Some("{}"),
  }
  let _ = client.send(req)
  let recorded = client.recorded_requests()
  @debug.assert_eq(recorded.length(), 1)
  @debug.assert_eq(recorded[0].headers.length(), 2)
  @debug.assert_eq(recorded[0].headers.get("Content-Type"), Some("application/json"))
  @debug.assert_eq(recorded[0].headers.get("content-type"), Some("text/plain"))
  @debug.assert_eq(recorded[0].body, Some("{}"))
}

///|
test "FixedClock advance/set is reflected by now_unix" {
  let clock = @contract.FixedClock::new(100L)
  @debug.assert_eq(@core.Clock::now_unix(clock), 100L)
  @debug.assert_eq(clock.peek(), 100L)
  clock.advance(5L)
  @debug.assert_eq(@core.Clock::now_unix(clock), 105L)
  clock.set(7L)
  @debug.assert_eq(@core.Clock::now_unix(clock), 7L)
}

///|
test "all_pass is true only when every case passes (including empty)" {
  assert_true(@contract.all_pass([]))
  assert_true(@contract.all_pass([@contract.CaseResult::pass("a")]))
  assert_false(
    @contract.all_pass([
      @contract.CaseResult::pass("a"),
      @contract.CaseResult::fail("b", "expected 200 got 500"),
    ]),
  )
  assert_false(@contract.all_pass([@contract.CaseResult::fail("b", "x")]))
}

///|
test "assert_all_pass completes normally on an all-passing set" {
  @contract.assert_all_pass([
    @contract.CaseResult::pass("only"),
    @contract.CaseResult::pass("two"),
  ])
  assert_true(true)
}
