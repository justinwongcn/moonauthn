//! moonauth / http_e2e —— 起真实本地 HTTP 服务器，验证自定义响应头端到端透传。

///|
/// 在 `127.0.0.1` 的随机端口上启动一个本地 HTTP 服务器：对任何请求返回一个
/// 带自定义响应头（`Content-Type` / `X-Custom-Header` / `X-Trace-Id`）与一段
/// form-encoded 形态 body 的 200 响应。返回监听端口。
async fn start_header_server(group : @async.TaskGroup[Unit]) -> Int {
  let server = @http.Server(@socket.Addr::parse("127.0.0.1:0"))
  group.add_defer(() => server.close())
  group.spawn_bg(no_wait=true) <| () => {
    server.run_forever() <| ((_request, _body, conn) => {
      conn
      ..send_response(200, "OK", extra_headers={
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Custom-Header": "abc",
        "X-Trace-Id": "0123",
      })
      .write("access_token=t&expires_in=1")
    })
  }
  server.addr.port()
}

///|
async test "custom response headers pass through AsyncHttpClient end to end" {
  @async.with_task_group() <| group => {
    let port = start_header_server(group)
    let client = @core.AsyncHttpClient::new()
    let req : @core.HttpRequest = {
      method: @core.HttpMethod::Get,
      url: "http://127.0.0.1:\{port}/",
      headers: Map([]),
      body: None,
    }
    let resp = client.send(req)
    @debug.assert_eq(resp.status, 200)
    @debug.assert_eq(resp.body, "access_token=t&expires_in=1")
    // 自定义头逐一透传（键保持服务器返回的原样大小写）
    @debug.assert_eq(
      resp.headers.get("Content-Type"),
      Some("application/x-www-form-urlencoded"),
    )
    @debug.assert_eq(resp.headers.get("X-Custom-Header"), Some("abc"))
    @debug.assert_eq(resp.headers.get("X-Trace-Id"), Some("0123"))
  }
}

///|
/// 🔴 seam 契约锁定：**非 2xx 不在传输层抛错**——`send` 原样返回 404 响应，
/// 状态码归一是调用方的责任（见 `core/seams_io.mbt`）。
async test "non-2xx responses are returned as-is, not raised" {
  @async.with_task_group() <| group => {
    let server = @http.Server(@socket.Addr::parse("127.0.0.1:0"))
    group.add_defer(() => server.close())
    group.spawn_bg(no_wait=true) <| () => {
      server.run_forever() <| ((_request, _body, conn) => {
        conn
        ..send_response(404, "Not Found", extra_headers={
          "Content-Type": "application/json",
        })
        .write("{\"error\":\"not_found\"}")
      })
    }
    let port = server.addr.port()
    let client = @core.AsyncHttpClient::new()
    let req : @core.HttpRequest = {
      method: @core.HttpMethod::Get,
      url: "http://127.0.0.1:\{port}/missing",
      headers: Map([]),
      body: None,
    }
    let resp = client.send(req)
    @debug.assert_eq(resp.status, 404)
    @debug.assert_eq(resp.body, "{\"error\":\"not_found\"}")
  }
}
