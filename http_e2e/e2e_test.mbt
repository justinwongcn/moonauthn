//! moonauth / http_e2e —— **端到端测试（JEV 标准，2026-11-19）**。
//!
//! JEV 判定的本轮标准（e2e_standard_out.json）：补 S1（google complete_auth 全链路
//! 0.961）/ S2（400 错误归一端到端 0.809）/ S3（POST 体完整性 0.942）；断言深度
//! **both**（传输层专项 + 全链路专项分开）；服务器 **shared per scenario class**
//! （同一场景类共享服务器，token→JWKS 请求序列）。S4（microsoft 租户派生 0.496）/
//! S5（429 透传 0.378）/ S6（JWKS 轮转 0.549）判边界，本轮不补。
//!
//! 与 MockHttpClient 的分工：协议逻辑已被 mock 覆盖；本文件只补**真实 I/O 边界**——
//! 真实 TCP 连接、HTTP 分帧、POST 体传输、请求序列（token→JWKS）。全部走 127.0.0.1
//! 回环随机端口，零外部网络，确定性可重放。
//!
//! 🔴 三个首轮踩坑（已修）：① token 端点响应必须是**完整 token JSON**——
//! `@contract.fixed_token_ok` 只是其中的 id_token 值，裸 JWT 会被 form 回退解析成
//! 「missing access_token」；② 验签时钟必须注入 **FixedClock**——fixed 向量的
//! exp 是 2023-11，真实系统时钟下必然 TokenExpired；③ MoonBit 字面量里 JSON 引号
//! 是**单反斜杠**转义（`\"`）——写成 `\\\"` 会在运行时产出带可见反斜杠的非法 JSON。

///|
/// OAuth 场景服务器（S1/S2 按 token 状态码区分场景类）：按 path 路由——
/// `POST /token` → `token_status` + `token_body`（读掉请求体后响应）；
/// `GET /jwks` → 200 + `jwks_body`。返回监听端口。
async fn start_oauth_server(
  group : @async.TaskGroup[Unit],
  token_status : Int,
  token_body : String,
  jwks_body : String,
) -> Int {
  let server = @http.Server(@socket.Addr::parse("127.0.0.1:0"))
  group.add_defer(() => server.close())
  group.spawn_bg(no_wait=true) <| () => {
    server.run_forever() <| ((req, body, conn) => {
      if req.path == "/token" {
        let _ = body.read_all()
        conn
        ..send_response(token_status, "OK", extra_headers={
          "Content-Type": "application/json",
        })
        .write(token_body)
      } else if req.path == "/jwks" {
        conn
        ..send_response(200, "OK", extra_headers={
          "Content-Type": "application/json",
        })
        .write(jwks_body)
      } else {
        conn
        ..send_response(404, "Not Found")
        .write("{}")
      }
    })
  }
  server.addr.port()
}

///|
/// 回显服务器（S3 传输层专项）：把 POST 请求体**原样**写回响应体——POST 体
/// 完整性断言用。
async fn start_echo_server(group : @async.TaskGroup[Unit]) -> Int {
  let server = @http.Server(@socket.Addr::parse("127.0.0.1:0"))
  group.add_defer(() => server.close())
  group.spawn_bg(no_wait=true) <| () => {
    server.run_forever() <| ((_req, body, conn) => {
      let data = body.read_all()
      let text = data.text() catch {
        _ => ""
      }
      conn
      ..send_response(200, "OK", extra_headers={
        "Content-Type": "application/x-www-form-urlencoded",
      })
      .write(text)
    })
  }
  server.addr.port()
}

///|
/// E2E-S1（JEV 0.961，全链路深度）：google `complete_auth` **全链路**——真实 TCP
/// 连接上完成 POST form 换 token → GET JWKS → RS256 验签 → 归一身份。本地服务器
/// 承担 token / JWKS 两个端点（shared per scenario class）；时钟注入 FixedClock
/// （fixed 向量 exp=2023-11，真实系统时钟下必然 TokenExpired）。
async test "E2E S1: google complete_auth full chain over real local HTTP" {
  @async.with_task_group() <| group => {
    let port = start_oauth_server(
      group,
      200,
      "{\"access_token\":\"at-e2e\",\"token_type\":\"Bearer\",\"id_token\":\"" +
      @contract.fixed_token_ok +
      "\"}",
      @contract.jwks_response().body,
    )
    let clock : &@core.Clock = @contract.FixedClock::new(@contract.fixed_now_unix())
    let config = @google.GoogleConfig::new("client-1", "https://app.example/cb")
    .with_endpoints(
      @contract.google_authorization_endpoint,
      "http://127.0.0.1:\{port}/token",
      "http://127.0.0.1:\{port}/jwks",
      "https://issuer.example",
    )
    .with_clock(clock)
    let secrets : @core.SuppliedSecrets = {
      state: Some("st-123"),
      code_verifier: Some("verifier-1abcdefghijklmnopqrstuvwxyz0123456789-._~"),
      nonce: Some("nonce-1"),
    }
    let start = @google.begin_auth(config, secrets)
    let callback = @core.CallbackParams::from_query_string(
      "code=auth-code-1&state=st-123",
    )
    let identity = @google.complete_auth(config, callback, start)
    @debug.assert_eq(identity.provider, "google")
    @debug.assert_eq(identity.uid, "user-1")
    @debug.assert_eq(identity.email, Some("alice@example.com"))
    assert_true(identity.email_verified)
  }
}

///|
/// E2E-S2（JEV 0.809，全链路深度）：本地服务器对 token 端点返回 **400 + error
/// JSON**——端到端验证 `ProviderError` 归一（错误消息完整穿透真实 HTTP）。
async test "E2E S2: 400 with error JSON normalizes to provider_error end to end" {
  @async.with_task_group() <| group => {
    let port = start_oauth_server(
      group,
      400,
      "{\"error\":\"invalid_grant\",\"error_description\":\"E2E: code expired\"}",
      "{}",
    )
    let config = @google.GoogleConfig::new("client-1", "https://app.example/cb")
    .with_endpoints(
      @contract.google_authorization_endpoint,
      "http://127.0.0.1:\{port}/token",
      "http://127.0.0.1:\{port}/jwks",
      "https://issuer.example",
    )
    let secrets : @core.SuppliedSecrets = {
      state: Some("st-123"),
      code_verifier: Some("verifier-1abcdefghijklmnopqrstuvwxyz0123456789-._~"),
      nonce: Some("nonce-1"),
    }
    let start = @google.begin_auth(config, secrets)
    let callback = @core.CallbackParams::from_query_string(
      "code=auth-code-1&state=st-123",
    )
    let outcome = try {
      let _ = @google.complete_auth(config, callback, start)
      "no-error"
    } catch {
      e => @core.auth_error_code(e) + "|" + @core.auth_error_message(e)
    }
    assert_true(outcome.has_prefix("provider_error|"))
    assert_true(outcome.contains("invalid_grant"))
    assert_true(outcome.contains("E2E: code expired"))
  }
}

///|
/// E2E-S3（JEV 0.942，传输层专项）：POST 体**逐字节**完整性——回显服务器把请求体
/// 原样写回，断言 form 编码体经真实 TCP 往返后完全一致（分帧/编码无失真）。
async test "E2E S3: POST form body survives the real HTTP round trip byte-exact" {
  @async.with_task_group() <| group => {
    let port = start_echo_server(group)
    let form = "grant_type=authorization_code&code=e2e-code-1&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&client_id=client-1&code_verifier=verifier-1abcdefghijklmnopqrstuvwxyz0123456789-._~"
    let client = @core.AsyncHttpClient::new()
    let req : @core.HttpRequest = {
      method: @core.HttpMethod::Post,
      url: "http://127.0.0.1:\{port}/echo",
      headers: Map([("Content-Type", "application/x-www-form-urlencoded")]),
      body: Some(form),
    }
    let resp = client.send(req)
    @debug.assert_eq(resp.status, 200)
    // POST 体完整性：逐字节一致（含百分号编码序列原样穿透）。
    @debug.assert_eq(resp.body, form)
  }
}
