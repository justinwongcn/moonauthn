//! moonauth / example —— **mars** 接入示范（LIB-14）。
//!
//! 主旨：**框架只做路由，鉴权逻辑仍走库**。
//! - `mars` 在本示例里只负责：注册路由、读 query、把结果写回响应；
//! - 组授权 URL / 校验 state / 换 token / 验 `id_token` / 归一身份，全部由
//!   `@google` facade 完成——`oauth` / `oidc` 的细节框架完全看不到。
//!
//! 🔴 依赖只写在**本示例的 `moon.mod`**（`mizchi/mars@0.3.13`，版本已锁定），
//! 库本体依赖图**不含** mars（LIB-14 ③）。mars 的 native HTTP 栈是 `mizchi/x/http`，
//! 故示例直接构造 `@xhttp.Server` 以取得**回环临时端口**，便于 CI 一次跑完。
//!
//! 运行：`moon run examples/mars/src`（native，回环 127.0.0.1，零外部网络）。

///|
/// 框架无关的鉴权逻辑（**库的职责**，框架看不到）：
/// `begin` 固定用 `state = "st-c1"`，`complete` 用请求带来的 `code`/`state`
/// 交由 facade 做 `state` 校验（「state 必须由库把关」的示范）。
async fn google_complete_from(
  code : String,
  state : String,
) -> @core.ExternalIdentity raise @core.AuthError {
  let config = @contract.google_mock_config()
  let start = @google.begin_auth(config, {
    state: Some("st-c1"),
    code_verifier: Some("verifier-1"),
    nonce: Some("nonce-1"),
  })
  let callback = @core.CallbackParams::from_pairs(
    Map([("code", code), ("state", state)]),
  )
  @google.complete_auth(config, callback, start)
}

///|
/// 发一条本机 GET，返回 `"<状态码> <响应体>"`（用于一次性回环验证）。
async fn local_get(url : String) -> String {
  let (response, body) = @http.get(url)
  let text = try {
    body.text()
  } catch {
    _ => "<body decode error>"
  }
  response.code.to_string() + " " + text
}

///|
/// mars 应用入口：注册路由 + 一次性回环请求。
async fn main {
  let app = @mars.Server::new()
  // 健康检查：与鉴权无关，证明框架照常工作。
  app.get("/healthz", @mars.handler(async fn(ctx) {
    ctx.text("ok")
  }))
  // OAuth 回调：框架只读 query，校验/换 token 交给库。
  app.get("/auth/google/callback", @mars.handler(async fn(ctx) {
    let code = ctx.query("code").unwrap_or("")
    let state = ctx.query("state").unwrap_or("")
    let outcome = try {
      let identity = google_complete_from(code, state)
      "uid=" +
      identity.uid +
      " provider=" +
      identity.provider +
      " email=" +
      identity.email.unwrap_or("-")
    } catch {
      e => "auth-error " + @core.auth_error_code(e)
    }
    ctx.text(outcome)
  }))

  let server = try {
    @xhttp.Server::new(host="127.0.0.1", port=0)
  } catch {
    _ => abort("mars demo: failed to bind loopback")
  }
  let port = server.port()
  let base = "http://127.0.0.1:" + port.to_string()
  println("[mars] listening on " + base)

  @async.with_task_group(group => {
    let serving = group.spawn(() => {
      try {
        server.run_forever(app.to_handler())
      } catch {
        _ => ()
      }
    })
    @async.sleep(80)
    println(
      "[mars] /healthz                  -> " + local_get(base + "/healthz"),
    )
    println(
      "[mars] callback (valid state)    -> " +
      local_get(base + "/auth/google/callback?code=auth-code-1&state=st-c1"),
    )
    println(
      "[mars] callback (tampered state) -> " +
      local_get(base + "/auth/google/callback?code=auth-code-1&state=WRONG"),
    )
    serving.cancel()
  })
  println("[mars] done")
}
