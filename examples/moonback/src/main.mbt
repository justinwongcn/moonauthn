//! moonauth / example —— **moonback** 接入示范（LIB-14）。
//!
//! 主旨：**框架只做路由，鉴权逻辑仍走库**。
//! - `moonback` 在本示例里只负责：注册路由、解析 query、把结果写回响应；
//! - 组授权 URL / 校验 state / 换 token / 验 `id_token` / 归一身份，全部由
//!   `@google` facade 完成——`oauth` / `oidc` 的细节框架完全看不到。
//!
//! 🔴 依赖只写在**本示例的 `moon.mod`**（`moonbitlang/moonback@0.8.6`，版本已锁定），
//! 库本体依赖图**不含** moonback（LIB-14 ③）。
//!
//! 运行：`moon run examples/moonback/src`（native，回环 127.0.0.1，零外部网络）。
//! 本示例用一个**一次性**回环请求驱动真实路由（`App::serve` + 本机 HTTP 客户端），
//! 请求走完真实路由链后打印结果，随后关闭，便于 CI 一次跑完。

///|
/// 框架无关的鉴权逻辑（**库的职责**，框架看不到）：
/// 用固定装配 + 固定向量把「回调 → 归一化身份」跑完。
///
/// `begin` 固定用 `state = "st-c1"`，`complete` 用请求里带来的 `code`/`state`
/// 交由 facade 做 `state` 校验（这正是「state 必须由库把关」的示范）。
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
/// moonback 应用入口：注册路由 + 一次性回环请求。
async fn main {
  let app = @moonback.App(ctx => {
    // 健康检查：与鉴权无关，证明框架照常工作。
    ctx.get("/healthz", (_req, res) => {
      res.send_text("ok")
    })
    // OAuth 回调：框架只解析 query，真正的校验/换 token 交给库。
    ctx.get("/auth/google/callback", (req, res) => {
      let query = req.query()
      let code = query.get("code").unwrap_or("")
      let state = query.get("state").unwrap_or("")
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
      res.send_text(outcome)
    })
  })
  defer app.close()

  let server = @moonback.listen(host="127.0.0.1", port=0)
  let base = "http://127.0.0.1:" + server.addr.port().to_string()
  println("[moonback] listening on " + base)

  @async.with_task_group(group => {
    let serving = group.spawn(() => app.serve(server))
    @async.sleep(80)
    println(
      "[moonback] /healthz                        -> " + local_get(base + "/healthz"),
    )
    println(
      "[moonback] callback (valid state)          -> " +
      local_get(base + "/auth/google/callback?code=auth-code-1&state=st-c1"),
    )
    println(
      "[moonback] callback (tampered state)       -> " +
      local_get(base + "/auth/google/callback?code=auth-code-1&state=WRONG"),
    )
    serving.cancel()
  })
  println("[moonback] done")
}
