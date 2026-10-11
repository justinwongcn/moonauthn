//! moonauth / example —— **mars** 接入示范（LIB-14）。
//!
//! 主旨：**框架只做路由，鉴权逻辑仍走库**。
//! - `mars` 在本示例里只负责：注册路由、读 query、把结果写回响应；
//! - 组授权 URL / 校验 state / 换 token / 验 `id_token` / 归一身份，全部由
//!   `@google` facade 完成——`oauth` / `oidc` 的细节框架完全看不到。
//!
//! 🔴 **OAuth 流程的正确形状**（与 `examples/moonback` 同构，接入方要抄的就是这个）：
//!   `/auth/google/login` —— **服务端**经 `begin_auth` 铸造 `state`（来自注入的
//!   `RandomSource`，绝不硬编码、绝不在回调时凭空重建），把整个 `AuthStart` 按
//!   服务器铸造的 `state` 暂存（生产 = session/Redis），返回授权 URL；
//!   `/auth/google/callback` —— 按**回调携带的 state** 一次性取回 `AuthStart`
//!   （取后即删，重放拒绝），再交库校验换 token。
//!
//! 🔴 依赖只写在**本示例的 `moon.mod`**（`mizchi/mars@0.3.13`，版本已锁定），
//! 库本体依赖图**不含** mars（LIB-14 ③）。mars 的 native HTTP 栈是 `mizchi/x/http`，
//! 故示例直接构造 `@xhttp.Server` 以取得**回环临时端口**，便于 CI 一次跑完。
//!
//! 运行：`moon run examples/mars/src`（native，回环 127.0.0.1，零外部网络）。

///|
/// `/auth/google/login` 的鉴权逻辑：**服务端铸造并暂存**本次流程的临时态。
///
/// 🔴 `state` / `code_verifier` 传 `None` → 由库经注入的 `RandomSource` 现场铸造。
/// `nonce` 固定为 `"nonce-1"` 仅为对齐 `@contract` 的离线 mock 向量（其 id_token 的
/// `nonce` claim 固定；真实场景 provider 会原样回写你发送的 nonce）。
async fn google_login(
  session : Map[String, @core.AuthStart],
) -> String raise @core.AuthError {
  let config = @contract.google_mock_config()
  let start = @google.begin_auth(config, {
    state: None,
    code_verifier: None,
    nonce: Some("nonce-1"),
  })
  session[start.state] = start
  start.url
}

///|
/// `/auth/google/callback` 的鉴权逻辑：按回调 `state` **一次性**取回暂存的
/// `AuthStart`，交库校验（state 比对 → 换 token → 验 `id_token` → 归一身份）。
async fn google_complete_from(
  session : Map[String, @core.AuthStart],
  code : String,
  state : String,
) -> @core.ExternalIdentity raise @core.AuthError {
  // 未知 / 已消费的 state：会话里取不到 → 直接 `StateMismatch`（无会话可续）。
  let start = match session.get(state) {
    Some(s) => s
    None => raise @core.StateMismatch
  }
  session.remove(state)
  let config = @contract.google_mock_config()
  let callback = @core.CallbackParams::from_pairs(
    Map([("code", code), ("state", state)]),
  )
  @google.complete_auth(config, callback, start)
}

///|
/// 从 `/login` 的响应（授权 URL 文本）里取出 `state` 参数——模拟浏览器原样带回。
fn extract_state(url_text : String) -> String {
  let marker = "state="
  let from = match url_text.find(marker) {
    Some(i) => i + marker.length()
    None => return ""
  }
  let rest = url_text[from:]
  match rest.find("&") {
    Some(end) => rest[:end].to_owned()
    None => rest.to_owned()
  }
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
  // 服务端会话（生产 = session/Redis；这里用进程内 Map 演示形状）。
  let session : Map[String, @core.AuthStart] = Map([])
  let app = @mars.Server::new()
  // 健康检查：与鉴权无关，证明框架照常工作。
  app.get("/healthz", @mars.handler(async fn(ctx) {
    ctx.text("ok")
  }))
  // 登录入口：服务端铸造 state + 暂存临时态，返回授权 URL（生产：302）。
  app.get("/auth/google/login", @mars.handler(async fn(ctx) {
    let outcome = try {
      "authorize " + google_login(session)
    } catch {
      e => "auth-error " + @core.auth_error_code(e)
    }
    ctx.text(outcome)
  }))
  // OAuth 回调：框架只读 query，校验/换 token 交给库。
  app.get("/auth/google/callback", @mars.handler(async fn(ctx) {
    let code = ctx.query("code").unwrap_or("")
    let state = ctx.query("state").unwrap_or("")
    let outcome = try {
      let identity = google_complete_from(session, code, state)
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
    // /login：服务端铸造 state（每次不同），响应里携带授权 URL。
    let login_resp = local_get(base + "/auth/google/login")
    println("[mars] /auth/google/login        -> " + login_resp)
    // 真实场景：浏览器带着回调参数原样回跳；这里从响应里取出 state 模拟之。
    let state = extract_state(login_resp)
    println(
      "[mars] callback (server-minted)  -> " +
      local_get(
        base +
        "/auth/google/callback?code=auth-code-1&state=" +
        state,
      ),
    )
    println(
      "[mars] callback (replayed)       -> " +
      local_get(
        base +
        "/auth/google/callback?code=auth-code-1&state=" +
        state,
      ),
    )
    println(
      "[mars] callback (tampered)       -> " +
      local_get(base + "/auth/google/callback?code=auth-code-1&state=WRONG"),
    )
    serving.cancel()
  })
  println("[mars] done")
}
