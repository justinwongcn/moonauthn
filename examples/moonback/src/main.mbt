//! moonauth / example —— **moonback** 接入示范（LIB-14）。
//!
//! 主旨：**框架只做路由，鉴权逻辑仍走库**。
//! - `moonback` 在本示例里只负责：注册路由、解析 query、把结果写回响应；
//! - 组授权 URL / 校验 state / 换 token / 验 `id_token` / 归一身份，全部由
//!   `@google` facade 完成——`oauth` / `oidc` 的细节框架完全看不到。
//!
//! 🔴 **OAuth 流程的正确形状**（接入方要抄的就是这个）：
//!   `/auth/google/login` —— **服务端**经 `begin_auth` 铸造 `state`（来自注入的
//!   `RandomSource`，**绝不硬编码、绝不在回调时凭空重建**），把整个 `AuthStart`
//!   按服务器铸造的 `state` 暂存（生产 = session/Redis），返回授权 URL；
//!   `/auth/google/callback` —— 按**回调携带的 state** 取回暂存的 `AuthStart`
//!   （**一次性**：取后即从会话删除，重放同一 state 拿不到会话），再交库校验换 token。
//!
//! 🔴 依赖只写在**本示例的 `moon.mod`**（`moonbitlang/moonback@0.8.6`，版本已锁定），
//! 库本体依赖图**不含** moonback（LIB-14 ③）。
//!
//! 运行：`moon run examples/moonback/src`（native，回环 127.0.0.1，零外部网络）。
//! 本示例用一个**一次性**回环请求驱动真实路由（`App::serve` + 本机 HTTP 客户端），
//! 请求走完真实路由链后打印结果，随后关闭，便于 CI 一次跑完。

///|
/// `/auth/google/login` 的鉴权逻辑：**服务端铸造并暂存**本次流程的临时态。
///
/// 🔴 `state` / `code_verifier` 传 `None` → 由库经注入的 `RandomSource` **现场铸造**
///（真实 CSPRNG，每次不同）——绝不硬编码、绝不在回调时凭空重建。生产中这一步应把
/// `start` 存进 session / Redis 并 302 跳转到 `start.url`；本示例返回 URL 文本，由
/// 回环驱动模拟「浏览器带回 state」。
///
/// 注：`nonce` 传入固定值是对齐 `@contract` 的**离线 mock 向量**（其 id_token 的
/// `nonce` claim 固定为 `"nonce-1"`；真实场景中 provider 会把你发送的 nonce 原样
/// 写进 id_token，由 `complete_auth` 比对）。
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
/// moonback 应用入口：注册路由 + 一次性回环请求。
async fn main {
  // 服务端会话（生产 = session/Redis；这里用进程内 Map 演示形状）。
  let session : Map[String, @core.AuthStart] = Map([])
  let app = @moonback.App(ctx => {
    // 健康检查：与鉴权无关，证明框架照常工作。
    ctx.get("/healthz", (_req, res) => {
      res.send_text("ok")
    })
    // 登录入口：服务端铸造 state + 暂存临时态，返回授权 URL（生产：302）。
    ctx.get("/auth/google/login", (_req, res) => {
      let outcome = try {
        "authorize " + google_login(session)
      } catch {
        e => "auth-error " + @core.auth_error_code(e)
      }
      res.send_text(outcome)
    })
    // OAuth 回调：框架只解析 query，真正的校验/换 token 交给库。
    ctx.get("/auth/google/callback", (req, res) => {
      let query = req.query()
      let code = query.get("code").unwrap_or("")
      let state = query.get("state").unwrap_or("")
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
    // /login：服务端铸造 state（每次不同），响应里携带授权 URL。
    let login_resp = local_get(base + "/auth/google/login")
    println("[moonback] /auth/google/login              -> " + login_resp)
    // 真实场景：浏览器带着回调参数原样回跳；这里从响应里取出 state 模拟之。
    let state = extract_state(login_resp)
    println(
      "[moonback] callback (server-minted state)  -> " +
      local_get(
        base +
        "/auth/google/callback?code=auth-code-1&state=" +
        state,
      ),
    )
    println(
      "[moonback] callback (replayed state)       -> " +
      local_get(
        base +
        "/auth/google/callback?code=auth-code-1&state=" +
        state,
      ),
    )
    println(
      "[moonback] callback (tampered state)       -> " +
      local_get(base + "/auth/google/callback?code=auth-code-1&state=WRONG"),
    )
    serving.cancel()
  })
  println("[moonback] done")
}
