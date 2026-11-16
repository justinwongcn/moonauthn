//! moonauth / provider/wechat —— 小程序登录（`code2Session`）。
//!
//! 小程序链路与网站扫码**完全不同**：没有浏览器回调、没有 `state`、没有 refresh
//! token——小程序端 `wx.login()` 取得临时 `code`（约 5 分钟有效）后，由服务端直接
//! 调 `code2Session` 换身份。官方注明该接口**只能在服务端调用**（不可在小程序、
//! 网页、APP 等前端直接调用）。
//!
//! 端点与响应经官方文档核实（2026-11-17，见 `docs/platforms/wechat.md`）：
//! `GET /sns/jscode2session?appid=&secret=&js_code=&grant_type=authorization_code`，
//! 返回 `openid` / `session_key` / 条件 `unionid`；错误经 `errcode` / `errmsg`
//! 表达（HTTP 仍可能是 200）。
//!
//! 身份归一与网站链路**同一口径**（`provider = "wechat"`，`unionid` 优先、
//! `openid` 兜底 `Degraded`）：同一开放平台账号下的网站 + 小程序可用 `unionid`
//! 关联同一用户；缺 `unionid` 时由调用方依据 `Degraded` 自行决定绑定策略。

///|
/// 小程序登录结果：归一身份 + 服务端专用的 `session_key`。
///
/// 🔴 `session_key` 是微信的会话密钥（解密用户数据用），**不是**本库会话，
/// 更不能替代调用方自己的登录态：
/// - 只允许保存在服务端，绝不返回小程序前端 / 浏览器；
/// - 不写入普通日志（微信文档将其列为敏感数据）；
/// - 每次 `code2Session` 都会返回**新的** `session_key`（自动轮换），
///   怀疑泄露时重新执行登录即可，无需撤销旧值；
/// - 不需要解密用户数据时可以完全不持久化它（只用 `openid` / `unionid`）。
///
/// 库零状态：拿到后随结果交还调用方，本库不做任何保存。
pub(all) struct WeChatCode2Session {
  identity : @core.ExternalIdentity
  session_key : String
}

///|
/// 小程序登录：`wx.login()` 的 `js_code` → `GET /sns/jscode2session` → 归一身份。
///
/// 错误口径与整包一致：**先查 `errcode`**（`40029` code 无效 / `40226` 高风险用户
/// 拦截 / `45011` 分钟级频控 / `-1` 系统繁忙等），非零即 `ProviderError`——
/// 不能只看 HTTP 状态码。
///
/// `extra` 只携带 `openid` / `unionid`（`session_key` 不进 `extra`——它是敏感
/// 密钥，只经专用字段返回，避免调用方把 `extra` 当普通元数据记录时意外落日志）。
pub async fn wechat_code2_session(
  config : WeChatConfig,
  js_code : String,
) -> WeChatCode2Session raise @core.AuthError {
  // 🔴 动态值一律编码：appid / secret / js_code 含 `&`、`+` 等字符时未编码
  // 会静默坏请求（与 `wechat_fetch_token` 同一口径）。
  let url = config.code2_session_endpoint +
    "?appid=" +
    wechat_percent_encode(config.appid) +
    "&secret=" +
    wechat_percent_encode(config.secret) +
    "&js_code=" +
    wechat_percent_encode(js_code) +
    "&grant_type=authorization_code"
  let resp = config.http.send({
    method : @core.HttpMethod::Get,
    url,
    headers : Map([("Accept", "application/json")]),
    body : None,
  })
  if resp.status < 200 || resp.status >= 300 {
    raise @core.HttpStatus(resp.status, resp.body)
  }
  let m = wechat_object(resp.body, "code2session response")
  wechat_check_errcode(m)
  let openid = match m.get("openid") {
    Some(String(s)) =>
      if s.length() > 0 {
        s
      } else {
        raise @core.ParseError(
          "moonauth: wechat code2session response has empty openid",
        )
      }
    _ =>
      raise @core.ParseError(
        "moonauth: wechat code2session response missing openid",
      )
  }
  let unionid = match m.get("unionid") {
    Some(String(s)) => if s.length() > 0 { Some(s) } else { None }
    _ => None
  }
  let session_key = match m.get("session_key") {
    Some(String(s)) => s
    _ => ""
  }
  let (uid, kind) = wechat_pick_uid(unionid, openid)
  let extra : Map[String, String] = Map([("openid", openid)])
  match unionid {
    Some(u) => extra["unionid"] = u
    None => ()
  }
  {
    identity: {
      provider: "wechat",
      uid,
      uid_kind: kind,
      email: None,
      email_verified: false,
      display_name: None,
      avatar: None,
      extra,
    },
    session_key,
  }
}
