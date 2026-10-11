//! moonauth / provider/wechat —— 用户信息获取与身份归一化。
//!
//! 🔴 **主键策略**：`unionid` 优先、`openid` 兜底。
//! - `unionid` 在同一微信开放平台账号下的所有应用间一致 → `uid_kind = Stable`；
//! - 若只有 `openid`（同一用户在不同 app 下不同）→ `uid_kind = Degraded`，
//!   调用方据此决定是否接受绑定（降级是**成功的**登录，不是错误）。
//!
//! 字段可缺省：`nickname` / `headimgurl` 自 2021 年起可能不再返回。

///|
/// 获取微信用户信息（`GET /sns/userinfo`，query 传 `access_token` + `openid`）。
pub async fn wechat_fetch_userinfo(
  config : WeChatConfig,
  access_token : String,
  openid : String,
) -> String raise @core.AuthError {
  let url = config.userinfo_endpoint +
    "?access_token=" +
    access_token +
    "&openid=" +
    openid +
    "&lang=zh_CN"
  let resp = config.http.send({
    method : @core.HttpMethod::Get,
    url,
    headers : Map([("Accept", "application/json")]),
    body : None,
  })
  if resp.status < 200 || resp.status >= 300 {
    raise @core.HttpStatus(resp.status, resp.body)
  }
  resp.body
}

///|
/// 把 `/sns/userinfo` 的 JSON 归一为 `ExternalIdentity`。
///
/// 🔴 **unionid 兜底链**（优先级从高到低）：`userinfo.unionid` →
/// `fallback_unionid`（token 响应里的 `unionid`）→ 无（则 `uid = openid` 且 `Degraded`）。
/// `fallback_openid` 为 token 响应里带的 `openid`（userinfo 缺省时兜底）。
///
/// 之所以用 `fallback_unionid`：token 响应偶尔带 `unionid` 而 `/sns/userinfo` 未带
/// （罕见但可能）——若只看 userinfo 会把本可 `Stable` 的登录**低估为 `Degraded`**。
pub fn wechat_identity(
  userinfo_json : String,
  fallback_openid : String,
  fallback_unionid? : String? = None,
) -> @core.ExternalIdentity raise @core.AuthError {
  let m = wechat_object(userinfo_json, "userinfo response")
  wechat_check_errcode(m)
  let openid = match m.get("openid") {
    Some(String(s)) => s
    _ => fallback_openid
  }
  // token 里的 unionid（空串视为缺失）
  let token_unionid = non_empty_opt(fallback_unionid)
  // userinfo.unionid 优先；为空则回退 token 的 unionid
  let unionid = match m.get("unionid") {
    Some(String(s)) => if s.length() > 0 { Some(s) } else { token_unionid }
    _ => token_unionid
  }
  let uid = match unionid {
    Some(u) => u
    None => openid
  }
  let kind = match unionid {
    Some(_) => @core.UidKind::Stable
    None => @core.UidKind::Degraded
  }
  let nickname = match m.get("nickname") {
    Some(String(s)) => Some(s)
    _ => None
  }
  let headimgurl = match m.get("headimgurl") {
    Some(String(s)) => Some(s)
    _ => None
  }
  let extra : Map[String, String] = Map([])
  for k, v in m {
    extra[k] = wechat_json_to_string(v)
  }
  {
    provider: "wechat",
    uid,
    uid_kind: kind,
    email: None,
    email_verified: false,
    display_name: nickname,
    avatar: headimgurl,
    extra,
  }
}

///|
/// 把 `String?` 归一为「非空才 `Some`」：`None` 或 `Some("")` → `None`。
/// 供 unionid 兜底链判定「token 是否真的带了 unionid」。
fn non_empty_opt(v : String?) -> String? {
  match v {
    Some(s) => if s.length() > 0 { Some(s) } else { None }
    None => None
  }
}
