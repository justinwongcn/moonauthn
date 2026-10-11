//! moonauth / provider/dingtalk —— 响应解析与身份归一。
//!
//! 取值表（见平台文档 `docs/platforms/dingtalk.md`）：
//! - `uid = unionId`（跨应用稳定的标识），`uid_kind = Stable`；
//!   仅拿到 `openId`（应用内标识）时降级为 `Degraded`（微信 unionid 先例）；
//! - `display_name = nick`，`avatar = avatarUrl`，`email = email`（常缺省）；
//! - 其余字段进 `extra`（字符串视图，无第三方类型泄漏）。

///|
/// 解析 token 响应（`{"expireIn":...,"accessToken":"...","refreshToken":"..."}`）。
pub fn dingtalk_parse_token(body : String) -> String raise @core.AuthError {
  let m = dingtalk_object(body, "token response")
  dingtalk_check_error(m)
  match m.get("accessToken") {
    Some(String(s)) => s
    _ => raise @core.ParseError("moonauth: dingtalk token response missing accessToken")
  }
}

///|
/// 归一化：`/v1.0/contact/users/me` **响应 JSON 文本** → `ExternalIdentity`。
///
/// 🔴 入参收原始文本而非 `Map[String, Json]`：`Json` 是第三方类型，不得出现在
/// `pub` 签名上（SDK-03，同 `qq_identity` 先例）。
pub fn dingtalk_identity(user_json : String) -> @core.ExternalIdentity raise @core.AuthError {
  let user = dingtalk_object(user_json, "userinfo response")
  // 2xx 体内嵌错误码的罕见分支也按统一口径归一（同 wechat_identity 先例）。
  dingtalk_check_error(user)
  // 🔴 空串视为缺失（同微信 `non_empty_opt` 先例）：`unionId: ""` 在场时若按
  // 「键在场」判定会产出 `uid=""` 且标 `Stable`，下游按跨应用稳定标识建映射即踩空。
  let union_id = dingtalk_non_empty(user.get("unionId"))
  let uid_kind = match union_id {
    Some(_) => @core.UidKind::Stable
    None => @core.UidKind::Degraded
  }
  let uid = match union_id {
    Some(u) => u
    None =>
      match dingtalk_non_empty(user.get("openId")) {
        Some(o) => o
        None =>
          raise @core.ParseError(
            "moonauth: dingtalk userinfo response missing unionId/openId",
          )
      }
  }
  let extra : Map[String, String] = Map([])
  for k, v in user {
    extra[k] = dingtalk_json_to_string(v)
  }
  {
    provider: "dingtalk",
    uid,
    uid_kind,
    email: dingtalk_string_opt(user.get("email")),
    // 钉钉 users/me 不提供邮箱验证标记，一律记 false。
    email_verified: false,
    display_name: dingtalk_string_opt(user.get("nick")),
    avatar: dingtalk_string_opt(user.get("avatarUrl")),
    extra,
  }
}

///|
/// 解析 JSON 对象；非对象 / 非法 JSON → `ParseError`。
fn dingtalk_object(body : String, what : String) -> Map[String, Json] raise @core.AuthError {
  let parsed : Json = @json.parse(body) catch {
    _ => raise @core.ParseError("moonauth: dingtalk " + what + " is not valid JSON")
  }
  match parsed {
    Object(m) => m
    _ => raise @core.ParseError("moonauth: dingtalk " + what + " is not a JSON object")
  }
}

///|
/// 非 2xx 响应的错误归一：钉钉 v1.0 错误体为 `{"code":"...","message":"..."}` →
/// `ProviderError`；解不出 → `HttpStatus`。
fn dingtalk_raise_http_error(resp : @core.HttpResponse) -> Unit raise @core.AuthError {
  let parsed : Json? = try {
    Some(@json.parse(resp.body))
  } catch {
    _ => None
  }
  match parsed {
    Some(Object(m)) => {
      // 口径（全库统一）：`code` 兼容字符串与数值两形态，非零即业务错误。
      let code = match m.get("code") {
        Some(String(s)) => s
        Some(Number(d, ..)) => d.to_int().to_string()
        _ => ""
      }
      let message = match m.get("message") {
        Some(String(s)) => s
        _ => ""
      }
      if code != "" && code != "0" {
        raise @core.ProviderError(code, message)
      }
      raise @core.HttpStatus(resp.status, resp.body)
    }
    _ => raise @core.HttpStatus(resp.status, resp.body)
  }
}

///|
/// 若对象含 `code`（钉钉错误体，2xx 响应内嵌错误的罕见分支）→ `ProviderError`。
fn dingtalk_check_error(m : Map[String, Json]) -> Unit raise @core.AuthError {
  // 口径（全库统一）：能解出数值且非零 → 报错；`0` / 缺字段 → 成功；
  // `code` 兼容字符串与数值两形态（钉钉文档以字符串为主，数值形态实测亦存在）。
  let message = match m.get("message") {
    Some(String(s)) => s
    _ => ""
  }
  match m.get("code") {
    Some(Number(d, ..)) =>
      if d.to_int() != 0 {
        raise @core.ProviderError(d.to_int().to_string(), message)
      }
    Some(String(code)) =>
      if code != "" && code != "0" {
        raise @core.ProviderError(code, message)
      }
    _ => ()
  }
}

///|
/// `Json?` → 非空字符串（`null` / 缺失 / `""` → `None`）。
///
/// uid 判定专用：空串不能当稳定标识（见 `dingtalk_identity` 内注释）。
fn dingtalk_non_empty(value : Json?) -> String? {
  match dingtalk_string_opt(value) {
    Some(s) => if s.length() > 0 { Some(s) } else { None }
    None => None
  }
}

///|
/// `Json` → 可选字符串（数值保留原始书写形态；`null` / 缺失 → `None`）。
fn dingtalk_string_opt(value : Json?) -> String? {
  match value {
    Some(String(s)) => Some(s)
    Some(Number(d, repr~)) =>
      match repr {
        Some(r) => Some(r)
        None => Some(d.to_string())
      }
    _ => None
  }
}

///|
/// `Json` → 字符串视图（数值保留原始书写形态）。
fn dingtalk_json_to_string(value : Json) -> String {
  match value {
    String(s) => s
    True => "true"
    False => "false"
    Null => "null"
    Number(d, repr~) =>
      match repr {
        Some(r) => r
        None => d.to_string()
      }
    _ => value.stringify()
  }
}
