//! moonauth / provider/feishu —— 响应解析与身份归一。
//!
//! 取值表（见平台文档 `docs/platforms/feishu.md`）：
//! - `uid = union_id`（同一开发者主体下跨应用稳定的标识），`uid_kind = Stable`；
//!   仅拿到 `open_id`（应用内标识）时降级为 `Degraded`（微信 unionid 先例）；
//! - `display_name = name`，`avatar = avatar_url`，`email = email`（常缺省）；
//! - 其余字段进 `extra`（字符串视图，无第三方类型泄漏）。

///|
/// 解析 token 响应（v2 顶层即
/// `{"access_token":"...","token_type":"Bearer","expires_in":...,"refresh_token":"..."}`）。
pub fn feishu_parse_token(body : String) -> String raise @core.AuthError {
  let m = feishu_object(body, "token response")
  feishu_check_envelope(m)
  match m.get("access_token") {
    Some(String(s)) => s
    _ => raise @core.ParseError("moonauth: feishu token response missing access_token")
  }
}

///|
/// 剥 `{code, msg, data}` 信封壳：`code != 0` → `ProviderError`；成功返回 `data` 对象。
fn feishu_unwrap_envelope(body : String) -> Map[String, Json] raise @core.AuthError {
  let m = feishu_object(body, "userinfo response")
  feishu_check_envelope(m)
  match m.get("data") {
    Some(Object(data)) => data
    _ => raise @core.ParseError("moonauth: feishu userinfo response missing data object")
  }
}

///|
/// 归一化：`user_info` **响应 JSON 文本** → `ExternalIdentity`。
///
/// 🔴 入参收原始文本而非 `Map[String, Json]`：`Json` 是第三方类型，不得出现在
/// `pub` 签名上（SDK-03，同 `qq_identity` 先例）。
pub fn feishu_identity(user_json : String) -> @core.ExternalIdentity raise @core.AuthError {
  let user = feishu_unwrap_envelope(user_json)
  let uid_kind = match user.get("union_id") {
    Some(String(_)) => @core.UidKind::Stable
    _ => @core.UidKind::Degraded
  }
  let uid = match feishu_string_opt(user.get("union_id")) {
    Some(u) => u
    None =>
      match feishu_string_opt(user.get("open_id")) {
        Some(o) => o
        None =>
          raise @core.ParseError(
            "moonauth: feishu userinfo data missing union_id/open_id",
          )
      }
  }
  let extra : Map[String, String] = Map([])
  for k, v in user {
    extra[k] = feishu_json_to_string(v)
  }
  {
    provider: "feishu",
    uid,
    uid_kind,
    email: feishu_string_opt(user.get("email")),
    // 飞书 user_info 不提供邮箱验证标记，一律记 false。
    email_verified: false,
    display_name: feishu_string_opt(user.get("name")),
    avatar: feishu_string_opt(user.get("avatar_url")),
    extra,
  }
}

///|
/// 解析 JSON 对象；非对象 / 非法 JSON → `ParseError`。
fn feishu_object(body : String, what : String) -> Map[String, Json] raise @core.AuthError {
  let parsed : Json = @json.parse(body) catch {
    _ => raise @core.ParseError("moonauth: feishu " + what + " is not valid JSON")
  }
  match parsed {
    Object(m) => m
    _ => raise @core.ParseError("moonauth: feishu " + what + " is not a JSON object")
  }
}

///|
/// 非 2xx 响应的错误归一：飞书 v2 遵循 OAuth2 标准错误体
/// `{"error":"...","error_description":"..."}` → `ProviderError`；解不出 → `HttpStatus`。
fn feishu_raise_http_error(resp : @core.HttpResponse) -> Unit raise @core.AuthError {
  let parsed : Json? = try {
    Some(@json.parse(resp.body))
  } catch {
    _ => None
  }
  match parsed {
    Some(Object(m)) => {
      let err = match m.get("error") {
        Some(String(s)) => s
        _ => ""
      }
      let desc = match m.get("error_description") {
        Some(String(s)) => s
        _ => ""
      }
      if err != "" {
        raise @core.ProviderError(err, desc)
      }
      raise @core.HttpStatus(resp.status, resp.body)
    }
    _ => raise @core.HttpStatus(resp.status, resp.body)
  }
}

///|
/// 若信封 `code != 0`（飞书业务错误）→ `ProviderError(code, msg)`。
fn feishu_check_envelope(m : Map[String, Json]) -> Unit raise @core.AuthError {
  match m.get("code") {
    // 成功信封 `code: 0`；无 `code` 字段视为成功（token v2 顶层无信封）。
    Some(Number(d, ..)) => {
      let code = d.to_int()
      if code != 0 {
        let msg = match m.get("msg") {
          Some(String(s)) => s
          _ => ""
        }
        raise @core.ProviderError(code.to_string(), msg)
      }
    }
    _ => ()
  }
}

///|
/// `Json` → 可选字符串（数值保留原始书写形态；`null` / 缺失 → `None`）。
fn feishu_string_opt(value : Json?) -> String? {
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
fn feishu_json_to_string(value : Json) -> String {
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
