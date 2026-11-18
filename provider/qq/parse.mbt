//! moonauth / provider/qq —— 响应解析：token（JSON / form 回退）、JSONP 剥壳、身份归一。
//!
//! 🔴 QQ 的 `GET /oauth2.0/me` 返回 **JSONP**：`callback( {"openid":"..."} );`。
//! 其错误分支为 `callback( {"error":N,"error_description":"..."} );`——必须**剥壳**后才能
//! 当 JSON 解析，并按错误码归类。

///|
/// 解析 QQ token 响应：优先 JSON（`fmt=json`），失败回退 `application/x-www-form-urlencoded`。
///
/// 两种形态都以 `error` 字段表达业务错误 → 归一为 `ProviderError`。
pub fn qq_parse_token(body : String) -> String raise @core.AuthError {
  let as_json : Json? = try {
    Some(@json.parse(body))
  } catch {
    _ => None
  }
  match as_json {
    Some(Object(m)) => {
      qq_check_error(m)
      match m.get("access_token") {
        Some(String(s)) => s
        _ => raise @core.ParseError("moonauth: qq token response missing access_token")
      }
    }
    _ => {
      // 非 JSON → 按 form-encoded 解析（`fmt=json` 未生效时的回退）。
      let p = @core.CallbackParams::from_form_body(body)
      match p.get("error") {
        Some(e) =>
          raise @core.ProviderError(e, match p.get("error_description") {
            Some(d) => d
            None => ""
          })
        None =>
          match p.get("access_token") {
            Some(s) => s
            None => raise @core.ParseError("moonauth: qq token response has no access_token")
          }
      }
    }
  }
}

///|
/// 剥掉 JSONP 外壳 `callback( {...} );` → 内部 JSON 文本。
///
/// 取第一个 `(` 与第一个 `)` 之间的内容（QQ 的 me 响应体不含嵌套括号）。
pub fn qq_unwrap_jsonp(body : String) -> String {
  let after_open = match body.split_once("(") {
    Some((_, rest)) => rest.to_owned()
    None => body
  }
  match after_open.split_once(")") {
    Some((inner, _)) => inner.to_owned()
    None => after_open
  }
}

///|
/// 解析 JSONP `me` 响应 → `openid`（先剥壳，再按错误码 / 字段处理）。
///
/// 🔴 **`client_id` 绑定校验（黑客审计第 1 轮确认）**：`me` 响应携带该
/// access_token 所属应用的 `client_id`——出现时**必须**与配置 appid 一致，
/// 不一致即 `ProviderError("client_id_mismatch", ...)`（防 token/openid 混入
/// 他应用的混淆攻击，与调研契约对支付宝「回调 app_id 与本地一致」的要求同构）。
/// 响应缺失 `client_id` 时无法校验，放行并记 `extra`（QQ 部分响应形态历史上有缺省）。
pub fn qq_parse_openid(
  body : String,
  expected_client_id : String,
) -> String raise @core.AuthError {
  let m = qq_object(qq_unwrap_jsonp(body), "me response")
  qq_check_error(m)
  match m.get("client_id") {
    Some(String(s)) =>
      if s != expected_client_id {
        raise @core.ProviderError(
          "client_id_mismatch",
          "moonauth: qq me response client_id \{s} does not match the configured appid",
        )
      }
    Some(_) =>
      raise @core.ProviderError(
        "client_id_mismatch",
        "moonauth: qq me response client_id is not a string",
      )
    None => ()
  }
  match m.get("openid") {
    // 🔴 空串视为缺失（契约 §2.2：subject 必须存在且非空——空串 uid 落进调用方
    // 映射表可与其它空串身份碰撞；黑客审计 E2 实测）。
    Some(String(s)) =>
      if s.length() > 0 {
        s
      } else {
        raise @core.ParseError("moonauth: qq me response has empty openid")
      }
    _ => raise @core.ParseError("moonauth: qq me response missing openid")
  }
}

///|
/// 解析 `get_user_info` 响应 → 身份（`uid = openid`，`Stable`）。
pub fn qq_identity(
  userinfo_json : String,
  openid : String,
) -> @core.ExternalIdentity raise @core.AuthError {
  let m = qq_object(userinfo_json, "userinfo response")
  // get_user_info 用 `ret`（0 = 成功）表达业务结果。
  match m.get("ret") {
    Some(Number(d, ..)) =>
      if d.to_int() != 0 {
        let msg = match m.get("msg") {
          Some(String(s)) => s
          _ => ""
        }
        raise @core.ProviderError(d.to_int().to_string(), msg)
      }
    _ => ()
  }
  let nickname = match m.get("nickname") {
    Some(String(s)) => Some(s)
    _ => None
  }
  let avatar = match m.get("figureurl_qq_1") {
    Some(String(s)) => Some(s)
    _ => match m.get("figureurl") {
      Some(String(s)) => Some(s)
      _ => None
    }
  }
  let extra : Map[String, String] = Map([])
  for k, v in m {
    extra[k] = qq_json_to_string(v)
  }
  {
    provider: "qq",
    uid: openid,
    uid_kind: @core.UidKind::Stable,
    email: None,
    email_verified: false,
    display_name: nickname,
    avatar,
    extra,
  }
}

///|
/// 解析 JSON 对象；非对象 / 非法 JSON → `ParseError`。
fn qq_object(body : String, what : String) -> Map[String, Json] raise @core.AuthError {
  let parsed : Json = @json.parse(body) catch {
    _ => raise @core.ParseError("moonauth: qq " + what + " is not valid JSON")
  }
  match parsed {
    Object(m) => m
    _ => raise @core.ParseError("moonauth: qq " + what + " is not a JSON object")
  }
}

///|
/// 若对象含 `error`（QQ 错误体）→ `ProviderError(error, error_description)`。
fn qq_check_error(m : Map[String, Json]) -> Unit raise @core.AuthError {
  match m.get("error") {
    Some(v) => {
      let code = match v {
        Number(d, ..) => d.to_int().to_string()
        String(s) => s
        _ => "unknown"
      }
      let msg = match m.get("error_description") {
        Some(String(s)) => s
        _ => ""
      }
      raise @core.ProviderError(code, msg)
    }
    None => ()
  }
}

///|
/// `Json` → 字符串视图（数值保留原始书写形态）。
fn qq_json_to_string(value : Json) -> String {
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
