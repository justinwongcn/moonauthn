//! moonauth / provider/feishu —— 响应解析与身份归一。
//!
//! 取值表（见平台文档 `docs/platforms/feishu.md`）：
//! - `uid = union_id`（同一开发者主体下跨应用稳定的标识），`uid_kind = Stable`；
//!   仅拿到 `open_id`（应用内标识）时降级为 `Degraded`（微信 unionid 先例）；
//! - `display_name = name`，`avatar = avatar_url`，`email = email`（常缺省）；
//! - 其余字段进 `extra`（字符串视图，无第三方类型泄漏）。

///|
/// 解析 token 响应，返回 `access_token`。
///
/// 🔴 真实 v2 端点（`POST /authen/v2/oauth/token`）的成功响应是
/// `{code:0, msg:"success", data:{access_token, ...}}` **信封壳**（与官方 Go/Node SDK
/// 的 `AuthenAccessTokenResp.Data` 模型一致）；为兼容「OAuth2 标准平铺形态
/// `{"access_token":"..."}`」（亦为官方文档所列形态），本函数**信封优先、平铺兼容**：
/// 有 `data` 对象则解包，否则回退顶层取值。
pub fn feishu_parse_token(body : String) -> String raise @core.AuthError {
  let m = feishu_object(body, "token response")
  feishu_check_envelope(m)
  let fields = match m.get("data") {
    Some(Object(data)) => data
    _ => m
  }
  match fields.get("access_token") {
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
  // 🔴 空串视为缺失（同微信 `non_empty_opt` 先例）：`union_id: ""` 在场时若按
  // 「键在场」判定会产出 `uid=""` 且标 `Stable`，下游按跨应用稳定标识建映射即踩空。
  let union_id = feishu_non_empty(user.get("union_id"))
  let uid_kind = match union_id {
    Some(_) => @core.UidKind::Stable
    None => @core.UidKind::Degraded
  }
  let uid = match union_id {
    Some(u) => u
    None =>
      match feishu_non_empty(user.get("open_id")) {
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
/// 非 2xx 响应的错误归一：飞书 v2 的错误体有两种实测形态，按序尝试——
/// ① OAuth2 标准错误 `{"error":"...","error_description":"..."}` → `ProviderError`；
/// ② 平台信封 `{"code":99991663,"msg":"...","data":null}` → `ProviderError`；
/// 两者都解不出 → `HttpStatus`。
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
      if err != "" {
        let desc = match m.get("error_description") {
          Some(String(s)) => s
          _ => ""
        }
        raise @core.ProviderError(err, desc)
      }
      match m.get("code") {
        Some(Number(d, ..)) if d.to_int() != 0 => {
          let msg = match m.get("msg") {
            Some(String(s)) => s
            _ => ""
          }
          raise @core.ProviderError(d.to_int().to_string(), msg)
        }
        _ => raise @core.HttpStatus(resp.status, resp.body)
      }
    }
    _ => raise @core.HttpStatus(resp.status, resp.body)
  }
}

///|
/// 若信封 `code != 0`（飞书业务错误）→ `ProviderError(code, msg)`。
///
/// 口径（全库统一）：能解出数值且非零 → 报错；`0` → 成功；类型不符 / 缺字段 →
/// 成功（交由后续字段缺失兜底）。`code` 兼容 `Number` 与数字字符串两形态
/// （飞书部分响应以 `"0"` / `"20035"` 字符串返回）。
fn feishu_check_envelope(m : Map[String, Json]) -> Unit raise @core.AuthError {
  let code_msg = match m.get("msg") {
    Some(String(s)) => s
    _ => ""
  }
  match m.get("code") {
    Some(Number(d, ..)) =>
      if d.to_int() != 0 {
        raise @core.ProviderError(d.to_int().to_string(), code_msg)
      }
    // 数字字符串形态：非 `"0"` 即业务错误。
    Some(String(s)) => if s != "0" {
      raise @core.ProviderError(s, code_msg)
    }
    _ => ()
  }
}

///|
/// `Json?` → 非空字符串（`null` / 缺失 / `""` → `None`）。
///
/// uid 判定专用：空串不能当稳定标识（见 `feishu_identity` 内注释）。
fn feishu_non_empty(value : Json?) -> String? {
  match feishu_string_opt(value) {
    Some(s) => if s.length() > 0 { Some(s) } else { None }
    None => None
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
