//! moonauth / provider/wechat —— 回调与 token 响应解析。
//!
//! 微信的错误体是 `{"errcode":N,"errmsg":"..."}`（HTTP 仍可能是 200！）——
//! 因此解析时必须**先查 `errcode`**，命中即归一为 `ProviderError`，不能只看 HTTP 状态码。

///|
/// 微信换 token 的结果（**仅标准类型**，无 `@json` 泄漏）。
pub(all) struct WeChatToken {
  access_token : String
  openid : String
  unionid : String?
  refresh_token : String?
  expires_in : Int?
}

///|
/// 解析微信回调 query（`code` + `state`）。
pub fn wechat_callback(query : String) -> @core.CallbackParams {
  @core.CallbackParams::from_query_string(query)
}

///|
/// 解析微信 token 端点响应：命中 `errcode` → `ProviderError`；否则取 token 字段。
pub fn wechat_parse_token(body : String) -> WeChatToken raise @core.AuthError {
  let m = wechat_object(body, "token response")
  wechat_check_errcode(m)
  let access_token = match m.get("access_token") {
    Some(String(s)) => s
    _ => raise @core.ParseError("moonauth: wechat token response missing access_token")
  }
  let openid = match m.get("openid") {
    Some(String(s)) => s
    _ => raise @core.ParseError("moonauth: wechat token response missing openid")
  }
  let unionid = match m.get("unionid") {
    Some(String(s)) => Some(s)
    _ => None
  }
  let refresh_token = match m.get("refresh_token") {
    Some(String(s)) => Some(s)
    _ => None
  }
  let expires_in = match m.get("expires_in") {
    Some(Number(d, ..)) => Some(d.to_int())
    _ => None
  }
  { access_token, openid, unionid, refresh_token, expires_in }
}

///|
/// 解析 JSON 对象；非对象 / 非法 JSON → `ParseError`。
///
/// 私有：`Map[String, Json]` 含第三方类型 `@json.Json`，不得出现在 `pub` 签名里（SDK-03）。
fn wechat_object(
  body : String,
  what : String,
) -> Map[String, Json] raise @core.AuthError {
  let parsed : Json = @json.parse(body) catch {
    _ => raise @core.ParseError("moonauth: wechat " + what + " is not valid JSON")
  }
  match parsed {
    Object(m) => m
    _ => raise @core.ParseError("moonauth: wechat " + what + " is not a JSON object")
  }
}

///|
/// 微信错误体 `errcode` 的统一口径：能解出数值且**非零** → `ProviderError(errcode, errmsg)`；
/// `0` → 成功；类型不符 / 缺字段 → 成功（交由后续字段缺失兜底）。
///
/// 🔴 早期实现「存在 `errcode` 即报错」，`errcode: 0` 会被误判为失败——微信部分
/// 成功体确实带 `errcode: 0`，不能依赖「成功体无 errcode」的脆弱假设。
///
/// 私有：入参含第三方类型 `@json.Json`（SDK-03）。
fn wechat_check_errcode(m : Map[String, Json]) -> Unit raise @core.AuthError {
  let msg = match m.get("errmsg") {
    Some(String(s)) => s
    _ => ""
  }
  match m.get("errcode") {
    Some(Number(d, ..)) =>
      if d.to_int() != 0 {
        raise @core.ProviderError(d.to_int().to_string(), msg)
      }
    // 数字字符串形态：非 `"0"` 即业务错误。
    Some(String(s)) => if s != "0" {
      raise @core.ProviderError(s, msg)
    }
    _ => ()
  }
}

///|
/// `Json` → 字符串视图（数值保留原始书写形态）。
///
/// 私有：入参/返回含第三方类型 `@json.Json`（SDK-03）。
fn wechat_json_to_string(value : Json) -> String {
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
