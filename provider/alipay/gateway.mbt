//! moonauth / provider/alipay —— 网关调用（换 token / 取用户信息）与身份归一。
//!
//! 所有调用统一走 `gateway.do`：构造公共参数 + 业务参数 → RSA2 签名 → POST 表单 →
//! 解析 `*_response` / `error_response`。

///|
/// 网关调用：`method` + 业务参数（`biz`）→ 指定响应节点（`response_node`）的扁平映射。
///
/// 响应含 `error_response` → `ProviderError(code, msg)`。
pub async fn alipay_gateway_call(
  config : AlipayConfig,
  method : String,
  response_node : String,
  biz : Map[String, String],
) -> Map[String, String] raise @core.AuthError {
  let params = alipay_common_params(config, method)
  for k, v in biz {
    params[k] = v
  }
  let sign = alipay_sign(config, params)
  params["sign"] = sign
  let body = alipay_form_body(params)
  let resp = config.http.send({
    method : @core.HttpMethod::Post,
    url : config.gateway_endpoint,
    headers : Map([("Content-Type", "application/x-www-form-urlencoded;charset=utf-8")]),
    body : Some(body),
  })
  if resp.status < 200 || resp.status >= 300 {
    raise @core.HttpStatus(resp.status, resp.body)
  }
  let top = alipay_object(resp.body, "gateway response")
  match top.get("error_response") {
    Some(Object(e)) => {
      let code = match e.get("code") {
        Some(String(s)) => s
        _ => "unknown"
      }
      let msg = match e.get("msg") {
        Some(String(s)) => s
        _ => ""
      }
      raise @core.ProviderError(code, msg)
    }
    _ => ()
  }
  match top.get(response_node) {
    Some(Object(m)) => {
      let out : Map[String, String] = Map([])
      for k, v in m {
        out[k] = alipay_json_to_string(v)
      }
      out
    }
    _ => raise @core.ParseError("moonauth: alipay response missing " + response_node)
  }
}

///|
/// `alipay.system.oauth.token`：用 `auth_code` 换 token。
pub async fn alipay_fetch_token(
  config : AlipayConfig,
  code : String,
) -> Map[String, String] raise @core.AuthError {
  alipay_gateway_call(
    config,
    "alipay.system.oauth.token",
    "alipay_system_oauth_token_response",
    Map([("grant_type", "authorization_code"), ("code", code)]),
  )
}

///|
/// `alipay.user.info.share`：用 `auth_token` 取用户信息。
pub async fn alipay_fetch_userinfo(
  config : AlipayConfig,
  access_token : String,
) -> Map[String, String] raise @core.AuthError {
  alipay_gateway_call(
    config,
    "alipay.user.info.share",
    "alipay_user_info_share_response",
    Map([("auth_token", access_token)]),
  )
}

///|
/// 从用户信息归一身份：`uid = user_id`（`Stable`），昵称 / 头像取自响应。
///
/// `fallback_user_id` 为 token 响应里的 `user_id`（userinfo 缺省时兜底）。
pub fn alipay_identity(
  userinfo : Map[String, String],
  fallback_user_id : String,
) -> @core.ExternalIdentity raise @core.AuthError {
  let user_id = match userinfo.get("user_id") {
    Some(s) =>
      if s.length() > 0 {
        s
      } else {
        fallback_user_id
      }
    None => fallback_user_id
  }
  if user_id.length() == 0 {
    raise @core.ParseError("moonauth: alipay response has no user_id")
  }
  {
    provider: "alipay",
    uid: user_id,
    uid_kind: @core.UidKind::Stable,
    email: None,
    email_verified: false,
    display_name: userinfo.get("nick_name"),
    avatar: userinfo.get("avatar"),
    extra: userinfo,
  }
}

// ════════ 内部构件 ════════

///|
/// 公共参数（`timestamp` 现取自注入时钟）。
fn alipay_common_params(
  config : AlipayConfig,
  method : String,
) -> Map[String, String] {
  Map([
    ("app_id", config.app_id),
    ("method", method),
    ("format", "JSON"),
    ("charset", "utf-8"),
    ("sign_type", "RSA2"),
    ("timestamp", alipay_timestamp(config.clock.now_unix())),
    ("version", "1.0"),
  ])
}

///|
/// 把参数编码为 `application/x-www-form-urlencoded` 表单体（POST body 需编码；
/// 注意：**签名串**用原始值，见 `sign.mbt`）。
fn alipay_form_body(params : Map[String, String]) -> String {
  let parts : Array[String] = []
  for k, v in params {
    parts.push(alipay_percent_encode(k) + "=" + alipay_percent_encode(v))
  }
  parts.join("&")
}

///|
/// 解析 JSON 对象；非对象 / 非法 JSON → `ParseError`。
fn alipay_object(body : String, what : String) -> Map[String, Json] raise @core.AuthError {
  let parsed : Json = @json.parse(body) catch {
    _ => raise @core.ParseError("moonauth: alipay " + what + " is not valid JSON")
  }
  match parsed {
    Object(m) => m
    _ => raise @core.ParseError("moonauth: alipay " + what + " is not a JSON object")
  }
}

///|
/// `Json` → 字符串视图（数值保留原始书写形态）。
fn alipay_json_to_string(value : Json) -> String {
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

///|
/// Unix 秒 → `yyyy-MM-dd HH:mm:ss`（UTC；支付宝要求该格式，时区影响极小）。
fn alipay_timestamp(unix : Int64) -> String {
  let days = unix / 86400L
  let rem = unix % 86400L
  let hh = rem / 3600L
  let mm = (rem % 3600L) / 60L
  let ss = rem % 60L
  let (y, mo, d) = alipay_civil_from_days(days)
  y.to_string() +
  "-" +
  alipay_pad2(mo) +
  "-" +
  alipay_pad2(d) +
  " " +
  alipay_pad2(hh) +
  ":" +
  alipay_pad2(mm) +
  ":" +
  alipay_pad2(ss)
}

///|
/// 天数（自 1970-01-01）→ (年, 月, 日)（Howard Hinnant 的 civil_from_days）。
fn alipay_civil_from_days(z0 : Int64) -> (Int64, Int64, Int64) {
  let z = z0 + 719468L
  let era = (if z >= 0L { z } else { z - 146096L }) / 146097L
  let doe = z - era * 146097L
  let yoe = (doe - doe / 1460L + doe / 36524L - doe / 146096L) / 365L
  let y = yoe + era * 400L
  let doy = doe - (365L * yoe + yoe / 4L - yoe / 100L)
  let mp = (5L * doy + 2L) / 153L
  let d = doy - (153L * mp + 2L) / 5L + 1L
  let m = if mp < 10L { mp + 3L } else { mp - 9L }
  let year = if m <= 2L { y + 1L } else { y }
  (year, m, d)
}

///|
/// 两位零填充。
fn alipay_pad2(n : Int64) -> String {
  if n < 10L {
    "0" + n.to_string()
  } else {
    n.to_string()
  }
}

///|
/// `application/x-www-form-urlencoded` 百分号编码（空格 → `%20`）。
fn alipay_percent_encode(s : String) -> String {
  let bytes = @utf8.encode(s)
  let out : Array[Byte] = []
  let hex = @utf8.encode("0123456789ABCDEF")
  for b in bytes {
    let c = b.to_int()
    if alipay_is_unreserved(c) {
      out.push(b)
    } else {
      out.push(b'%')
      out.push(hex[(c >> 4) & 0x0F])
      out.push(hex[c & 0x0F])
    }
  }
  @utf8.decode_lossy(Bytes::from_array(out))
}

///|
/// 是否为 RFC 3986 非保留字符。
fn alipay_is_unreserved(c : Int) -> Bool {
  (c >= 65 && c <= 90) ||
  (c >= 97 && c <= 122) ||
  (c >= 48 && c <= 57) ||
  c == 45 ||
  c == 95 ||
  c == 46 ||
  c == 126
}
