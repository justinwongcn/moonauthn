//! moonauth / oauth —— 默认 `OAuthAuthCode` 实现：`StandardOAuthAuthCode`。
//!
//! 覆盖「标准 OAuth2 / OIDC Authorization Code + PKCE」的通用语义，
//! 供 Google / Apple / X 等标准 provider 复用（微信 / QQ / 支付宝各自子包内实现自有协议）。
//!
//! ## 关于授权端点
//! 授权端点由 `AuthorizeRequest.authorization_endpoint` **随请求传入**（与
//! `TokenExchangeRequest.token_endpoint` 对称）。因此本实现是**无 provider 配置的
//! 纯机械组装**：给什么请求就组什么 URL。注入方（`provider/*`）可统一配置任意
//! `&OAuthAuthCode` 实现，无需知道「怎么给实现喂端点」。
//! （「端点作构造参数」方案会因「构造函数不在 trait 里」而破坏 SDK-01 可替换性，
//! 已在 T02 复核中否决。）
//!
//! ## 换 token
//! `exchange` 以 `application/x-www-form-urlencoded` POST `token_endpoint`，把响应体
//! 按 JSON（优先）或 form-encoded（回退）解析为 `TokenSet`；非 2xx 时把 provider 的
//! 业务错误码（`error` / `error_description`）归一为 `ProviderError`，否则 `HttpStatus`。

///|
/// 默认 `OAuthAuthCode` 实现：标准 OAuth2 Authorization Code（组 URL + 换 token）。
///
/// 只持有出站 HTTP 一个 seam——不含任何 provider 配置（授权端点随请求传入）。
pub struct StandardOAuthAuthCode {
  http : &@core.HttpClient
}

///|
/// 构造默认实现（无参）。
///
/// 授权端点**不再**由构造传入，而是随 `AuthorizeRequest.authorization_endpoint`
/// 逐次提供；HTTP 默认取 `core.AsyncHttpClient`（可在装配处 `with_http` 覆盖）。
pub fn StandardOAuthAuthCode::new() -> StandardOAuthAuthCode {
  let http : &@core.HttpClient = @core.AsyncHttpClient::new()
  { http, }
}

///|
/// 覆盖出站 HTTP 实现（返回新实例，不改原实例）。
pub fn StandardOAuthAuthCode::with_http(
  self : StandardOAuthAuthCode,
  http : &@core.HttpClient,
) -> StandardOAuthAuthCode {
  let _ = self
  { http, }
}

///|
/// 实现 seam：组授权 URL（纯拼接，无 I/O；但仍按 seam 约定声明为 async）。
///
/// 参数按 RFC 6749 §4.1.1 的常用顺序输出；`extra` 按**键字典序**追加以保证确定性
/// （微信那种「严格顺序」不适用本实现——它由 `provider/wechat` 自有实现承担）。
/// `AuthStart.code_verifier` 恒为 `None`：请求里只有 `code_challenge`，
/// `code_verifier` 由调用方持有。
pub impl @core.OAuthAuthCode for StandardOAuthAuthCode with fn begin(self, req) {
  let _ = self
  let params : Array[String] = []
  params.push("client_id=" + percent_encode(req.client_id))
  params.push("redirect_uri=" + percent_encode(req.redirect_uri))
  params.push("response_type=code")
  if req.scopes.length() > 0 {
    params.push("scope=" + percent_encode(req.scopes.join(" ")))
  }
  params.push("state=" + percent_encode(req.state))
  match req.nonce {
    Some(v) => params.push("nonce=" + percent_encode(v))
    None => ()
  }
  match req.code_challenge {
    Some(v) => params.push("code_challenge=" + percent_encode(v))
    None => ()
  }
  match req.code_challenge_method {
    Some(v) => params.push("code_challenge_method=" + percent_encode(v))
    None => ()
  }
  match req.response_mode {
    Some(v) => params.push("response_mode=" + percent_encode(v))
    None => ()
  }
  for k in @core.sorted_keys(req.extra) {
    params.push(percent_encode(k) + "=" + percent_encode(req.extra[k]))
  }
  {
    url: req.authorization_endpoint + "?" + params.join("&"),
    state: req.state,
    code_verifier: None,
    nonce: req.nonce,
  }
}

///|
/// 实现 seam：用授权码换 token（POST `token_endpoint`）。
pub impl @core.OAuthAuthCode for StandardOAuthAuthCode with fn exchange(self, req) {
  let form : Array[String] = []
  form.push("grant_type=authorization_code")
  form.push("code=" + percent_encode(req.code))
  form.push("redirect_uri=" + percent_encode(req.redirect_uri))
  form.push("client_id=" + percent_encode(req.client_id))
  match req.client_secret {
    Some(v) => form.push("client_secret=" + percent_encode(v))
    None => ()
  }
  match req.code_verifier {
    Some(v) => form.push("code_verifier=" + percent_encode(v))
    None => ()
  }
  for k in @core.sorted_keys(req.extra) {
    form.push(percent_encode(k) + "=" + percent_encode(req.extra[k]))
  }
  let resp = self.http.send({
    method: @core.HttpMethod::Post,
    url: req.token_endpoint,
    headers: Map([
      ("Content-Type", "application/x-www-form-urlencoded"),
      ("Accept", "application/json"),
    ]),
    body: Some(form.join("&")),
  })
  if resp.status < 200 || resp.status >= 300 {
    raise map_token_error(resp)
  }
  parse_token_set(resp.body)
}

///|
/// 显式把 seam 方法提升为常规方法，避免隐式提升的弃用告警。
pub extend StandardOAuthAuthCode with @core.OAuthAuthCode::{begin, exchange}

// ════════ URL / 表单编码 ════════

///|
/// `application/x-www-form-urlencoded` 片段的百分号编码（RFC 3986 §2.3 非保留集之外全编码）。
/// 空格编码为 `%20`（不是 `+`）——两者对服务端等价，`%20` 更通用。
fn percent_encode(s : String) -> String {
  let bytes = @utf8.encode(s)
  let out : Array[Byte] = []
  let hex = @utf8.encode("0123456789ABCDEF")
  for b in bytes {
    let c = b.to_int()
    if is_unreserved(c) {
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
/// 是否为 RFC 3986 非保留字符：`A-Z a-z 0-9 - _ . ~`。
fn is_unreserved(c : Int) -> Bool {
  (c >= 65 && c <= 90) ||
  (c >= 97 && c <= 122) ||
  (c >= 48 && c <= 57) ||
  c == 45 ||
  c == 95 ||
  c == 46 ||
  c == 126
}

// 注：键的**字典序升序**由 `@core.sorted_keys` 提供（见 `core/lexical.mbt` 顶部：
// 为什么不能用默认 `String::compare` / `Array[String]::sort()`）。本文件的两处调用
//（`begin` / `exchange` 的 `extra`）均跨包引用 `@core.sorted_keys`。

// ════════ 响应解析 ════════

///|
/// 把非 2xx 的 token 响应归一为 `AuthError`：
/// 体里能解出 provider 业务码（`error`）→ `ProviderError`；否则 → `HttpStatus`。
fn map_token_error(resp : @core.HttpResponse) -> @core.AuthError {
  let fields = token_fields(resp.body)
  match fields.get("error") {
    Some(code) => {
      let msg = match fields.get("error_description") {
        Some(d) => d
        None => resp.body
      }
      @core.ProviderError(code, msg)
    }
    None => @core.HttpStatus(resp.status, resp.body)
  }
}

///|
/// 解析成功响应体为 `TokenSet`。`access_token` 缺失即 `ParseError`。
fn parse_token_set(body : String) -> @core.TokenSet raise @core.AuthError {
  let fields = token_fields(body)
  let access = match fields.get("access_token") {
    Some(v) => v
    None => raise @core.ParseError("moonauth: token response missing access_token")
  }
  {
    access_token: access,
    id_token: fields.get("id_token"),
    refresh_token: fields.get("refresh_token"),
    expires_in: parse_int_opt(fields.get("expires_in")),
    token_type: fields.get("token_type"),
    scope: fields.get("scope"),
    raw: fields,
  }
}

///|
/// 把响应体归一为 `Map[String, String]`：优先 JSON 对象，回退 form-encoded。
fn token_fields(body : String) -> Map[String, String] {
  let from_json : Map[String, String]? = try {
    match @json.parse(body) {
      Object(members) => Some(json_object_to_map(members))
      _ => None
    }
  } catch {
    _ => None
  }
  match from_json {
    Some(m) => m
    None => @core.CallbackParams::from_form_body(body).params
  }
}

///|
/// JSON 对象 → 字符串扁平映射（值取字符串视图；数组 / 对象回退为紧凑 JSON 文本）。
fn json_object_to_map(members : Map[String, Json]) -> Map[String, String] {
  let out : Map[String, String] = Map([])
  for k, v in members {
    out[k] = json_to_string(v)
  }
  out
}

///|
/// `Json` → 字符串视图（不含引号；数值优先保留原始书写形态）。
fn json_to_string(value : Json) -> String {
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
/// 字符串 → `Int?`：容忍前导空白，遇非数字即停；无任何数字则 `None`。
fn parse_int_opt(value : String?) -> Int? {
  match value {
    None => None
    Some(s) => {
      let bytes = @utf8.encode(s)
      let n = bytes.length()
      let mut i = 0
      while i < n && (bytes[i] == b' ' || bytes[i] == b'\t') {
        i = i + 1
      }
      let mut acc : Int64 = 0L
      let mut digits = 0
      let mut done = false
      while i < n && !done {
        let c = bytes[i].to_int()
        if c >= 48 && c <= 57 {
          acc = acc * 10L + (c - 48).to_int64()
          digits = digits + 1
          i = i + 1
        } else {
          done = true
        }
      }
      if digits == 0 {
        None
      } else {
        Some(acc.to_int())
      }
    }
  }
}
