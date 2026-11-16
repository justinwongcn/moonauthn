//! moonauth / core —— 核心值类型（values）。
//!
//! 所有类型只使用 MoonBit 标准类型；临时态（state / code_verifier / nonce / challenge）
//! 一律随返回值交给调用方持有（零状态）。

///|
/// HTTP 方法（仅出站请求所需的两类）。
pub(all) enum HttpMethod {
  Get
  Post
}

///|
/// 出站 HTTP 请求（seam `HttpClient` 的入参）。
///
/// 注：字段名 `method` 由架构契约固定（跨 package 的公开字段名），编译器会给出
/// `reserved_keyword` 提示——属预期，不影响语义。
pub(all) struct HttpRequest {
  method : HttpMethod
  url : String
  headers : Map[String, String]
  /// 已编码的请求体（form / json 字符串），无体时为 `None`。
  body : String?
}

///|
/// 出站 HTTP 响应（seam `HttpClient` 的出参）。
pub(all) struct HttpResponse {
  status : Int
  headers : Map[String, String]
  body : String
}

///|
/// 回调参数（GET query 或 POST form_post body 的解析结果）。
/// 库只提供解析器，不关心数据来源。
pub(all) struct CallbackParams {
  params : Map[String, String]
}

///|
/// 私有：十六进制字符 → 数值；非法返回 -1。
fn hex_value(c : Byte) -> Int {
  let n = c.to_int()
  if n >= 48 && n <= 57 {
    n - 48
  } else if n >= 65 && n <= 70 {
    n - 55
  } else if n >= 97 && n <= 102 {
    n - 87
  } else {
    -1
  }
}

///|
/// 私有：对 `application/x-www-form-urlencoded` 片段做 percent-decode。
/// `+` 解码为空格；`%XX` 解码为单字节；非法 `%` 序列原样保留。
/// 结果按 UTF-8 解释，解码失败时原样返回输入。
fn percent_decode(raw : String) -> String {
  let src = @utf8.encode(raw)
  let buf = Buffer()
  let len = src.length()
  let mut i = 0
  while i < len {
    let c = src[i]
    if c == b'+' {
      buf.write_byte(b' ')
      i = i + 1
    } else if c == b'%' && i + 2 < len {
      let hi = hex_value(src[i + 1])
      let lo = hex_value(src[i + 2])
      if hi >= 0 && lo >= 0 {
        buf.write_byte((hi * 16 + lo).to_byte())
        i = i + 3
      } else {
        buf.write_byte(c)
        i = i + 1
      }
    } else {
      buf.write_byte(c)
      i = i + 1
    }
  }
  @utf8.decode(buf.to_bytes()) catch {
    _ => raw
  }
}

///|
/// 私有：解析 `k=v&k2=v2` 形态（query string 与 form body 同构）。
/// 无 `=` 的片段视为「键且值为空串」；空片段被忽略；后出现的同名键覆盖先出现的。
fn parse_urlencoded(s : String) -> Map[String, String] {
  let out : Map[String, String] = Map([])
  for seg in s.split("&") {
    if seg.length() > 0 {
      match seg.split_once("=") {
        Some((k, v)) => out[percent_decode(k.to_owned())] = percent_decode(v.to_owned())
        None => out[percent_decode(seg.to_owned())] = ""
      }
    }
  }
  out
}

///|
/// 从 URL query string 构造回调参数。
pub fn CallbackParams::from_query_string(query : String) -> CallbackParams {
  { params: parse_urlencoded(query) }
}

///|
/// 从 POST form body（`application/x-www-form-urlencoded`）构造回调参数。
pub fn CallbackParams::from_form_body(body : String) -> CallbackParams {
  { params: parse_urlencoded(body) }
}

///|
/// 从已解析的键值对构造回调参数（调用方自带解析结果时使用）。
pub fn CallbackParams::from_pairs(pairs : Map[String, String]) -> CallbackParams {
  { params: pairs }
}

///|
/// 读取单个回调参数；不存在时返回 `None`。
pub fn CallbackParams::get(self : CallbackParams, key : String) -> String? {
  self.params.get(key)
}

///|
/// 回调以 query / form 参数直接携带平台错误时的统一读取。
///
/// 覆盖 RFC 6749 §4.1.2.1 授权错误响应三参数：`error` / `error_description` /
/// `error_uri`（后者仅在出现时并入消息）。Google / GitHub 在 query、Apple 在
/// `form_post` body、飞书在 query（`error=access_denied`）均以此形态回传「用户拒绝
/// 授权」等失败结果。
///
/// `error` 非空 → `Some(ProviderError(error, 描述[; uri]))`；否则 `None`。
///
/// 🔴 各 provider 必须在 **`state` 校验通过后、读取授权码之前** 调用本方法：
/// 用户拒绝授权必须归一为 `provider_error`（可定位的平台语义），
/// 而不是误报为 `missing_param`（与真实丢参无法区分）。
pub fn CallbackParams::provider_error(self : CallbackParams) -> AuthError? {
  let code = match self.params.get("error") {
    Some(c) => if c.length() > 0 { c } else { return None }
    None => return None
  }
  let mut msg = match self.params.get("error_description") {
    Some(d) => d
    None => ""
  }
  match self.params.get("error_uri") {
    Some(u) =>
      if u.length() > 0 {
        msg = if msg.length() > 0 { msg + "; " + u } else { u }
      }
    None => ()
  }
  Some(ProviderError(code, msg))
}

///|
/// `begin_*` 的返回值。临时态随返回值交给调用方持有（零状态）。
pub(all) struct AuthStart {
  /// 供浏览器跳转的授权 URL。
  url : String
  /// 本次流程的 `state`（调用方自行存储并回传）。
  state : String
  /// PKCE `code_verifier`（仅使用 PKCE 的 provider）。
  code_verifier : String?
  /// OIDC `nonce`。
  nonce : String?
}

///|
/// 调用方自带的临时态（`begin_*_with` 形态使用）。
/// 三字段皆可缺省，缺省者由库经 `RandomSource` 生成。
pub(all) struct SuppliedSecrets {
  state : String?
  code_verifier : String?
  nonce : String?
}

///|
/// `OAuthAuthCode.begin` 的输入：组授权 URL 所需的全部信息。
///
/// 🔴 `authorization_endpoint` 作为**请求字段**（而非 seam 实现的构造参数）：
/// provider 调用的是**注入进来**的 `&OAuthAuthCode`，而**构造函数不在 trait 里**——
/// 若端点只能经构造函数传入，provider 就无法统一配置任意注入的实现，「可替换性」
/// （SDK-01）会被削弱。端点随请求传入后，seam 实现变成纯机械的 URL 组装，对注入方
/// 零隐含前提。这与 `TokenExchangeRequest.token_endpoint` 完全对齐。
pub(all) struct AuthorizeRequest {
  /// 授权端点（绝对 URL）——seam 实现据此组 `AuthStart.url`。
  authorization_endpoint : String
  client_id : String
  redirect_uri : String
  scopes : Array[String]
  state : String
  nonce : String?
  code_challenge : String?
  code_challenge_method : String?
  /// 如 Apple 的 "form_post"。
  response_mode : String?
  /// 平台特殊项（如微信的 `#wechat_redirect`）。
  extra : Map[String, String]
}

///|
/// `OAuthAuthCode.exchange` 的输入：换 token 所需的全部信息。
pub(all) struct TokenExchangeRequest {
  token_endpoint : String
  client_id : String
  client_secret : String?
  code : String
  redirect_uri : String
  code_verifier : String?
  /// 平台特殊项（如支付宝的 method / 签名）。
  extra : Map[String, String]
}

///|
/// 换 token 的结果。
pub(all) struct TokenSet {
  access_token : String
  id_token : String?
  refresh_token : String?
  expires_in : Int?
  token_type : String?
  scope : String?
  /// 平台附加的扁平字段（字符串视图）。
  raw : Map[String, String]
}

///|
/// 验 `id_token` 的期望值（OIDC 语义）。
pub(all) struct IdTokenExpectations {
  issuers : Array[String]
  audiences : Array[String]
  nonce : String?
  jwks_uri : String?
  leeway_seconds : Int?
  /// 可接受的 `id_token` 签名算法白名单（JOSE `alg`，如 `["RS256"]`）。
  ///
  /// 🔴 RFC 8725 §3.1：`alg` 来自**未验签**的 token 头，绝不能无条件信任——本库以
  /// 「调用方钉死白名单」收敛。非空时严格比对（不命中即 `UnsupportedAlg`）；
  /// 空数组 = 接受实现支持的任一算法（RS/ES 族，全部绑定 JWKS 公钥，无 `none`/HMAC 面）。
  /// Provider 默认实现恒填平台实际算法（如 Google/Apple 均为 `["RS256"]`）。
  algorithms : Array[String]
}

///|
/// 验签后的 `id_token` claims（已归一为库自有类型）。
pub(all) struct IdTokenClaims {
  subject : String
  issuer : String
  audience : Array[String]
  expires_at : Int64
  issued_at : Int64
  nonce : String?
  email : String?
  email_verified : Bool?
  /// 其余声明的字符串视图（无 `@json.Json` 泄漏）。
  raw : Map[String, String]
}

///|
/// 签名算法（Apple client secret 用 ES256，OIDC id_token 用 RS256）。
pub(all) enum SignAlg {
  ES256
  RS256
}

///|
/// 签名密钥：PEM 文本或 DER 字节。
pub(all) enum SigningKey {
  Pem(String)
  Der(Bytes)
}

///|
/// WebAuthn 注册（attestation）校验输入。
pub(all) struct RegistrationInput {
  client_data_json : Bytes
  attestation_object : Bytes
  expected_challenge : String
  expected_origin : String
  rp_id : String
}

///|
/// WebAuthn 登录（assertion）校验输入。
pub(all) struct AssertionInput {
  client_data_json : Bytes
  authenticator_data : Bytes
  signature : Bytes
  /// COSE 公钥。
  credential_public_key : Bytes
  expected_challenge : String
  expected_origin : String
  rp_id : String
  stored_sign_count : Int
}

///|
/// WebAuthn 注册校验结果。
pub(all) struct VerifiedRegistration {
  credential_id : Bytes
  /// COSE 公钥。
  public_key : Bytes
  sign_count : Int
  aaguid : String?
  user_verified : Bool
}

///|
/// WebAuthn 登录校验结果。
pub(all) struct VerifiedAssertion {
  sign_count : Int
  user_verified : Bool
}

///|
/// TOTP 选项（RFC 6238 / RFC 4226）。
pub(all) struct TotpOptions {
  digits : Int
  period : Int
  /// "SHA1" | "SHA256" | "SHA512"
  algorithm : String
}
