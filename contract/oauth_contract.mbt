//! moonauth / contract —— `OAuthAuthCode` 的参数化契约（SDK-04 / LIB-17）。
//!
//! 契约函数 `run(make)` 把**同一套断言**跑在任意实现上（库自实现 / 官方 SDK 适配层）。
//!
//! 断言集：组 URL 参数与顺序 / PKCE 透传 / 换 token 成功 / provider 业务错误码。
//!
//! 🔴 **调用方契约**：`run` 会对被测实现依次触发 **1 次 `begin`（无 I/O）+ 2 次 `exchange`**，
//! 因此调用方必须把实现接到一个**预置了 2 条响应（先成功、后失败）**的 `HttpClient`：
//! `@contract.MockHttpClient::new(@contract.oauth_token_responses())`。
//! 这是「以固定向量驱动、零真实网络」的取法（LIB-15 ③）。
//!
//! 说明：授权端点随 `AuthorizeRequest.authorization_endpoint` 传入（T02 复核后补齐，
//! 与 `TokenExchangeRequest.token_endpoint` 对称），故契约可同时断言 **绝对端点前缀**
//! 与 **query 部分**的构成——实现无关（不绑定任何实现的内部状态）。

///|
/// 契约与下游测试共用的固定授权端点（Google 的真实端点）。
pub let google_authorization_endpoint : String = "https://accounts.google.com/o/oauth2/v2/auth"

///|
/// 换 token 的固定成功响应。
let oauth_token_ok : @core.HttpResponse = {
  status: 200,
  headers: Map([("Content-Type", "application/json")]),
  body: "{\"access_token\":\"at-123\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"id_token\":\"idt-xyz\",\"refresh_token\":\"rt-1\",\"scope\":\"openid email\"}",
}

///|
/// 换 token 的固定失败响应（provider 业务错误码）。
let oauth_token_error : @core.HttpResponse = {
  status: 400,
  headers: Map([("Content-Type", "application/json")]),
  body: "{\"error\":\"invalid_grant\",\"error_description\":\"authorization code expired\"}",
}

///|
/// `exchange` 将按序消费的固定响应队列（先成功、后失败）。
pub fn oauth_token_responses() -> Array[@core.HttpResponse] {
  [oauth_token_ok, oauth_token_error]
}

///|
/// 固定的授权请求（PKCE S256）。
///
/// `authorization_endpoint` 随请求传入（T02 复核后补齐的字段），故契约可同时断言
/// **绝对端点前缀**与 query 构成，实现无关。
pub fn authorize_request() -> @core.AuthorizeRequest {
  {
    authorization_endpoint: google_authorization_endpoint,
    client_id: "client-1",
    redirect_uri: "https://app.example/cb",
    scopes: ["openid", "email"],
    state: "st-123",
    nonce: Some("nonce-1"),
    code_challenge: Some("CHALLENGE-abc"),
    code_challenge_method: Some("S256"),
    response_mode: None,
    extra: Map([]),
  }
}

///|
/// 固定的换 token 请求。
pub fn token_exchange_request() -> @core.TokenExchangeRequest {
  {
    token_endpoint: "mock://token",
    client_id: "client-1",
    client_secret: Some("secret-1"),
    code: "auth-code-1",
    redirect_uri: "https://app.example/cb",
    code_verifier: Some("vabcdefghijklmnopqrstuvwxyz0123456789-._~abcdef"),
    extra: Map([]),
  }
}

///|
/// 对该 `OAuthAuthCode` 实现跑完整断言集。
///
/// 注意：`begin` / `exchange` 均声明 `raise AuthError`，故这里逐段 `try/catch`，
/// 把「本不该出现的异常」也收集成一条失败用例（而不是让契约函数自己中断）。
pub async fn run_oauth(make : () -> &@core.OAuthAuthCode) -> Array[CaseResult] {
  let subject = make()
  let out : Array[CaseResult] = []
  let begin_name = "oauth: begin assembles the authorization URL (PKCE + state + nonce)"
  let begin_case : CaseResult = try {
    check_begin_query(subject.begin(authorize_request()))
  } catch {
    e => CaseResult::fail(begin_name, "unexpected error: " + @core.auth_error_message(e))
  }
  out.push(begin_case)
  let success_name = "oauth: exchange parses a successful token response"
  let success_case : CaseResult = try {
    check_exchange_success(subject.exchange(token_exchange_request()))
  } catch {
    e => CaseResult::fail(success_name, "unexpected error: " + @core.auth_error_message(e))
  }
  out.push(success_case)
  let error_name = "oauth: exchange maps a provider error code"
  let error_case : CaseResult = try {
    let _ = subject.exchange(token_exchange_request())
    CaseResult::fail(error_name, "expected an error but exchange succeeded")
  } catch {
    e => check_exchange_error(e)
  }
  out.push(error_case)
  out
}

///|
/// 断言授权 URL 同时满足：**绝对端点前缀**正确 + query 含全部必需参数（与顺序无关）。
fn check_begin_query(start : @core.AuthStart) -> CaseResult {
  let name = "oauth: begin assembles the authorization URL (PKCE + state + nonce)"
  let url = start.url
  let checks : Array[(String, Bool)] = [
    ("endpoint prefix", url.has_prefix(google_authorization_endpoint + "?")),
    ("? marker", url.contains("?")),
    ("client_id", url.contains("client_id=client-1")),
    ("redirect_uri", url.contains("redirect_uri=https%3A%2F%2Fapp.example%2Fcb")),
    ("response_type", url.contains("response_type=code")),
    ("scope", url.contains("scope=openid%20email")),
    ("state", url.contains("state=st-123")),
    ("nonce", url.contains("nonce=nonce-1")),
    ("code_challenge", url.contains("code_challenge=CHALLENGE-abc")),
    ("code_challenge_method", url.contains("code_challenge_method=S256")),
  ]
  let missing : Array[String] = []
  for check in checks {
    let (label, ok) = check
    if !ok {
      missing.push(label)
    }
  }
  if missing.length() == 0 && start.state == "st-123" && start.nonce == Some("nonce-1") {
    CaseResult::pass(name)
  } else {
    CaseResult::fail(name, "missing/mismatched: " + missing.join(",") + " | url=" + url)
  }
}

///|
/// 断言换 token 成功：`TokenSet` 各字段解析正确。
fn check_exchange_success(token : @core.TokenSet) -> CaseResult {
  let name = "oauth: exchange parses a successful token response"
  if token.access_token == "at-123" &&
    token.id_token == Some("idt-xyz") &&
    token.refresh_token == Some("rt-1") &&
    token.expires_in == Some(3600) &&
    token.token_type == Some("Bearer") &&
    token.raw.get("scope") == Some("openid email") {
    CaseResult::pass(name)
  } else {
    CaseResult::fail(name, "unexpected TokenSet: access_token=" + token.access_token)
  }
}

///|
/// 断言换 token 失败：provider 业务错误码归一并映射为可 catch 的 `AuthError`。
fn check_exchange_error(err : @core.AuthError) -> CaseResult {
  let name = "oauth: exchange maps a provider error code"
  let code = @core.auth_error_code(err)
  if code == "provider_error" {
    match err {
      ProviderError(code_, message) =>
        if code_ == "invalid_grant" && message.contains("expired") {
          CaseResult::pass(name)
        } else {
          CaseResult::fail(name, "unexpected provider error: " + code_ + " / " + message)
        }
      _ => CaseResult::fail(name, "mapped to provider_error but not ProviderError")
    }
  } else {
    CaseResult::fail(name, "expected provider_error but got " + code)
  }
}
