//! moonauth / provider/alipay —— 黑盒测试（🔴 字典序签名串 / RSA2 验签 / 网关 / 错误）。
//!
//! 全部离线确定性：HTTP 走 `@contract.MockHttpClient`，RSA 用固定向量，
//! 公钥独立构造、与被测实现不共享代码路径。

// ════════ 测试辅助 ════════

///|
/// 十六进制 → 字节。
fn alipay_hex_bytes(s : String) -> Bytes {
  let src = @utf8.encode(s)
  let out : Array[Byte] = []
  let n = src.length()
  let mut i = 0
  while i + 1 < n {
    let hi = alipay_nibble(src[i].to_int())
    let lo = alipay_nibble(src[i + 1].to_int())
    out.push(((hi << 4) | lo).to_byte())
    i = i + 2
  }
  Bytes::from_array(out)
}

///|
/// 单字符十六进制 → 数值。
fn alipay_nibble(v : Int) -> Int {
  if v >= 48 && v <= 57 {
    v - 48
  } else if v >= 97 && v <= 102 {
    v - 97 + 10
  } else if v >= 65 && v <= 70 {
    v - 65 + 10
  } else {
    0
  }
}

///|
/// 固定 RS256（RSA-2048）私钥的 PKCS#1 体（标准 base64）。
let alipay_rsa_pkcs1_b64 : String = "MIIEpAIBAAKCAQEAoT66btCxc2vTvxzdFOrUT5eZkcp1PAGbKYxJREtQG3DOCNHc8l9J1a2kN1BLVeLphMwuWBFKUYANkiKLaMDLpeSlW06n8uEborA+LE7b+q8hL007YN6f850j17/Vq41FuvDYN6xSy8O3WIRzza9znhgTq2MukyzrHOiGijI7L4SusMsOKKQGV2DiZIjNYn8bfhUnxJRyKSFNqBQ/wOZBUo38pHut2ojX4SNDLx7YvrbtCVYE+1sp79THzp8rzaLhIwEf5QLq8IojLVf041eLp28Nlu5qHMPC1lnSO1kQpmPnYju1aPKYNBcGPniX/rzGBUOywLV8UMUHDJZySnjSXwIDAQABAoIBAB/GPzHIITfH902RUAWnstfOXX5Lwadl/6AD24pANxR5ObimNl5ypZecZKBby8Ssduzq2XUUTytZSxNRiFxHpbnWoTkpelITxwDbrxzHG3U+XpE2LG3N4QI+JIqG7IGmUKfifxEVfalWs4IXc8SD/woX34RmAo8RCnHDZoPEG0KlGDROGKKj7/iySxdku9Z4kK5nip7pQIubIXtVFKBBiiFmPzwTh2lH7k52/53luuy2mQmCXavY5xWaB6SN/PQuoPE7Di8w9OoXPKMoTRzfBOSCs1V1vMMVaKtk8F9WP9uGFTGwV/NTJDlzH3/sYkvyR2JIrIMx79UbMU7GkrKev4kCgYEA0bt1iZTln1KypvHshkfUZD7vfa21tWJm+/DR+lBwgnWB2qXgqer7lxaFkGeGf5LJCaeapMAogKmJyKmpeu2OPW0xeyIpy2n1jEq7Bg1Bziia7uQkNJGZJfxo5c/LwHa2JMPDlg1YW0TaDU0aeQMLeAm8XnQ8Or8p3ZNb1d6hj9cCgYEAxND5Kko/7nbI27hjx02kjs8a3E0WbhpWHSMNqaVsQLQG23gNyffUs8PcP0juZGb7BpMm3F3WKPjiFI0bAcc4qizYqiNaIIabbwEKw9t205PKCw0Kh4OSK9icX98x8lcbdGIocUWOzyyufO5lhTtfF+o456c5D1FC3RPbrkSLILkCgYBhkWukjXglHjuuHm2CKnhMClsvhFg8AYMXQXjtke5FQpUeOnzBj2drajbIbuDLCGYt76Kpchtlf3lxuDv3y/uX5+xU9BetYaWxljJbJl+uoIUzDT8qlXFBkqLaBkkrSA6EG+4pKBwqmWU3Ot9N3HTBawYOitRaIARB6AOZAvD2EQKBgQCDgEy6oNmObvdNNyoTpCDq+h2sTCVMc3ROC3m5e7mUkbRzNwefhmMrqRWjgwslMllOz0sLufa5cXE84frFeWK28TfilbRGPynjRQL4Uc5XF0vLjm8WlCY5/YSd2fb5QJIrdNootJzyd5wuBOr31e93fxt+TBCn11ehdv80tL9woQKBgQDGX9ASVzVzflcCGhAK+1qQEdt52rR82JVsqzTEtTJE06CjZIIRpBBFuwNNbO7pJJMqNdieEWr3OcZSIQLNAFd4rCYR/+gRPwXUNf1kuRGs4ggxqjzqi0xWKMJns0t5gH0fjwdGIf4JaIDPknVb+guF0HWI3zFaVebjtJUHsLuzyQ=="

///|
/// 固定 RS256 公钥模数（十六进制）。
let alipay_rsa_n_hex : String = "a13eba6ed0b1736bd3bf1cdd14ead44f979991ca753c019b298c49444b501b70ce08d1dcf25f49d5ada437504b55e2e984cc2e58114a51800d92228b68c0cba5e4a55b4ea7f2e11ba2b03e2c4edbfaaf212f4d3b60de9ff39d23d7bfd5ab8d45baf0d837ac52cbc3b7588473cdaf739e1813ab632e932ceb1ce8868a323b2f84aeb0cb0e28a4065760e26488cd627f1b7e1527c4947229214da8143fc0e641528dfca47badda88d7e123432f1ed8beb6ed095604fb5b29efd4c7ce9f2bcda2e123011fe502eaf08a232d57f4e3578ba76f0d96ee6a1cc3c2d659d23b5910a663e7623bb568f2983417063e7897febcc60543b2c0b57c50c5070c96724a78d25f"

///|
/// 固定 RS256 公钥指数（十六进制，65537）。
let alipay_rsa_e_hex : String = "010001"

///|
/// 固定配置（RSA 私钥内嵌）。
fn alipay_config() -> @alipay.AlipayConfig raise @core.AuthError {
  @alipay.AlipayConfig::new(
    "2021000000000000",
    @core.SigningKey::Der(@oauth.base64_std_decode(alipay_rsa_pkcs1_b64)),
    "https://app.example/cb",
  )
}

// ════════ 签名串：字典序（🔴） ════════

///|
/// 🔴 签名串必须按 **ASCII 升序**（非长度优先）、去 `sign`、去空值。
///
/// 用例故意含 `"aa"`(2) 与 `"b"`(1)：默认 `String::compare` 是长度优先 → 会得到
/// `b` 在 `aa` 前（**错**）；必须得到 `aa` 在 `b` 前。
async test "alipay: signing string is ASCII-ascending, drops sign and empties" {
  let params : Map[String, String] = Map([
    ("b", "2"),
    ("aa", "1"),
    ("z", "9"),
    ("sign_type", "RSA2"),
    ("empty", ""),
    ("sign", "SHOULD-BE-DROPPED"),
  ])
  @debug.assert_eq(
    @alipay.alipay_signing_string(params),
    "aa=1&b=2&sign_type=RSA2&z=9",
  )
}

// ════════ RSA2 签名可验 ════════

///|
/// RSA2 签名（标准 Base64）能被**独立构造**的 RSA 公钥验签通过。
async test "alipay: RSA2 signature verifies with the public key" {
  let config = alipay_config()
  let params : Map[String, String] = Map([
    ("app_id", "2021000000000000"),
    ("method", "alipay.system.oauth.token"),
    ("bb", "2"),
    ("a", "1"),
  ])
  let content = @alipay.alipay_signing_string(params)
  let sig = @oauth.base64_std_decode(@alipay.alipay_sign(config, params))
  let pk = @rsa.PublicKey::new(
    alipay_hex_bytes(alipay_rsa_n_hex)[:],
    alipay_hex_bytes(alipay_rsa_e_hex)[:],
    digest=@rsa.Digest::Sha256,
    scheme=@rsa.Scheme::Pkcs1,
  )
  assert_true(pk.verify(@utf8.encode(content)[:], sig[:]))
}

// ════════ 网关：换 token + 取用户信息 ════════

///|
/// `complete_auth`：网关换 token → 取用户信息 → `uid = user_id`。
async test "alipay: complete_auth yields an identity with user_id as uid" {
  let client : &@core.HttpClient = @contract.MockHttpClient::new([
    {
      status: 200,
      headers: Map([("Content-Type", "application/json")]),
      body: "{\"alipay_system_oauth_token_response\":{\"access_token\":\"AT\",\"user_id\":\"2088123456789\",\"expires_in\":3600}}",
    },
    {
      status: 200,
      headers: Map([("Content-Type", "application/json")]),
      body: "{\"alipay_user_info_share_response\":{\"user_id\":\"2088123456789\",\"nick_name\":\"支付用户\",\"avatar\":\"https://tfs.example/a.png\"}}",
    },
  ])
  let config = alipay_config().with_endpoints(
    "mock://gateway",
    "https://openauth.alipay.com/oauth2/publicAppAuthorize.htm",
    "auth_user",
  ).with_http(client)
  let start = @alipay.begin_auth(config, {
    state: Some("st-1"),
    code_verifier: None,
    nonce: None,
  })
  let cb = @core.CallbackParams::from_query_string("auth_code=AC&state=st-1")
  let identity = @alipay.complete_auth(config, cb, start)
  @debug.assert_eq(identity.provider, "alipay")
  @debug.assert_eq(identity.uid, "2088123456789")
  @debug.assert_eq(identity.display_name, Some("支付用户"))
  @debug.assert_eq(identity.avatar, Some("https://tfs.example/a.png"))
  match identity.uid_kind {
    @core.UidKind::Stable => ()
    @core.UidKind::Degraded => abort("alipay uid must be Stable")
  }
}

// ════════ 错误向量 ════════

///|
/// `error_response` → `provider_error`。
async test "alipay: error_response is normalized to provider_error" {
  let client : &@core.HttpClient = @contract.MockHttpClient::new([
    {
      status: 200,
      headers: Map([("Content-Type", "application/json")]),
      body: "{\"error_response\":{\"code\":\"20001\",\"msg\":\"Invalid Auth Token\",\"sub_code\":\"aop.invalid-auth-token\"}}",
    },
  ])
  let config = alipay_config().with_endpoints(
    "mock://gateway",
    "https://openauth.alipay.com/oauth2/publicAppAuthorize.htm",
    "auth_user",
  ).with_http(client)
  let start = @alipay.begin_auth(config, {
    state: Some("st-1"),
    code_verifier: None,
    nonce: None,
  })
  let cb = @core.CallbackParams::from_query_string("auth_code=BAD&state=st-1")
  let outcome = try {
    let _ = @alipay.complete_auth(config, cb, start)
    "no-error"
  } catch {
    e =>
      // 🔴 `sub_code` 必须进入消息（它是支付宝唯一有用的排障线索，如
      // `isv.invalid-signature`）；`msg` 为空时回退 `sub_msg`。
      @core.auth_error_code(e) + "|" + @core.auth_error_message(e)
  }
  assert_true(outcome.has_prefix("provider_error|"))
  assert_true(outcome.contains("aop.invalid-auth-token"))
  assert_true(outcome.contains("Invalid Auth Token"))
}

///|
/// `state` 不符 → `StateMismatch`。
async test "alipay: state mismatch is rejected" {
  let config = alipay_config()
  let start = @alipay.begin_auth(config, {
    state: Some("st-1"),
    code_verifier: None,
    nonce: None,
  })
  let cb = @core.CallbackParams::from_query_string("auth_code=c&state=WRONG")
  let code = try {
    let _ = @alipay.complete_auth(config, cb, start)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "state_mismatch")
}
