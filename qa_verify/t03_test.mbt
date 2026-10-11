//! moonauth / qa_verify —— **T03 六 provider 的独立对抗性验证**（QA：严过关）。
//!
//! 目标：不复用工程师的断言，自构造期望值 / 独立构造公私钥，逐平台按协议语义对抗性验证。
//! 全部离线确定性（HTTP 走 `@contract.MockHttpClient`，时钟走 `@contract.FixedClock`）。

// ════════ 通用辅助 ════════

///|
/// 单字符十六进制 → 数值。
fn t3_nib(v : Int) -> Int {
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
/// 十六进制 → 字节。
fn t3_hex_bytes(s : String) -> Bytes {
  let src = @utf8.encode(s)
  let out : Array[Byte] = []
  let n = src.length()
  let mut i = 0
  while i + 1 < n {
    out.push(((t3_nib(src[i].to_int()) << 4) | t3_nib(src[i + 1].to_int())).to_byte())
    i = i + 2
  }
  Bytes::from_array(out)
}

///|
/// 固定字节序列的 `RandomSource`（确定性；用于判别「值确实来自注入 seam」）。
///
/// 无状态地循环填充到请求长度——这样只要实现**只向 seam 取一次**，
/// 结果即可用请求内容精确预测。
struct T3Random {
  data : Bytes
}

///|
impl @core.RandomSource for T3Random with fn bytes(self, n) {
  let out : Array[Byte] = []
  let len = self.data.length()
  if len == 0 {
    return Bytes::from_array(out)
  }
  let mut i = 0
  while i < n {
    out.push(self.data[i % len])
    i = i + 1
  }
  Bytes::from_array(out)
}

///|
/// 已知的 16 字节序列（0x00…0x0f）——用于预测 state / challenge 编码。
fn t3_known() -> Bytes {
  t3_hex_bytes("000102030405060708090a0b0c0d0e0f")
}

///|
/// `t3_known()` 的十六进制串（hex 型 state 的期望值）。
let t3_known_hex : String = "000102030405060708090a0b0c0d0e0f"
///|
/// `t3_known()` 的 base64url 串（base64url 型 state 的期望值）。
let t3_known_b64url : String = "AAECAwQFBgcICQoLDA0ODw"

///|
/// 断言一个 `uid_kind` 是 `Stable`。
fn t3_is_stable(k : @core.UidKind) -> Bool {
  match k {
    @core.UidKind::Stable => true
    @core.UidKind::Degraded => false
  }
}

// ════════ §2.1 支付宝签名串（🔴 判别性用例） ════════

///|
/// 🔴 **长度不齐的 key 混排**：`a`(1) / `aa`(2) / `b`(1) / `ccc`(3) / `z`(1)。
///
/// 默认 `String::compare` 先比长度 → 会得到 `a,b,z,aa,ccc`（错）；字典序必须是
/// `a,aa,b,ccc,z`。**期望串由 QA 手工按 ASCII 升序推导**（未复用工程师断言）。
async test "t03 §2.1 alipay signing string: ASCII-ascending, NOT length-first" {
  let params : Map[String, String] = Map([
    ("z", "last"),
    ("aa", "2"),
    ("b", "1"),
    ("ccc", "3"),
    ("sign", "SHOULD-BE-DROPPED"),
    ("empty", ""),
    ("a", "0"),
  ])
  @debug.assert_eq(
    @alipay.alipay_signing_string(params),
    "a=0&aa=2&b=1&ccc=3&z=last",
  )
}

///|
/// 值的**原样（不 URL 编码）**：含 `空格 / = / &` 的值必须原样参与签名串。
async test "t03 §2.1 alipay signing string: raw values are not URL-encoded" {
  let params : Map[String, String] = Map([("raw", "a b=c&d"), ("k", "1")])
  @debug.assert_eq(
    @alipay.alipay_signing_string(params),
    "k=1&raw=a b=c&d",
  )
}

///|
/// `sign_type` **参与**排序（不被剔除）；只有 `sign` 与空值被剔除。
async test "t03 §2.1 alipay signing string: sign_type participates, sign dropped" {
  let params : Map[String, String] = Map([
    ("sign_type", "RSA2"),
    ("app_id", "2021000000000000"),
    ("sign", "X"),
  ])
  @debug.assert_eq(
    @alipay.alipay_signing_string(params),
    "app_id=2021000000000000&sign_type=RSA2",
  )
}

// ════════ §2.1 RSA2：用**独立构造**的公钥验签 ════════

///|
/// 固定 RS256（RSA-2048）**私钥**的 PKCS#1 体（标准 base64）——公开测试向量。
let t3_alipay_pkcs1_b64 : String = "MIIEpAIBAAKCAQEAoT66btCxc2vTvxzdFOrUT5eZkcp1PAGbKYxJREtQG3DOCNHc8l9J1a2kN1BLVeLphMwuWBFKUYANkiKLaMDLpeSlW06n8uEborA+LE7b+q8hL007YN6f850j17/Vq41FuvDYN6xSy8O3WIRzza9znhgTq2MukyzrHOiGijI7L4SusMsOKKQGV2DiZIjNYn8bfhUnxJRyKSFNqBQ/wOZBUo38pHut2ojX4SNDLx7YvrbtCVYE+1sp79THzp8rzaLhIwEf5QLq8IojLVf041eLp28Nlu5qHMPC1lnSO1kQpmPnYju1aPKYNBcGPniX/rzGBUOywLV8UMUHDJZySnjSXwIDAQABAoIBAB/GPzHIITfH902RUAWnstfOXX5Lwadl/6AD24pANxR5ObimNl5ypZecZKBby8Ssduzq2XUUTytZSxNRiFxHpbnWoTkpelITxwDbrxzHG3U+XpE2LG3N4QI+JIqG7IGmUKfifxEVfalWs4IXc8SD/woX34RmAo8RCnHDZoPEG0KlGDROGKKj7/iySxdku9Z4kK5nip7pQIubIXtVFKBBiiFmPzwTh2lH7k52/53luuy2mQmCXavY5xWaB6SN/PQuoPE7Di8w9OoXPKMoTRzfBOSCs1V1vMMVaKtk8F9WP9uGFTGwV/NTJDlzH3/sYkvyR2JIrIMx79UbMU7GkrKev4kCgYEA0bt1iZTln1KypvHshkfUZD7vfa21tWJm+/DR+lBwgnWB2qXgqer7lxaFkGeGf5LJCaeapMAogKmJyKmpeu2OPW0xeyIpy2n1jEq7Bg1Bziia7uQkNJGZJfxo5c/LwHa2JMPDlg1YW0TaDU0aeQMLeAm8XnQ8Or8p3ZNb1d6hj9cCgYEAxND5Kko/7nbI27hjx02kjs8a3E0WbhpWHSMNqaVsQLQG23gNyffUs8PcP0juZGb7BpMm3F3WKPjiFI0bAcc4qizYqiNaIIabbwEKw9t205PKCw0Kh4OSK9icX98x8lcbdGIocUWOzyyufO5lhTtfF+o456c5D1FC3RPbrkSLILkCgYBhkWukjXglHjuuHm2CKnhMClsvhFg8AYMXQXjtke5FQpUeOnzBj2drajbIbuDLCGYt76Kpchtlf3lxuDv3y/uX5+xU9BetYaWxljJbJl+uoIUzDT8qlXFBkqLaBkkrSA6EG+4pKBwqmWU3Ot9N3HTBawYOitRaIARB6AOZAvD2EQKBgQCDgEy6oNmObvdNNyoTpCDq+h2sTCVMc3ROC3m5e7mUkbRzNwefhmMrqRWjgwslMllOz0sLufa5cXE84frFeWK28TfilbRGPynjRQL4Uc5XF0vLjm8WlCY5/YSd2fb5QJIrdNootJzyd5wuBOr31e93fxt+TBCn11ehdv80tL9woQKBgQDGX9ASVzVzflcCGhAK+1qQEdt52rR82JVsqzTEtTJE06CjZIIRpBBFuwNNbO7pJJMqNdieEWr3OcZSIQLNAFd4rCYR/+gRPwXUNf1kuRGs4ggxqjzqi0xWKMJns0t5gH0fjwdGIf4JaIDPknVb+guF0HWI3zFaVebjtJUHsLuzyQ=="

///|
/// 读取 DER 中 `pos` 处的长度字节，返回 `(内容长度, 内容起始)`（只支持短/长两型）。
fn t3_der_len(buf : Bytes, pos : Int) -> (Int, Int) {
  let first = buf[pos].to_int()
  if (first & 0x80) == 0 {
    (first, pos + 1)
  } else {
    let cnt = first & 0x7F
    let mut v = 0
    let mut k = 0
    let mut p = pos + 1
    while k < cnt {
      v = (v << 8) | buf[p].to_int()
      p = p + 1
      k = k + 1
    }
    (v, p)
  }
}

///|
/// 读 `pos` 处的 INTEGER（含前导零剥离），返回 `(内容, 下一 TLV 起始)`。
fn t3_der_int(buf : Bytes, pos : Int) -> (Bytes, Int) {
  let (len, cs) = t3_der_len(buf, pos + 1)
  let raw = buf[cs : cs + len].to_owned()
  let mut s = 0
  while s + 1 < raw.length() && raw[s] == b'\x00' {
    s = s + 1
  }
  (raw[s:].to_owned(), cs + len)
}

///|
/// 从 PKCS#1 `RSAPrivateKey` DER **自行解析**出 `(n, e)`（不采信任何硬编码模数）。
fn t3_rsa_n_e(der : Bytes) -> (Bytes, Bytes) {
  // 外层 SEQUENCE：tag 在 [0]，长度从 [1] 起
  let (_, cs) = t3_der_len(der, 1)
  let (_, p1) = t3_der_int(der, cs) // version
  let (n, p2) = t3_der_int(der, p1) // modulus
  let (e, _) = t3_der_int(der, p2) // publicExponent
  (n, e)
}

///|
/// 🔴 RSA2：签名用**从 DER 自行解析**出的公钥验签通过；篡改消息 / 签名必须失败。
async test "t03 §2.1 alipay RSA2 verifies under an independently-derived public key" {
  let der = @oauth.base64_std_decode(t3_alipay_pkcs1_b64)
  let (n, e) = t3_rsa_n_e(der)
  let pk : @rsa.PublicKey = @rsa.PublicKey::new(
    n[:],
    e[:],
    digest=@rsa.Digest::Sha256,
    scheme=@rsa.Scheme::Pkcs1,
  ) catch {
    _ => abort("t03: derived RSA public key rejected")
  }
  let config = @alipay.AlipayConfig::new(
    "2021000000000000",
    @core.SigningKey::Der(der),
    "https://app.example/cb",
  )
  let params : Map[String, String] = Map([
    ("method", "alipay.system.oauth.token"),
    ("ccc", "3"),
    ("aa", "2"),
    ("b", "1"),
    ("a", "0"),
  ])
  let content = @alipay.alipay_signing_string(params)
  // 期望串（QA 独立推导）
  @debug.assert_eq(content, "a=0&aa=2&b=1&ccc=3&method=alipay.system.oauth.token")
  let sig = @oauth.base64_std_decode(@alipay.alipay_sign(config, params))
  // 正例：独立公钥验签通过
  assert_true(pk.verify(@utf8.encode(content)[:], sig[:]))
  // 反例 1：篡改消息 → 必须失败
  assert_false(pk.verify(@utf8.encode(content + "x")[:], sig[:]))
  // 反例 2：翻转签名首字节 → 必须失败
  let bad = sig.to_array()
  bad[0] = (bad[0].to_int() ^ 0x01).to_byte()
  assert_false(pk.verify(@utf8.encode(content)[:], Bytes::from_array(bad)[:]))
}

// ════════ §2.2 微信：严格 URL 顺序 + unionid 降级 + 200+errcode ════════

///|
/// 🔴 授权 URL 参数顺序必须与官方**逐字节一致**（期望串由 QA 独立推导）。
async test "t03 §2.2 wechat authorize URL: strict order + percent-encoded redirect" {
  let config = @wechat.WeChatConfig::new(
    "wx_TEST_appid",
    "SECRET",
    "https://app.example/cb?x=1&y=2",
  )
  let start = @wechat.begin_auth(config, {
    state: Some("ST-STATE"),
    code_verifier: None,
    nonce: None,
  })
  @debug.assert_eq(
    start.url,
    "https://open.weixin.qq.com/connect/oauth2/authorize?appid=wx_TEST_appid&redirect_uri=https%3A%2F%2Fapp.example%2Fcb%3Fx%3D1%26y%3D2&response_type=code&scope=snsapi_login&state=ST-STATE#wechat_redirect",
  )
}

///|
/// 无 `unionid`（缺省）→ 降级 `openid` + `Degraded`。
async test "t03 §2.2 wechat identity: unionid present -> Stable; absent -> Degraded" {
  let a = @wechat.wechat_identity("{\"openid\":\"O1\",\"unionid\":\"U1\"}", "FB")
  @debug.assert_eq(a.uid, "U1")
  assert_true(t3_is_stable(a.uid_kind))
  let b = @wechat.wechat_identity("{\"openid\":\"O2\"}", "FB")
  @debug.assert_eq(b.uid, "O2")
  assert_false(t3_is_stable(b.uid_kind))
  // 空 unionid 视为无（不能误判为 Stable）
  let c = @wechat.wechat_identity("{\"openid\":\"O3\",\"unionid\":\"\"}", "FB")
  @debug.assert_eq(c.uid, "O3")
  assert_false(t3_is_stable(c.uid_kind))
  // openid 缺省 → fallback
  let d = @wechat.wechat_identity("{\"nickname\":\"n\"}", "FB")
  @debug.assert_eq(d.uid, "FB")
}

///|
/// 🔴 业务错误常为 **HTTP 200 + `errcode`**：必须依 `errcode` 判失败，而非 HTTP 状态码。
async test "t03 §2.2 wechat: HTTP 200 + errcode is a provider_error" {
  let client : &@core.HttpClient = @contract.MockHttpClient::new([
    {
      status: 200,
      headers: Map([("Content-Type", "application/json")]),
      body: "{\"errcode\":40029,\"errmsg\":\"invalid code\"}",
    },
  ])
  let config = @wechat.WeChatConfig::new(
    "wx",
    "SEC",
    "https://app.example/cb",
  ).with_http(client)
  let start = @wechat.begin_auth(config, {
    state: Some("st"),
    code_verifier: None,
    nonce: None,
  })
  let cb = @core.CallbackParams::from_query_string("code=BAD&state=st")
  let code = try {
    let _ = @wechat.complete_auth(config, cb, start)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "provider_error")
}

///|
/// `wechat_parse_token` 命中 `errcode` 即 `provider_error`（不看 HTTP 状态）。
async test "t03 §2.2 wechat_parse_token: errcode -> provider_error" {
  let code = try {
    let _ = @wechat.wechat_parse_token("{\"errcode\":40163,\"errmsg\":\"code been used\"}")
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "provider_error")
}

// ════════ §2.3 QQ：JSONP 剥壳畸形输入 + form 回退 ════════

///|
/// JSONP 剥壳：标准形态（固定 callback 名 + 尾 `;`）。
async test "t03 §2.3 qq jsonp: standard form unwraps to inner JSON" {
  @debug.assert_eq(
    @qq.qq_unwrap_jsonp("callback( {\"openid\":\"x\"} );"),
    " {\"openid\":\"x\"} ",
  )
}

///|
/// JSONP 剥壳：**无 callback 包裹** 与 **尾部无 `;`** 两种畸形 → 仍能得到可解析内容。
async test "t03 §2.3 qq jsonp: no-wrapper and missing-semicolon still parse" {
  // 无包裹：无 `(` / `)` → 原样返回
  @debug.assert_eq(@qq.qq_unwrap_jsonp("{\"openid\":\"x\"}"), "{\"openid\":\"x\"}")
  // 尾部无 `;`
  @debug.assert_eq(
    @qq.qq_unwrap_jsonp("callback( {\"openid\":\"x\"} )"),
    " {\"openid\":\"x\"} ",
  )
}

///|
/// 🔴 内含 `)` 的畸形输入：剥壳只能取到第一个 `)`，得到非法 JSON →
/// 必须**报错**（而非静默返回空串）。此处确认**无静默吞错**。
async test "t03 §2.3 qq jsonp: ')' inside body -> explicit parse_error (no silent swallow)" {
  let body = "callback( {\"a\":\"b)c\"} );"
  let code = try {
    let _ = @qq.qq_parse_openid(body)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "parse_error")
}

///|
/// 空 body / 空白壳 → 明确报错，不得静默返回空串。
async test "t03 §2.3 qq parse_openid: empty body -> parse_error" {
  let code = try {
    let _ = @qq.qq_parse_openid("")
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "parse_error")
}

///|
/// JSONP **错误码分支** `callback( {"error":N,...} );` → `provider_error`。
async test "t03 §2.3 qq jsonp: error branch -> provider_error" {
  let body = "callback( {\"error\":100016,\"error_description\":\"access token check failed\"} );"
  let code = try {
    let _ = @qq.qq_parse_openid(body)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "provider_error")
}

///|
/// token 端点：JSON 路径（`fmt=json`）与 **form-encoded 回退**路径两条都实测。
async test "t03 §2.3 qq token: JSON path and form-encoded fallback both work" {
  @debug.assert_eq(@qq.qq_parse_token("{\"access_token\":\"ATJ\"}"), "ATJ")
  @debug.assert_eq(@qq.qq_parse_token("access_token=ATF&expires_in=7776000"), "ATF")
  // 两条路径的错误分支都归一为 provider_error
  let jc = try {
    let _ = @qq.qq_parse_token("{\"error\":100016,\"error_description\":\"bad\"}")
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(jc, "provider_error")
  let fc = try {
    let _ = @qq.qq_parse_token("error=100016&error_description=bad")
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(fc, "provider_error")
}

///|
/// 合法 JSON 但缺 `access_token` → `parse_error`（不静默）。
async test "t03 §2.3 qq token: JSON object without access_token -> parse_error" {
  let code = try {
    let _ = @qq.qq_parse_token("{\"foo\":1}")
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "parse_error")
}

// ════════ §2.4 Apple：form_post / private_email / ES256 client secret ════════

///|
/// `form_post` 回调体（urlencoded POST body）→ `CallbackParams`。
async test "t03 §2.4 apple: form_post body parses into params" {
  let body = "code=AC1&id_token=abc.def.ghi&state=ST1&user=%7B%22name%22%3A%7B%22firstName%22%3A%22Ada%22%7D%7D"
  let cb = @apple.apple_callback(body)
  @debug.assert_eq(cb.get("code"), Some("AC1"))
  @debug.assert_eq(cb.get("id_token"), Some("abc.def.ghi"))
  @debug.assert_eq(cb.get("state"), Some("ST1"))
}

///|
/// `user` 姓名解析：first+last、仅 first、仅 last、空、非法 JSON。
async test "t03 §2.4 apple user name: full / partial / malformed" {
  @debug.assert_eq(
    @apple.apple_user_name("{\"name\":{\"firstName\":\"Ada\",\"lastName\":\"Lovelace\"}}"),
    Some("Ada Lovelace"),
  )
  @debug.assert_eq(
    @apple.apple_user_name("{\"name\":{\"firstName\":\"Ada\"}}"),
    Some("Ada"),
  )
  @debug.assert_eq(
    @apple.apple_user_name("{\"name\":{\"lastName\":\"Lovelace\"}}"),
    Some("Lovelace"),
  )
  @debug.assert_eq(@apple.apple_user_name("{\"name\":{}}"), None)
  @debug.assert_eq(@apple.apple_user_name("not json"), None)
}

///|
/// 🔴 `is_private_email`：`"true"` → true；缺省 → **false**（不得误判 true）；`"false"`/其它 → false。
async test "t03 §2.4 apple is_private_email: default false, only 'true' is true" {
  let base : @core.IdTokenClaims = {
    subject: "u",
    issuer: "i",
    audience: ["a"],
    expires_at: 0L,
    issued_at: 0L,
    nonce: None,
    email: None,
    email_verified: None,
    raw: Map([]),
  }
  @debug.assert_eq(
    @apple.apple_is_private_email({ ..base, raw: Map([("is_private_email", "true")]) }),
    true,
  )
  @debug.assert_eq(@apple.apple_is_private_email(base), false)
  @debug.assert_eq(
    @apple.apple_is_private_email({ ..base, raw: Map([("is_private_email", "false")]) }),
    false,
  )
  @debug.assert_eq(
    @apple.apple_is_private_email({ ..base, raw: Map([("is_private_email", "1")]) }),
    false,
  )
}

///|
/// QA 自选的 P-256 私钥标量（与工程师向量**不同**），用于独立验签 Apple client secret。
let t3_apple_ec_scalar_hex : String = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"

///|
/// 🔴 ES256 client secret：3 段 JWS、签名字节 **64**（raw r‖s）、
/// 用**从标量独立导出**的 P-256 公钥验签通过；`iss/sub/aud` 正确；`exp` 现签。
async test "t03 §2.4 apple ES256 client secret is a verifiable JWS with 64-byte sig" {
  let scalar = t3_hex_bytes(t3_apple_ec_scalar_hex)
  let config = @apple.AppleConfig::new(
    "com.example.qa",
    "https://app.example/cb",
    "TEAMQA",
    "KEYQA",
    @core.SigningKey::Der(scalar),
  ).with_clock(@contract.FixedClock::new(1700000000L))
  let secret = @apple.apple_client_secret(config)
  let parts = secret.split(".").to_array()
  @debug.assert_eq(parts.length(), 3)
  let header = parts[0].to_owned()
  let payload = parts[1].to_owned()
  let sig = @oauth.base64url_decode(parts[2].to_owned())
  // raw r‖s 必须恰为 64 字节
  @debug.assert_eq(sig.length(), 64)
  // 独立导出公钥并验签
  let sk : @ecdsa.PrivateKey = @ecdsa.PrivateKey::new(
    scalar[:],
    curve=@ecdsa.Curve::P256,
  ) catch {
    _ => abort("t03: invalid P-256 scalar")
  }
  let pk = sk.public()
  assert_true(pk.verify(@utf8.encode(header + "." + payload)[:], sig[:]))
  // claims
  let payload_json = @utf8.decode_lossy(@oauth.base64url_decode(payload))
  assert_true(payload_json.contains("\"iss\":\"TEAMQA\""))
  assert_true(payload_json.contains("\"sub\":\"com.example.qa\""))
  assert_true(payload_json.contains("\"aud\":\"https://appleid.apple.com\""))
  let header_json = @utf8.decode_lossy(@oauth.base64url_decode(header))
  assert_true(header_json.contains("\"alg\":\"ES256\""))
  assert_true(header_json.contains("\"kid\":\"KEYQA\""))
  // exp 现签：iat = 1700000000，exp = iat + 15777000
  assert_true(payload_json.contains("\"iat\":1700000000"))
  assert_true(payload_json.contains("\"exp\":1715777000"))
}

///|
/// `exp` 随注入时钟变化（非写死）：+1000 秒 → `exp` 同步 +1000。
async test "t03 §2.4 apple client secret exp tracks the injected clock" {
  let scalar = t3_hex_bytes(t3_apple_ec_scalar_hex)
  let c1 = @apple.AppleConfig::new(
    "c",
    "https://app.example/cb",
    "t",
    "k",
    @core.SigningKey::Der(scalar),
  ).with_clock(@contract.FixedClock::new(1700000000L))
  let c2 = @apple.AppleConfig::new(
    "c",
    "https://app.example/cb",
    "t",
    "k",
    @core.SigningKey::Der(scalar),
  ).with_clock(@contract.FixedClock::new(1700001000L))
  let p1 = @utf8.decode_lossy(@oauth.base64url_decode(@apple.apple_client_secret(c1).split(".").to_array()[1].to_owned()))
  let p2 = @utf8.decode_lossy(@oauth.base64url_decode(@apple.apple_client_secret(c2).split(".").to_array()[1].to_owned()))
  assert_true(p1.contains("\"exp\":1715777000"))
  assert_true(p2.contains("\"exp\":1715778000"))
}

// ════════ §2.5 Google ════════

///|
/// 固定 token 响应（含固定 id_token）。
fn t3_google_token_ok() -> @core.HttpResponse {
  let body = "{\"access_token\":\"at-1\",\"token_type\":\"Bearer\",\"id_token\":\"" +
    @contract.fixed_token_ok +
    "\"}"
  { status: 200, headers: Map([("Content-Type", "application/json")]), body }
}

///|
/// 接好固定向量 + Mock 的 Google 配置（每次调用独立队列）。
fn t3_google_config() -> @google.GoogleConfig {
  let client : &@core.HttpClient = @contract.MockHttpClient::new([
    t3_google_token_ok(),
    @contract.jwks_response(),
  ])
  let clock : &@core.Clock = @contract.FixedClock::new(@contract.fixed_now_unix())
  @google.GoogleConfig::new("client-1", "https://app.example/cb").with_endpoints(
    @contract.google_authorization_endpoint,
    "mock://token",
    "mock://jwks",
    "https://issuer.example",
  ).with_http(client).with_clock(clock)
}

///|
/// Google：固定 JWKS + id_token → 确定性身份（`uid = sub`，Stable，邮箱已验）。
async test "t03 §2.5 google: fixed vectors yield uid=sub and verified email" {
  let config = t3_google_config()
  let start = @google.begin_auth(config, {
    state: Some("st-1"),
    code_verifier: Some("verifier-1"),
    nonce: Some("nonce-1"),
  })
  let cb = @core.CallbackParams::from_query_string("code=ac&state=st-1")
  let identity = @google.complete_auth(config, cb, start)
  @debug.assert_eq(identity.provider, "google")
  @debug.assert_eq(identity.uid, "user-1")
  @debug.assert_eq(identity.email, Some("alice@example.com"))
  @debug.assert_eq(identity.email_verified, true)
  assert_true(t3_is_stable(identity.uid_kind))
}

///|
/// Google 错误向量：错 state / 缺 code / nonce 不符 / token 错误 各自命中正确 `AuthError`。
async test "t03 §2.5 google error vectors map to the right AuthError" {
  // 错 state
  let c1 = t3_google_config()
  let s1 = @google.begin_auth(c1, {
    state: Some("st"),
    code_verifier: Some("v"),
    nonce: Some("n"),
  })
  let e1 = try {
    let _ = @google.complete_auth(c1, @core.CallbackParams::from_query_string("code=c&state=WRONG"), s1)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(e1, "state_mismatch")
  // 缺 code
  let c2 = t3_google_config()
  let e2 = try {
    let s2 = @google.begin_auth(c2, {
      state: Some("st"),
      code_verifier: Some("v"),
      nonce: Some("n"),
    })
    let _ = @google.complete_auth(c2, @core.CallbackParams::from_query_string("state=st"), s2)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(e2, "missing_param")
  // nonce 不符
  let c3 = t3_google_config()
  let s3 = @google.begin_auth(c3, {
    state: Some("st"),
    code_verifier: Some("v"),
    nonce: Some("WRONG"),
  })
  let e3 = try {
    let _ = @google.complete_auth(c3, @core.CallbackParams::from_query_string("code=c&state=st"), s3)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(e3, "nonce_mismatch")
  // token 端点 400
  let client : &@core.HttpClient = @contract.MockHttpClient::new([
    {
      status: 400,
      headers: Map([("Content-Type", "application/json")]),
      body: "{\"error\":\"invalid_grant\",\"error_description\":\"expired\"}",
    },
  ])
  let c4 = @google.GoogleConfig::new("client-1", "https://app.example/cb").with_endpoints(
    @contract.google_authorization_endpoint,
    "mock://token",
    "mock://jwks",
    "https://issuer.example",
  ).with_http(client)
  let s4 = @google.begin_auth(c4, {
    state: Some("st"),
    code_verifier: Some("v"),
    nonce: Some("n"),
  })
  let e4 = try {
    let _ = @google.complete_auth(c4, @core.CallbackParams::from_query_string("code=c&state=st"), s4)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(e4, "provider_error")
}

///|
/// `google_identity`：`email_verified` 缺省 → false（不误判）。
async test "t03 §2.5 google_identity: email_verified defaults to false" {
  let claims : @core.IdTokenClaims = {
    subject: "s",
    issuer: "i",
    audience: ["a"],
    expires_at: 0L,
    issued_at: 0L,
    nonce: None,
    email: Some("e@x"),
    email_verified: None,
    raw: Map([]),
  }
  let id = @google.google_identity(claims)
  @debug.assert_eq(id.uid, "s")
  @debug.assert_eq(id.email_verified, false)
}

// ════════ §2.5 X：PKCE + 数值 user id ════════

///|
/// 🔴 X：`code_challenge_method=S256` 且 challenge == `s256(verifier)`。
async test "t03 §2.5 x: PKCE S256 challenge matches the verifier" {
  let config = @x.XConfig::new("client-x", "https://app.example/cb")
  let start = @x.begin_auth(config, {
    state: Some("st-x"),
    code_verifier: Some("verifier-x"),
    nonce: None,
  })
  let expected = @oauth.s256_challenge("verifier-x")
  assert_true(start.url.contains("code_challenge_method=S256"))
  assert_true(start.url.contains("code_challenge=" + expected))
  assert_true(start.url.contains("state=st-x"))
  @debug.assert_eq(start.code_verifier, Some("verifier-x"))
}

///|
/// 🔴 X：主键取 `data.id`（数值字符串），而非可变的 `username`。
async test "t03 §2.5 x_identity: uid is data.id, not username" {
  let id = @x.x_identity(
    "{\"data\":{\"id\":\"2244994945\",\"name\":\"X Dev\",\"username\":\"XDevelopers\"}}",
  )
  @debug.assert_eq(id.uid, "2244994945")
  @debug.assert_eq(id.display_name, Some("X Dev"))
  assert_true(t3_is_stable(id.uid_kind))
  // 缺 data.id → parse_error
  let code = try {
    let _ = @x.x_identity("{\"data\":{\"username\":\"X\"}}")
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "parse_error")
}

// ════════ §2.6 LIB-20 隔离（结构层已在 shell 侧核对；此处补一个编译期隔离证据） ════════

///|
/// 六个 provider 的包级 facade 各自独立可用（能同时 import 而不冲突）——
/// 与「子包互不依赖」一致；真正的交叉 import 审计见报告中的 grep/`moon tree` 证据。
async test "t03 §2.6 six providers assemble their own authorization URLs" {
  let secrets : @core.SuppliedSecrets = {
    state: Some("st"),
    code_verifier: Some("v"),
    nonce: Some("n"),
  }
  let g = @google.begin_auth(@google.GoogleConfig::new("c", "https://app.example/cb"), secrets)
  assert_true(
    g.url.has_prefix("https://accounts.google.com/o/oauth2/v2/auth?"),
  )
  let a = @apple.begin_auth(
    @apple.AppleConfig::new(
      "c",
      "https://app.example/cb",
      "t",
      "k",
      @core.SigningKey::Der(t3_hex_bytes(t3_apple_ec_scalar_hex)),
    ),
    secrets,
  )
  assert_true(a.url.has_prefix("https://appleid.apple.com/auth/authorize?"))
  let xc = @x.begin_auth(@x.XConfig::new("c", "https://app.example/cb"), secrets)
  assert_true(xc.url.has_prefix("https://twitter.com/i/oauth2/authorize?"))
  let w = @wechat.begin_auth(
    @wechat.WeChatConfig::new("c", "s", "https://app.example/cb"),
    secrets,
  )
  assert_true(w.url.has_prefix("https://open.weixin.qq.com/connect/oauth2/authorize?"))
  let q = @qq.begin_auth(
    @qq.QQConfig::new("c", "s", "https://app.example/cb"),
    secrets,
  )
  assert_true(q.url.has_prefix("https://graph.qq.com/oauth2.0/authorize?"))
  let ap = @alipay.begin_auth(
    @alipay.AlipayConfig::new(
      "c",
      @core.SigningKey::Der(t3_hex_bytes("00")),
      "https://app.example/cb",
    ),
    secrets,
  )
  assert_true(
    ap.url.has_prefix("https://openauth.alipay.com/oauth2/publicAppAuthorize.htm?"),
  )
}

// ════════ §2.7 纯度 / 注入 seam（🔴 判别性：值确实来自注入的随机源） ════════

///|
/// 🔴 判别性用例：注入「已知字节」随机源 → state 必须**精确等于**这些字节的编码。
///
/// 若实现绕过 seam 直读 `@env.rand`（OS CSPRNG），state 绝不可能等于已知值。
async test "t03 §2.7 wechat state comes from the injected RandomSource" {
  let config = @wechat.WeChatConfig::new(
    "wx",
    "s",
    "https://app.example/cb",
  ).with_random(T3Random::{ data: t3_known() })
  let start = @wechat.begin_auth(config, {
    state: None,
    code_verifier: None,
    nonce: None,
  })
  @debug.assert_eq(start.state, t3_known_hex)
  // 同注入 → 重复调用结果一致（确定性）
  let again = @wechat.begin_auth(config, {
    state: None,
    code_verifier: None,
    nonce: None,
  })
  @debug.assert_eq(again.state, t3_known_hex)
}

///|
/// 🔴 同上，QQ / 支付宝：state 为 hex 编码，必须精确等于注入字节。
async test "t03 §2.7 qq & alipay state come from the injected RandomSource" {
  let q = @qq.QQConfig::new("c", "s", "https://app.example/cb").with_random(
    T3Random::{ data: t3_known() },
  )
  let qs = @qq.begin_auth(q, { state: None, code_verifier: None, nonce: None })
  @debug.assert_eq(qs.state, t3_known_hex)
  let a = @alipay.AlipayConfig::new(
    "c",
    @core.SigningKey::Der(t3_hex_bytes("00")),
    "https://app.example/cb",
  ).with_random(T3Random::{ data: t3_known() })
  let as_ = @alipay.begin_auth(a, { state: None, code_verifier: None, nonce: None })
  @debug.assert_eq(as_.state, t3_known_hex)
}

///|
/// 🔴 同上，Google / Apple / X：state 为 base64url 编码（且等于 `base64url(注入字节)`）。
async test "t03 §2.7 google/apple/x state come from the injected RandomSource" {
  let g = @google.GoogleConfig::new("c", "https://app.example/cb").with_random(
    T3Random::{ data: t3_known() },
  )
  let gs = @google.begin_auth(g, {
    state: None,
    code_verifier: Some("v"),
    nonce: Some("n"),
  })
  @debug.assert_eq(gs.state, t3_known_b64url)
  @debug.assert_eq(gs.state, @oauth.base64url_encode(t3_known()))
  let xc = @x.XConfig::new("c", "https://app.example/cb").with_random(
    T3Random::{ data: t3_known() },
  )
  let xs = @x.begin_auth(xc, { state: None, code_verifier: Some("v"), nonce: None })
  @debug.assert_eq(xs.state, t3_known_b64url)
  let ac = @apple.AppleConfig::new(
    "c",
    "https://app.example/cb",
    "t",
    "k",
    @core.SigningKey::Der(t3_hex_bytes(t3_apple_ec_scalar_hex)),
  ).with_random(T3Random::{ data: t3_known() })
  let as_ = @apple.begin_auth(ac, {
    state: None,
    code_verifier: Some("v"),
    nonce: Some("n"),
  })
  @debug.assert_eq(as_.state, t3_known_b64url)
}
