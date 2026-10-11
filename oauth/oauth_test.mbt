//! moonauth / oauth —— 黑盒测试：PKCE / base64 / 默认签名器 / 标准授权码实现。
//!
//! 🔴 本文件是**黑盒测试**（`*_test.mbt`）：被 implicit 导入的被测包须以 `@oauth.`
//! 限定引用。全部用例**离线、确定性**：
//! - 网络一律走 `@contract.MockHttpClient`（预置响应队列），**零真实网络**；
//! - 随机源经本地 `FixedRandomSource` 注入，输出可重放；
//! - 签名往返使用**固定密钥向量**（P-256 / RSA-2048），公钥坐标独立生成并硬编码，
//!   与被测实现不共享代码路径。
//!
//! 用例一律写成 `async test`：签名器 / 换 token 涉及 `raise AuthError`，
//! 且 `OAuthAuthCode.begin/exchange` 为 async seam，需 async 上下文。

// ════════ 测试辅助 ════════

///|
/// 十六进制字符串 → 字节。
fn hex_bytes(s : String) -> Bytes {
  let src = @utf8.encode(s)
  let out : Array[Byte] = []
  let n = src.length()
  let mut i = 0
  while i + 1 < n {
    let hi = hex_nibble(src[i].to_int())
    let lo = hex_nibble(src[i + 1].to_int())
    out.push(((hi << 4) | lo).to_byte())
    i = i + 2
  }
  Bytes::from_array(out)
}

///|
/// 单个十六进制字符 → 数值（非法记为 0，仅在已知合法输入上使用）。
fn hex_nibble(v : Int) -> Int {
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
/// 标准 base64 → 字节（失败给空串，仅用于内嵌固定密钥向量）。
fn decode_key_b64(s : String) -> Bytes {
  @oauth.base64_std_decode(s) catch {
    _ => Bytes::from_array([])
  }
}

///|
/// 返回固定字节序列的 `RandomSource`（确定性重放；按需循环填充到 `n` 字节）。
struct FixedRandomSource {
  data : Bytes
}

///|
impl @core.RandomSource for FixedRandomSource with fn bytes(self, n) {
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

// ════════ 固定密钥向量 ════════
// 由 openssl 生成、经独立 DER 解析提取；公钥坐标独立于 mooncrypt。

///|
/// 固定 ES256（P-256）私钥的 PKCS#8 体（标准 base64，单行）。
let ec_pkcs8_b64 : String = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgvSKtUkdmv0mKyk2xfXGkESDzY8zwKuKnZpeqR7eqy2ChRANCAAThLmz16+M1FddH0P0uGOabWkSGPV7RFcej53/oNIg5pmPGlRYQPn+Vje2hv6UXNvMqtj2YAhN6VxA7mGY9F9Pd"

///|
/// 固定 ES256 私钥的裸 32 字节标量（十六进制）。
let ec_scalar_hex : String = "bd22ad524766bf498aca4db17d71a41120f363ccf02ae2a76697aa47b7aacb60"

///|
/// 固定 ES256 公钥的 X 坐标（十六进制）。
let ec_x_hex : String = "e12e6cf5ebe33515d747d0fd2e18e69b5a44863d5ed115c7a3e77fe8348839a6"

///|
/// 固定 ES256 公钥的 Y 坐标（十六进制）。
let ec_y_hex : String = "63c69516103e7f958deda1bfa51736f32ab63d9802137a57103b98663d17d3dd"

///|
/// 固定 RS256（RSA-2048）私钥的 PKCS#1 体（标准 base64，单行）。
let rsa_pkcs1_b64 : String = "MIIEpAIBAAKCAQEAoT66btCxc2vTvxzdFOrUT5eZkcp1PAGbKYxJREtQG3DOCNHc8l9J1a2kN1BLVeLphMwuWBFKUYANkiKLaMDLpeSlW06n8uEborA+LE7b+q8hL007YN6f850j17/Vq41FuvDYN6xSy8O3WIRzza9znhgTq2MukyzrHOiGijI7L4SusMsOKKQGV2DiZIjNYn8bfhUnxJRyKSFNqBQ/wOZBUo38pHut2ojX4SNDLx7YvrbtCVYE+1sp79THzp8rzaLhIwEf5QLq8IojLVf041eLp28Nlu5qHMPC1lnSO1kQpmPnYju1aPKYNBcGPniX/rzGBUOywLV8UMUHDJZySnjSXwIDAQABAoIBAB/GPzHIITfH902RUAWnstfOXX5Lwadl/6AD24pANxR5ObimNl5ypZecZKBby8Ssduzq2XUUTytZSxNRiFxHpbnWoTkpelITxwDbrxzHG3U+XpE2LG3N4QI+JIqG7IGmUKfifxEVfalWs4IXc8SD/woX34RmAo8RCnHDZoPEG0KlGDROGKKj7/iySxdku9Z4kK5nip7pQIubIXtVFKBBiiFmPzwTh2lH7k52/53luuy2mQmCXavY5xWaB6SN/PQuoPE7Di8w9OoXPKMoTRzfBOSCs1V1vMMVaKtk8F9WP9uGFTGwV/NTJDlzH3/sYkvyR2JIrIMx79UbMU7GkrKev4kCgYEA0bt1iZTln1KypvHshkfUZD7vfa21tWJm+/DR+lBwgnWB2qXgqer7lxaFkGeGf5LJCaeapMAogKmJyKmpeu2OPW0xeyIpy2n1jEq7Bg1Bziia7uQkNJGZJfxo5c/LwHa2JMPDlg1YW0TaDU0aeQMLeAm8XnQ8Or8p3ZNb1d6hj9cCgYEAxND5Kko/7nbI27hjx02kjs8a3E0WbhpWHSMNqaVsQLQG23gNyffUs8PcP0juZGb7BpMm3F3WKPjiFI0bAcc4qizYqiNaIIabbwEKw9t205PKCw0Kh4OSK9icX98x8lcbdGIocUWOzyyufO5lhTtfF+o456c5D1FC3RPbrkSLILkCgYBhkWukjXglHjuuHm2CKnhMClsvhFg8AYMXQXjtke5FQpUeOnzBj2drajbIbuDLCGYt76Kpchtlf3lxuDv3y/uX5+xU9BetYaWxljJbJl+uoIUzDT8qlXFBkqLaBkkrSA6EG+4pKBwqmWU3Ot9N3HTBawYOitRaIARB6AOZAvD2EQKBgQCDgEy6oNmObvdNNyoTpCDq+h2sTCVMc3ROC3m5e7mUkbRzNwefhmMrqRWjgwslMllOz0sLufa5cXE84frFeWK28TfilbRGPynjRQL4Uc5XF0vLjm8WlCY5/YSd2fb5QJIrdNootJzyd5wuBOr31e93fxt+TBCn11ehdv80tL9woQKBgQDGX9ASVzVzflcCGhAK+1qQEdt52rR82JVsqzTEtTJE06CjZIIRpBBFuwNNbO7pJJMqNdieEWr3OcZSIQLNAFd4rCYR/+gRPwXUNf1kuRGs4ggxqjzqi0xWKMJns0t5gH0fjwdGIf4JaIDPknVb+guF0HWI3zFaVebjtJUHsLuzyQ=="

///|
/// 固定 RS256 公钥模数（十六进制）。
let rsa_n_hex : String = "a13eba6ed0b1736bd3bf1cdd14ead44f979991ca753c019b298c49444b501b70ce08d1dcf25f49d5ada437504b55e2e984cc2e58114a51800d92228b68c0cba5e4a55b4ea7f2e11ba2b03e2c4edbfaaf212f4d3b60de9ff39d23d7bfd5ab8d45baf0d837ac52cbc3b7588473cdaf739e1813ab632e932ceb1ce8868a323b2f84aeb0cb0e28a4065760e26488cd627f1b7e1527c4947229214da8143fc0e641528dfca47badda88d7e123432f1ed8beb6ed095604fb5b29efd4c7ce9f2bcda2e123011fe502eaf08a232d57f4e3578ba76f0d96ee6a1cc3c2d659d23b5910a663e7623bb568f2983417063e7897febcc60543b2c0b57c50c5070c96724a78d25f"

///|
/// 固定 RS256 公钥指数（十六进制，65537）。
let rsa_e_hex : String = "010001"

///|
/// 固定 ES256 私钥的 PEM 文本。
fn ec_pem() -> String {
  "-----BEGIN PRIVATE KEY-----\n" +
  ec_pkcs8_b64 +
  "\n-----END PRIVATE KEY-----\n"
}

///|
/// 固定 RS256 私钥的 PEM 文本。
fn rsa_pem() -> String {
  "-----BEGIN RSA PRIVATE KEY-----\n" +
  rsa_pkcs1_b64 +
  "\n-----END RSA PRIVATE KEY-----\n"
}

// ════════ PKCE（RFC 7636）════════

///|
/// RFC 7636 附录 B 的**官方样例**：43 字符 verifier → 43 字符 S256 挑战。
async test "pkce: RFC 7636 appendix B vector" {
  let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
  @debug.assert_eq(@oauth.s256_challenge(verifier), challenge)
  assert_true(@oauth.verify_s256(verifier, challenge))
  assert_false(@oauth.verify_s256(verifier + "x", challenge))
  assert_false(@oauth.verify_s256(verifier, "wrong-challenge"))
}

///|
/// `S256` 挑战恒为 43 字符（32 字节 SHA-256 的 base64url，无填充）。
async test "pkce: S256 challenge is 43 chars and depends on the verifier" {
  let a = @oauth.s256_challenge("verifier-a")
  let b = @oauth.s256_challenge("verifier-b")
  @debug.assert_eq(a.length(), 43)
  assert_true(a != b)
  assert_true(@oauth.verify_s256("verifier-a", a))
  assert_false(@oauth.verify_s256("verifier-b", a))
}

///|
/// `generate_code_verifier` 只经注入的 `RandomSource`：相同随机源 → 相同 verifier。
async test "pkce: code verifier is deterministic from the injected random source" {
  let data = hex_bytes(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  let random = FixedRandomSource::{ data: data }
  let src : &@core.RandomSource = random
  @debug.assert_eq(
    @oauth.generate_code_verifier(src),
    @oauth.base64url_encode(data),
  )
  // 默认 32 字节 → 43 字符，落在 RFC 允许的 43~128 区间
  @debug.assert_eq(@oauth.generate_code_verifier(src).length(), 43)
  // 自定义 byte_len
  @debug.assert_eq(@oauth.generate_code_verifier(src, byte_len=16).length(), 22)
}

// ════════ base64 ════════

///|
/// base64url 已知向量 + 填充容忍 + 往返。
async test "base64url: known vectors, padding tolerance and roundtrip" {
  @debug.assert_eq(@oauth.base64url_encode(b"hello"), "aGVsbG8")
  @debug.assert_eq(@oauth.base64url_encode(b"f"), "Zg")
  @debug.assert_eq(@oauth.base64url_encode(b"\xff\xff\xff"), "____")
  @debug.assert_eq(@oauth.base64url_decode("aGVsbG8"), b"hello")
  @debug.assert_eq(@oauth.base64url_decode("aGVsbG8="), b"hello")
  let raw = hex_bytes("00ff10abcdef00")
  @debug.assert_eq(@oauth.base64url_decode(@oauth.base64url_encode(raw)), raw)
}

///|
/// 标准 base64：RFC 4648 §10 的官方测试向量（**带 `=` 填充**，输出恒为 4 的倍数）。
///
/// 对照：`base64url_encode` **无填充**（见上方用例 `base64url_encode(b"f") == "Zg"`），
/// 二者不可混用——标准 base64 供 PEM / 支付宝 `sign`，base64url 供 JOSE。
async test "base64 std: RFC 4648 test vectors (padded)" {
  @debug.assert_eq(@oauth.base64_std_encode(b""), "")
  @debug.assert_eq(@oauth.base64_std_encode(b"f"), "Zg==")
  @debug.assert_eq(@oauth.base64_std_encode(b"fo"), "Zm8=")
  @debug.assert_eq(@oauth.base64_std_encode(b"foo"), "Zm9v")
  @debug.assert_eq(@oauth.base64_std_encode(b"foob"), "Zm9vYg==")
  @debug.assert_eq(@oauth.base64_std_encode(b"fooba"), "Zm9vYmE=")
  @debug.assert_eq(@oauth.base64_std_encode(b"foobar"), "Zm9vYmFy")
  // 填充长度契约：输出长度恒为 4 的倍数（0/1/2 三种余数各覆盖）
  @debug.assert_eq(@oauth.base64_std_encode(b"").length(), 0)
  @debug.assert_eq(@oauth.base64_std_encode(b"f").length(), 4)
  @debug.assert_eq(@oauth.base64_std_encode(b"fo").length(), 4)
  @debug.assert_eq(@oauth.base64_std_encode(b"foo").length(), 4)
  @debug.assert_eq(@oauth.base64_std_decode("Zm9vYmFy"), b"foobar")
  // 解码容忍填充：标准变体的 `+` / `/`（带或缺 `=` 均等价）
  @debug.assert_eq(
    @oauth.base64_std_decode("+/=="),
    @oauth.base64_std_decode("+/"),
  )
}

///|
/// 🔴 `base64_std_encode` 的**真实消费者是 PEM 路径**：把 PKCS#8 DER 经 encode 包成 PEM，
/// `MooncryptSecretSigner` 仍能加载并签出可被独立公钥验签的 64 字节 ES256 签名。
/// 这条锁定「标准 base64 必须带填充」——严格 PEM 解析器不接受无填充 body。
async test "base64 std: padded PEM output round-trips through the signer" {
  let der = decode_key_b64(ec_pkcs8_b64)
  let pem =
    "-----BEGIN PRIVATE KEY-----\n" +
    @oauth.base64_std_encode(der) +
    "\n-----END PRIVATE KEY-----\n"
  let signer = @oauth.MooncryptSecretSigner::new()
  let msg = @utf8.encode("moonauth-pem-roundtrip")
  let sig = signer.sign(@core.SignAlg::ES256, @core.SigningKey::Pem(pem), msg)
  @debug.assert_eq(sig.length(), 64)
  let pk = @ecdsa.PublicKey::of_xy(
    hex_bytes(ec_x_hex)[:],
    hex_bytes(ec_y_hex)[:],
    curve=@ecdsa.Curve::P256,
  )
  assert_true(pk.verify(msg[:], sig[:]))
}

///|
/// 字母表外字符 → `ParseError`（绝不静默丢弃）。
async test "base64url: invalid character raises parse_error" {
  let code = try {
    let _ = @oauth.base64url_decode("!!!!")
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "parse_error")
}

// ════════ 字典序原语 ════════
// 说明：`lexicographic_compare` / `sort_lexicographic` / `sorted_keys` 已按**依赖方向**
// 迁至 `core/lexical.mbt`（跨领域文本工具，任何包都能直接取用，不必依赖 oauth 功能包）。
// 其行为（含「默认 String::compare 是长度优先」的工具链快照）锁在 `core/lexical_wbtest.mbt`。
// `oauth` 经 `@core.sorted_keys` 使用它——见上方 `StandardOAuthAuthCode` 的 `extra` 排序用例。

// ════════ MooncryptSecretSigner ════════

///|
/// ES256：裸 32 字节标量 → 签名恒为 64 字节（`r ∥ s`，JOSE 线格式，**非 DER**），
/// 且能被独立构造的 P-256 公钥验签通过。
async test "signer: ES256 round-trips a raw P-256 scalar (64-byte r||s)" {
  let signer = @oauth.MooncryptSecretSigner::new()
  let msg = @utf8.encode("moonauth-es256")
  let sig = signer.sign(
    @core.SignAlg::ES256,
    @core.SigningKey::Der(hex_bytes(ec_scalar_hex)),
    msg,
  )
  // DER 编码的 ES256 签名约 70~72 字节；64 字节即证明是 raw `r ∥ s`。
  @debug.assert_eq(sig.length(), 64)
  let pk = @ecdsa.PublicKey::of_xy(
    hex_bytes(ec_x_hex)[:],
    hex_bytes(ec_y_hex)[:],
    curve=@ecdsa.Curve::P256,
  )
  assert_true(pk.verify(msg[:], sig[:]))
}

///|
/// ES256：PKCS#8 PEM 形态同样可加载并签出可验签的 64 字节签名。
async test "signer: ES256 accepts a PKCS#8 PEM key" {
  let signer = @oauth.MooncryptSecretSigner::new()
  let msg = @utf8.encode("moonauth-es256-pem")
  let sig = signer.sign(
    @core.SignAlg::ES256,
    @core.SigningKey::Pem(ec_pem()),
    msg,
  )
  @debug.assert_eq(sig.length(), 64)
  let pk = @ecdsa.PublicKey::of_xy(
    hex_bytes(ec_x_hex)[:],
    hex_bytes(ec_y_hex)[:],
    curve=@ecdsa.Curve::P256,
  )
  assert_true(pk.verify(msg[:], sig[:]))
}

///|
/// RS256：PKCS#1 DER → 2048 位签名（256 字节），独立构造的公钥验签通过。
async test "signer: RS256 round-trips a PKCS#1 key" {
  let signer = @oauth.MooncryptSecretSigner::new()
  let msg = @utf8.encode("moonauth-rs256")
  let sig = signer.sign(
    @core.SignAlg::RS256,
    @core.SigningKey::Der(decode_key_b64(rsa_pkcs1_b64)),
    msg,
  )
  @debug.assert_eq(sig.length(), 256)
  let pk = @rsa.PublicKey::new(
    hex_bytes(rsa_n_hex)[:],
    hex_bytes(rsa_e_hex)[:],
    digest=@rsa.Digest::Sha256,
    scheme=@rsa.Scheme::Pkcs1,
  )
  assert_true(pk.verify(msg[:], sig[:]))
}

///|
/// RS256：PKCS#1 PEM 形态同样可加载并签出可验签的签名。
async test "signer: RS256 accepts a PKCS#1 PEM key" {
  let signer = @oauth.MooncryptSecretSigner::new()
  let msg = @utf8.encode("moonauth-rs256-pem")
  let sig = signer.sign(
    @core.SignAlg::RS256,
    @core.SigningKey::Pem(rsa_pem()),
    msg,
  )
  @debug.assert_eq(sig.length(), 256)
  let pk = @rsa.PublicKey::new(
    hex_bytes(rsa_n_hex)[:],
    hex_bytes(rsa_e_hex)[:],
    digest=@rsa.Digest::Sha256,
    scheme=@rsa.Scheme::Pkcs1,
  )
  assert_true(pk.verify(msg[:], sig[:]))
}

///|
/// 密钥加载失败（形态非法 / 长度错误 / base64 非法）一律 `KeyError`。
async test "signer: malformed keys raise key_error" {
  let signer = @oauth.MooncryptSecretSigner::new()
  let msg = @utf8.encode("x")
  // ES256：DER 截断
  let c1 = try {
    let _ = signer.sign(
      @core.SignAlg::ES256,
      @core.SigningKey::Der(b"\x00\x01"),
      msg,
    )
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(c1, "key_error")
  // ES256：长度对但非密钥结构（32 字节全 0xff 非 P-256 合法标量）
  let c2 = try {
    let _ = signer.sign(
      @core.SignAlg::ES256,
      @core.SigningKey::Der(
        hex_bytes(
          "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ),
      ),
      msg,
    )
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(c2, "key_error")
  // RS256：非 DER
  let c3 = try {
    let _ = signer.sign(
      @core.SignAlg::RS256,
      @core.SigningKey::Der(b"not-der"),
      msg,
    )
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(c3, "key_error")
  // RS256：PEM 体非法 base64 → 归一为 KeyError
  let c4 = try {
    let _ = signer.sign(
      @core.SignAlg::RS256,
      @core.SigningKey::Pem(
        "-----BEGIN RSA PRIVATE KEY-----\n@@@@\n-----END RSA PRIVATE KEY-----\n",
      ),
      msg,
    )
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(c4, "key_error")
}

// ════════ StandardOAuthAuthCode ════════

///|
/// `begin` 组授权 URL：断言**绝对端点前缀** + query 构成。
/// （端点随 `AuthorizeRequest.authorization_endpoint` 传入，不再是实现的内部状态。）
async test "standard oauth: begin assembles the PKCE authorization URL" {
  let oauth = @oauth.StandardOAuthAuthCode::new().with_http(@contract.MockHttpClient::new([]))
  let start = oauth.begin(@contract.authorize_request())
  assert_true(start.url.has_prefix(@contract.google_authorization_endpoint + "?"))
  assert_true(start.url.contains("client_id=client-1"))
  assert_true(start.url.contains("redirect_uri=https%3A%2F%2Fapp.example%2Fcb"))
  assert_true(start.url.contains("response_type=code"))
  assert_true(start.url.contains("scope=openid%20email"))
  assert_true(start.url.contains("state=st-123"))
  assert_true(start.url.contains("nonce=nonce-1"))
  assert_true(start.url.contains("code_challenge=CHALLENGE-abc"))
  assert_true(start.url.contains("code_challenge_method=S256"))
  // 临时态随返回值交给调用方（零状态）：verifier 由调用方持有，不在此返回
  @debug.assert_eq(start.state, "st-123")
  @debug.assert_eq(start.nonce, Some("nonce-1"))
  @debug.assert_eq(start.code_verifier, None)
}

///|
/// `begin` 的 `extra` 按**字典序**升序追加，保证输出确定性。
async test "standard oauth: begin appends extra params in sorted order" {
  let oauth = @oauth.StandardOAuthAuthCode::new().with_http(@contract.MockHttpClient::new([]))
  let req : @core.AuthorizeRequest = {
    authorization_endpoint: "https://r.example/authorize",
    client_id: "c",
    redirect_uri: "https://r/",
    scopes: [],
    state: "s",
    nonce: None,
    code_challenge: None,
    code_challenge_method: None,
    response_mode: Some("form_post"),
    extra: Map([("zeta", "1"), ("alpha", "2")]),
  }
  let url = oauth.begin(req).url
  // 无 scope 时不输出 scope 参数
  assert_false(url.contains("scope="))
  assert_true(url.contains("response_mode=form_post"))
  let at_alpha = url.find("alpha=2").unwrap_or(-1)
  let at_zeta = url.find("zeta=1").unwrap_or(-1)
  assert_true(at_alpha >= 0 && at_zeta >= 0 && at_alpha < at_zeta)
}

///|
/// `exchange` 解析 JSON 成功体为 `TokenSet`。
async test "standard oauth: exchange parses a JSON token response" {
  let client = @contract.MockHttpClient::new([
    @contract.ok_response(
      "{\"access_token\":\"at-1\",\"token_type\":\"Bearer\",\"expires_in\":120,\"id_token\":\"idt\",\"refresh_token\":\"rt\",\"scope\":\"openid\"}",
    ),
  ])
  let oauth = @oauth.StandardOAuthAuthCode::new().with_http(client)
  let token = oauth.exchange(@contract.token_exchange_request())
  @debug.assert_eq(token.access_token, "at-1")
  @debug.assert_eq(token.id_token, Some("idt"))
  @debug.assert_eq(token.refresh_token, Some("rt"))
  @debug.assert_eq(token.expires_in, Some(120))
  @debug.assert_eq(token.token_type, Some("Bearer"))
  @debug.assert_eq(token.scope, Some("openid"))
  // 原始字段亦保留
  @debug.assert_eq(token.raw.get("scope"), Some("openid"))
}

///|
/// `exchange` 回退解析 form-encoded 成功体。
async test "standard oauth: exchange parses a form-encoded token response" {
  let client = @contract.MockHttpClient::new([
    @contract.ok_response(
      "access_token=at-2&token_type=bearer&expires_in=60&refresh_token=rt-2",
    ),
  ])
  let oauth = @oauth.StandardOAuthAuthCode::new().with_http(client)
  let token = oauth.exchange(@contract.token_exchange_request())
  @debug.assert_eq(token.access_token, "at-2")
  @debug.assert_eq(token.expires_in, Some(60))
  @debug.assert_eq(token.refresh_token, Some("rt-2"))
  @debug.assert_eq(token.id_token, None)
}

///|
/// 🔴 `exchange` 的响应体解析**不读 `resp.headers`**：只要体是 form-encoded，即便
/// `Content-Type` 明确声明为 `application/x-www-form-urlencoded`，也照样解析为 `TokenSet`。
///
/// 这是**产品包自身的**用例（此前该行为只被 `qa_verify` 的外部测试覆盖）。解析路径是
/// 「JSON 优先（试探）→ 失败回退 form-encoded」，与 `Content-Type` 无关。
async test "standard oauth: exchange parses a content-type-declared form body" {
  let resp : @core.HttpResponse = {
    status: 200,
    headers: Map([("Content-Type", "application/x-www-form-urlencoded")]),
    body: "access_token=at-5&token_type=Bearer&expires_in=3600",
  }
  let client = @contract.MockHttpClient::new([resp])
  let oauth = @oauth.StandardOAuthAuthCode::new().with_http(client)
  let token = oauth.exchange(@contract.token_exchange_request())
  @debug.assert_eq(token.access_token, "at-5")
  @debug.assert_eq(token.token_type, Some("Bearer"))
  @debug.assert_eq(token.expires_in, Some(3600))
  @debug.assert_eq(token.id_token, None)
}

///|
/// 🔴 **边界（有意为之，请勿"修"成严格分派）**：`Content-Type` 声称 `application/json`
/// 而体实为 form-encoded → **仍被解析成功**，因为实现根本不读 `resp.headers`。
///
/// 这不是缺陷：宽松解析能兼容那些 `Content-Type` 标错的平台（QQ `fmt=json` 回退、
/// 错误网关回退 form 等）。本用例**固化**该行为，避免后人误判为 bug 而改成按 header
/// 严格分派、从而打破平台兼容性。
async test "standard oauth: exchange ignores a lying JSON content-type and parses the form body" {
  let resp : @core.HttpResponse = {
    status: 200,
    headers: Map([("Content-Type", "application/json")]),
    body: "access_token=at-6&token_type=bearer&expires_in=7200",
  }
  let client = @contract.MockHttpClient::new([resp])
  let oauth = @oauth.StandardOAuthAuthCode::new().with_http(client)
  let token = oauth.exchange(@contract.token_exchange_request())
  @debug.assert_eq(token.access_token, "at-6")
  @debug.assert_eq(token.token_type, Some("bearer"))
  @debug.assert_eq(token.expires_in, Some(7200))
}

///|
/// provider 业务错误码（`error` + `error_description`）归一为 `ProviderError`。
async test "standard oauth: provider error code maps to ProviderError" {
  let client = @contract.MockHttpClient::new([
    @contract.status_response(
      400,
      "{\"error\":\"invalid_client\",\"error_description\":\"bad client\"}",
    ),
  ])
  let oauth = @oauth.StandardOAuthAuthCode::new().with_http(client)
  let (code, provider_code, message) = try {
    let _ = oauth.exchange(@contract.token_exchange_request())
    ("no-error", "", "")
  } catch {
    e =>
      match e {
        ProviderError(c, m) => (@core.auth_error_code(e), c, m)
        _ => (@core.auth_error_code(e), "", "")
      }
  }
  @debug.assert_eq(code, "provider_error")
  @debug.assert_eq(provider_code, "invalid_client")
  @debug.assert_eq(message, "bad client")
}

///|
/// 非 2xx 且体里没有 provider 业务码 → `HttpStatus`。
async test "standard oauth: non-2xx without error code maps to HttpStatus" {
  let client = @contract.MockHttpClient::new([
    @contract.status_response(502, "upstream boom"),
  ])
  let oauth = @oauth.StandardOAuthAuthCode::new().with_http(client)
  let code = try {
    let _ = oauth.exchange(@contract.token_exchange_request())
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "http_status")
}

///|
/// 2xx 但缺 `access_token` → `ParseError`。
async test "standard oauth: success body missing access_token raises parse_error" {
  let client = @contract.MockHttpClient::new([
    @contract.ok_response("{\"token_type\":\"Bearer\"}"),
  ])
  let oauth = @oauth.StandardOAuthAuthCode::new().with_http(client)
  let code = try {
    let _ = oauth.exchange(@contract.token_exchange_request())
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "parse_error")
}

// ════════ 契约：对默认实现跑参数化断言集 ════════

///|
/// `OAuthAuthCode` 契约对**库自实现**（`StandardOAuthAuthCode`）100% 通过。
///
/// 🔴 契约函数只调用一次 `make()`，并对返回的实现触发 1 次 `begin` + 2 次 `exchange`，
/// 故这里的 `MockHttpClient` 预置 2 条响应（先成功、后失败）。
async test "oauth contract: StandardOAuthAuthCode passes every case" {
  let cases = @contract.run_oauth(fn() {
    let client = @contract.MockHttpClient::new(@contract.oauth_token_responses())
    let subject : &@core.OAuthAuthCode = @oauth.StandardOAuthAuthCode::new()
      .with_http(client)
    subject
  })
  @contract.assert_all_pass(cases)
}
