//! moonauth / provider/apple —— 黑盒测试（form_post / ES256 secret / 归一化 / 错误）。
//!
//! 全部离线确定性：HTTP 走 `@contract.MockHttpClient`，时钟走 `@contract.FixedClock`，
//! `id_token` 用 `@contract` 固定向量，P-256 私钥用固定向量并**独立**用公钥验签。

// ════════ 测试辅助 ════════

///|
/// 十六进制 → 字节。
fn apple_hex_bytes(s : String) -> Bytes {
  let src = @utf8.encode(s)
  let out : Array[Byte] = []
  let n = src.length()
  let mut i = 0
  while i + 1 < n {
    out.push(((apple_nibble(src[i].to_int()) << 4) | apple_nibble(src[i + 1].to_int())).to_byte())
    i = i + 2
  }
  Bytes::from_array(out)
}

///|
/// 单字符十六进制 → 数值。
fn apple_nibble(v : Int) -> Int {
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
/// 固定 P-256 私钥标量（与 `oauth` 测试同一公开向量）。
let apple_ec_scalar_hex : String = "bd22ad524766bf498aca4db17d71a41120f363ccf02ae2a76697aa47b7aacb60"

///|
/// 固定 P-256 公钥 X 坐标。
let apple_ec_x_hex : String = "e12e6cf5ebe33515d747d0fd2e18e69b5a44863d5ed115c7a3e77fe8348839a6"

///|
/// 固定 P-256 公钥 Y 坐标。
let apple_ec_y_hex : String = "63c69516103e7f958deda1bfa51736f32ab63d9802137a57103b98663d17d3dd"

///|
/// 一条 Apple 固定配置（未接 mock；由调用方 `with_http` 补）。
fn apple_base_config() -> @apple.AppleConfig {
  @apple.AppleConfig::new(
    "client-1",
    "https://app.example/cb",
    "TEAM123",
    "KEY123",
    @core.SigningKey::Der(apple_hex_bytes(apple_ec_scalar_hex)),
  ).with_endpoints(
    "https://appleid.apple.com/auth/authorize",
    "mock://token",
    "mock://jwks",
    "https://issuer.example",
  )
}

///|
/// 固定 token 响应（含 refresh_token）。
fn apple_token_ok() -> @core.HttpResponse {
  {
    status: 200,
    headers: Map([("Content-Type", "application/json")]),
    body: "{\"access_token\":\"at-1\",\"token_type\":\"Bearer\",\"refresh_token\":\"rt-1\"}",
  }
}

///|
/// 接好固定向量的 Apple 配置。
fn apple_fixed_config() -> @apple.AppleConfig {
  let client : &@core.HttpClient = @contract.MockHttpClient::new([
    apple_token_ok(),
    @contract.jwks_response(),
  ])
  let clock : &@core.Clock = @contract.FixedClock::new(@contract.fixed_now_unix())
  apple_base_config().with_http(client).with_clock(clock)
}

// ════════ begin_auth ════════

///|
/// `begin_auth` 必须带 `response_mode=form_post` + PKCE。
async test "apple: begin_auth uses form_post + PKCE" {
  let config = apple_base_config()
  let start = @apple.begin_auth(config, {
    state: Some("st-1"),
    code_verifier: Some("verifier-1"),
    nonce: Some("nonce-1"),
  })
  let url = start.url
  assert_true(url.has_prefix("https://appleid.apple.com/auth/authorize?"))
  assert_true(url.contains("response_mode=form_post"))
  assert_true(url.contains("code_challenge_method=S256"))
  assert_true(url.contains("nonce=nonce-1"))
  @debug.assert_eq(start.code_verifier, Some("verifier-1"))
}

// ════════ ES256 client secret ════════

///|
/// client secret 是合法 JWS：签名能被**独立构造**的 P-256 公钥验签通过（64 字节 raw）。
async test "apple: ES256 client secret is a verifiable JWS" {
  let config = @apple.AppleConfig::new(
    "com.example.app",
    "https://app.example/cb",
    "TEAM123",
    "KEY123",
    @core.SigningKey::Der(apple_hex_bytes(apple_ec_scalar_hex)),
  )
  let secret = @apple.apple_client_secret(config)
  let parts = secret.split(".").to_array()
  @debug.assert_eq(parts.length(), 3)
  let header = parts[0].to_owned()
  let payload = parts[1].to_owned()
  let sig = @oauth.base64url_decode(parts[2].to_owned())
  @debug.assert_eq(sig.length(), 64)
  let signing_input = @utf8.encode(header + "." + payload)
  let pk = @ecdsa.PublicKey::of_xy(
    apple_hex_bytes(apple_ec_x_hex)[:],
    apple_hex_bytes(apple_ec_y_hex)[:],
    curve=@ecdsa.Curve::P256,
  )
  assert_true(pk.verify(signing_input[:], sig[:]))
  // 头 / 载荷的声明符合 Apple 要求
  let payload_json = @utf8.decode_lossy(@oauth.base64url_decode(payload))
  assert_true(payload_json.contains("\"iss\":\"TEAM123\""))
  assert_true(payload_json.contains("\"sub\":\"com.example.app\""))
  assert_true(payload_json.contains("\"aud\":\"https://appleid.apple.com\""))
  let header_json = @utf8.decode_lossy(@oauth.base64url_decode(header))
  assert_true(header_json.contains("\"alg\":\"ES256\""))
  assert_true(header_json.contains("\"kid\":\"KEY123\""))
}

///|
/// 🔴 client secret 的 JWS header/payload 对用户配置值做 **JSON 转义**：含 `"` 与 `\`
/// 的 `client_id` / `team_id` / `key_id` 仍产出**合法 JSON**，且值原样 round-trip。
///
/// 修复前（朴素拼接）payload 会变成 `…"sub":"com.example."quoted"\path"}` —— **非法
/// JSON**。这里用**逐字节期望串**（固定时钟 → 完全确定）作独立 oracle，朴素拼接必不等。
///
/// （黑盒测试作用域里核心包 `Json` 类型不易引用，故不依赖 `@json` 解析，改用字符串
/// 逐字节比对——等价且更强。）
async test "apple: client secret JSON-escapes a client_id containing quotes and backslashes" {
  let now = @contract.fixed_now_unix()
  let ttl : Int64 = 15777000L // = apple_client_secret_ttl（≈ 182.6 天）
  let clock : &@core.Clock = @contract.FixedClock::new(now)
  let config = @apple.AppleConfig::new(
    "com.example.\"quoted\"\\path",
    "https://app.example/cb",
    "TEAM\"123",
    "KEY\\123",
    @core.SigningKey::Der(apple_hex_bytes(apple_ec_scalar_hex)),
  ).with_clock(clock)
  let secret = @apple.apple_client_secret(config)
  let parts = secret.split(".").to_array()
  @debug.assert_eq(parts.length(), 3)
  let header = parts[0].to_owned()
  let payload = parts[1].to_owned()
  let header_json = @utf8.decode_lossy(@oauth.base64url_decode(header))
  let payload_json = @utf8.decode_lossy(@oauth.base64url_decode(payload))
  // 逐字节期望串（独立 oracle）：只有正确转义才相等
  @debug.assert_eq(
    header_json,
    "{\"alg\":\"ES256\",\"kid\":\"KEY\\\\123\",\"typ\":\"JWT\"}",
  )
  @debug.assert_eq(
    payload_json,
    "{\"iss\":\"TEAM\\\"123\",\"iat\":" +
    now.to_string() +
    ",\"exp\":" +
    (now + ttl).to_string() +
    ",\"aud\":\"https://appleid.apple.com\",\"sub\":\"com.example.\\\"quoted\\\"\\\\path\"}",
  )
  // 签名仍能被独立构造的公钥验签通过（未破坏 JOSE 线格式）
  let sig = @oauth.base64url_decode(parts[2].to_owned())
  @debug.assert_eq(sig.length(), 64)
  let pk = @ecdsa.PublicKey::of_xy(
    apple_hex_bytes(apple_ec_x_hex)[:],
    apple_hex_bytes(apple_ec_y_hex)[:],
    curve=@ecdsa.Curve::P256,
  )
  assert_true(pk.verify(@utf8.encode(header + "." + payload)[:], sig[:]))
}

// ════════ form_post 解析 ════════

///|
/// `form_post` 回调体（urlencoded）→ `CallbackParams`。
async test "apple: form_post callback parses into params" {
  let body = "code=auth-code-1&id_token=" +
    @contract.fixed_token_ok +
    "&state=st-1"
  let cb = @apple.apple_callback(body)
  @debug.assert_eq(cb.get("code"), Some("auth-code-1"))
  @debug.assert_eq(cb.get("id_token"), Some(@contract.fixed_token_ok))
  @debug.assert_eq(cb.get("state"), Some("st-1"))
}

// ════════ complete_auth ════════

///|
/// 固定向量 → 确定性 identity；首次授权的 `user` 姓名补入 `display_name`。
async test "apple: complete_auth yields a deterministic identity with first-auth name" {
  let start = @apple.begin_auth(apple_base_config(), {
    state: Some("st-1"),
    code_verifier: Some("verifier-1"),
    nonce: Some("nonce-1"),
  })
  // 首次授权额外带 user（通常在 form_post body 里；此处用 from_pairs 直接注入）。
  let with_user = @core.CallbackParams::from_pairs(
    Map([
      ("code", "auth-code-1"),
      ("id_token", @contract.fixed_token_ok),
      ("state", "st-1"),
      ("user", "{\"name\":{\"firstName\":\"Ada\",\"lastName\":\"Lovelace\"}}"),
    ]),
  )
  let identity = @apple.complete_auth(apple_fixed_config(), with_user, start)
  @debug.assert_eq(identity.provider, "apple")
  @debug.assert_eq(identity.uid, "user-1")
  @debug.assert_eq(identity.email, Some("alice@example.com"))
  @debug.assert_eq(identity.email_verified, true)
  @debug.assert_eq(identity.display_name, Some("Ada Lovelace"))
}

// ════════ is_private_email 双形态 ════════

///|
/// `is_private_email` 兼容布尔 / 字符串两形态：归一后都是同一字符串视图 → `Bool`。
async test "apple: is_private_email normalizes both true and \"true\"" {
  // `@oidc` 的 json_to_string 把布尔 `true` 与字符串 `"true"` 都归一为 "true"，
  // 故进入 public claim 后二者不可区分——两种来源都必须判为私有邮箱。
  let from_bool : @core.IdTokenClaims = {
    subject: "u",
    issuer: "i",
    audience: ["a"],
    expires_at: 0L,
    issued_at: 0L,
    nonce: None,
    email: None,
    email_verified: None,
    raw: Map([("is_private_email", "true")]),
  }
  let from_string : @core.IdTokenClaims = { ..from_bool, raw: Map([("is_private_email", "true")]) }
  @debug.assert_eq(@apple.apple_is_private_email(from_bool), true)
  @debug.assert_eq(@apple.apple_is_private_email(from_string), true)
  let absent : @core.IdTokenClaims = { ..from_bool, raw: Map([]) }
  @debug.assert_eq(@apple.apple_is_private_email(absent), false)
}

// ════════ 错误向量 ════════

///|
/// `state` 不符 → `StateMismatch`。
async test "apple: state mismatch is rejected" {
  let config = apple_fixed_config()
  let start = @apple.begin_auth(config, {
    state: Some("st-1"),
    code_verifier: Some("verifier-1"),
    nonce: Some("nonce-1"),
  })
  let cb = @core.CallbackParams::from_query_string("code=c&state=WRONG&id_token=x")
  let code = try {
    let _ = @apple.complete_auth(config, cb, start)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "state_mismatch")
}

///|
/// 回调缺 `id_token` → `MissingParam`。
async test "apple: missing id_token is rejected as missing_param" {
  let config = apple_fixed_config()
  let start = @apple.begin_auth(config, {
    state: Some("st-1"),
    code_verifier: Some("verifier-1"),
    nonce: Some("nonce-1"),
  })
  let cb = @core.CallbackParams::from_query_string("code=c&state=st-1")
  let code = try {
    let _ = @apple.complete_auth(config, cb, start)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "missing_param")
}
