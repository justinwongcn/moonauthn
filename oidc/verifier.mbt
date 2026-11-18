//! moonauth / oidc —— 默认 `IdTokenVerifier` 实现：`JwksIdTokenVerifier`。
//!
//! 语义 = OIDC id_token 验签：
//! 1. 从 token 头取 `alg` / `kid`，按 `alg` 决定算法（RS256 / RS384 / RS512 / ES256 / ES384 / ES512）；
//! 2. 经 `jwks_uri` 取 JWKS（实例内缓存 + 轮转，见 `jwks_cache.mbt`），按 `kid` 选公钥；
//! 3. `mooncred/jwt::verify` 验签 + 校验 `exp` / `nbf`（含 `leeway`）/ `aud`；
//! 4. 本层补 `iss`（支持多值）与 `nonce` 校验；
//! 5. `@jwt.Rejected` → `AuthError`（ARCH §4.3）；第三方类型**绝不**逃逸到公开签名。
//!
//! 公开签名只出现 `@core` 类型；`@jwt` / `@jwk` / `@rsa` / `@ecdsa` / `@spec` 仅出现在
//! 私有函数体内，`.mbti` 完全干净（SDK-03）。

///|
/// 实现 seam：验证 `id_token` 并返回归一化 claims。
pub impl @core.IdTokenVerifier for JwksIdTokenVerifier with fn verify(self, token, expect) {
  self.verify_token(token, expect)
}

///|
/// 显式把 seam 方法提升为常规方法，避免隐式提升的弃用告警。
pub extend JwksIdTokenVerifier with @core.IdTokenVerifier::{verify}

///|
/// `verify` 的实际实现（抽成私有 async 方法，便于内部复用与阅读）。
async fn JwksIdTokenVerifier::verify_token(
  self : JwksIdTokenVerifier,
  token : String,
  expect : @core.IdTokenExpectations,
) -> @core.IdTokenClaims raise @core.AuthError {
  let jwks_uri = match expect.jwks_uri {
    Some(uri) => uri
    None => raise @core.InvalidInput("moonauth: IdTokenExpectations.jwks_uri is required")
  }
  // 🔴 fail-closed：OIDC 中 `iss` / `aud` 校验没有合法的「跳过」场景——空数组会让
  // 「任何发行者 / 任何受众」的 token 直接通过（省略即关闭的默认方向是错的）。
  if expect.issuers.is_empty() {
    raise @core.InvalidInput(
      "moonauth: IdTokenExpectations.issuers must not be empty",
    )
  }
  if expect.audiences.is_empty() {
    raise @core.InvalidInput(
      "moonauth: IdTokenExpectations.audiences must not be empty",
    )
  }
  let (alg, kid) = parse_header(token)
  let alg_name = alg.name()
  // 🔴 RFC 8725 §3.1：token 头的 `alg` 不可信，必须先过调用方白名单再继续。
  // 空白名单 = 接受本实现支持的任一算法（RS/ES 族，最终仍绑死 JWKS 公钥）。
  if expect.algorithms.length() > 0 && !expect.algorithms.contains(alg_name) {
    raise @core.UnsupportedAlg(alg_name)
  }
  let mut body = self.current_jwks(jwks_uri)
  let mut key = select_key(body, alg_name, kid)
  if key is None {
    // 轮转：缓存里找不到该 kid，强制重取一次 JWKS 再选（覆盖密钥轮换场景）。
    // 🔴 节流：距上次强制重取不足 `forced_refetch_min_seconds` 时不再出站——
    // 否则未认证路径上伪造随机 `kid` 即可把每次验签放大为对 `jwks_uri` 的出站请求。
    let now = self.clock.now_unix()
    if now - self.last_forced_refetch >= self.forced_refetch_min_seconds {
      self.last_forced_refetch = now
      body = self.fetch_jwks(jwks_uri)
      key = select_key(body, alg_name, kid)
    }
  }
  let jwk = match key {
    Some(k) => k
    None => raise @core.KeyError("moonauth: no JWKS key matches the id_token kid/alg")
  }
  let verifier = build_verifier(jwk, alg)
  let now = self.clock.now_unix()
  let leeway = match expect.leeway_seconds {
    Some(seconds) => seconds.to_int64()
    None => 0L
  }
  let claims = @jwt.verify(
    token[:],
    alg,
    verifier,
    now=@jwt.Clock::At(now),
    leeway=leeway,
    audience=expect.audiences,
  ) catch {
    e => raise map_rejected(e, token)
  }
  check_exp(claims)
  check_issuer(claims, expect.issuers)
  check_nonce(claims, expect.nonce)
  check_azp(claims, expect.audiences)
  build_claims(claims)
}

///|
/// 🔴 `exp` 为 OIDC Core 的 REQUIRED 声明，客户端 MUST 校验——**缺失即拒绝**，
/// 不得静默放行（mooncred 对缺失 `exp` 跳过过期检查，故本层补防线）。
/// 非数值形态（字符串等）视同缺失（`num_claim` 亦不会采信）。
fn check_exp(claims : Map[String, Json]) -> Unit raise @core.AuthError {
  match claims.get("exp") {
    Some(Number(_, ..)) => ()
    _ =>
      raise @core.ParseError(
        "moonauth: id_token missing/invalid exp claim (REQUIRED by OIDC Core)",
      )
  }
}

// ════════ 头部解析与公钥选择 ════════

///|
/// 取 JOSE 头的 `alg`（映射为 `@jwt.Alg`）与可选 `kid`。
fn parse_header(token : String) -> (@jwt.Alg, String?) raise @core.AuthError {
  let header = @jwt.header(token[:]) catch {
    _ => raise @core.ParseError("moonauth: id_token has an invalid JOSE header")
  }
  let name = match header.get("alg") {
    Some(String(s)) => s
    _ => raise @core.UnsupportedAlg("id_token header has no alg")
  }
  let alg = @jwt.Alg::of(name[:]) catch {
    _ => raise @core.UnsupportedAlg(name)
  }
  let kid = match header.get("kid") {
    Some(String(s)) => Some(s)
    _ => None
  }
  (alg, kid)
}

///|
/// 在当前 JWKS 文本中选出 token 对应的公钥（按 `kid` + `alg`，`use` 默认要求 `sig`）。
fn select_key(body : String, alg_name : String, kid : String?) -> @jwk.Jwk? {
  let parsed : @jwk.Set? = try {
    Some(@jwk.Set::parse(body[:]))
  } catch {
    _ => None
  }
  match parsed {
    None => None
    Some(set) =>
      match kid {
        Some(id) => set.pick(alg=alg_name, id=id)
        None => set.pick(alg=alg_name, first=true)
      }
  }
}

// ════════ JWK → 验签器 ════════

///|
/// 由 JWK 材料构造 `&@spec.Verifier`（按 `alg` 分派 RSA / EC）。
fn build_verifier(jwk : @jwk.Jwk, alg : @jwt.Alg) -> &@spec.Verifier raise @core.AuthError {
  match (alg, jwk.material()) {
    (RS256, Rsa(modulus~, exponent~, ..)) =>
      rsa_verifier(modulus, exponent, @rsa.Digest::Sha256)
    (RS384, Rsa(modulus~, exponent~, ..)) =>
      rsa_verifier(modulus, exponent, @rsa.Digest::Sha384)
    (RS512, Rsa(modulus~, exponent~, ..)) =>
      rsa_verifier(modulus, exponent, @rsa.Digest::Sha512)
    (ES256, Ec(curve~, x~, y~, ..)) => ec_verifier(curve, x, y, @ecdsa.Curve::P256)
    (ES384, Ec(curve~, x~, y~, ..)) => ec_verifier(curve, x, y, @ecdsa.Curve::P384)
    (ES512, Ec(curve~, x~, y~, ..)) => ec_verifier(curve, x, y, @ecdsa.Curve::P521)
    (_, _) => raise @core.UnsupportedAlg(alg.name())
  }
}

///|
/// RSA 公钥（PKCS#1 v1.5）。
fn rsa_verifier(
  modulus : Bytes,
  exponent : Bytes,
  digest : @rsa.Digest,
) -> &@spec.Verifier raise @core.AuthError {
  @rsa.PublicKey::new(
    modulus[:],
    exponent[:],
    digest=digest,
    scheme=@rsa.Scheme::Pkcs1,
  ) catch {
    _ => raise @core.KeyError("moonauth: invalid RSA JWK material")
  }
}

///|
/// EC 公钥；顺带校验 JWK 的 `crv` 与所选算法匹配。
fn ec_verifier(
  crv : String,
  x : Bytes,
  y : Bytes,
  curve : @ecdsa.Curve,
) -> &@spec.Verifier raise @core.AuthError {
  if crv != curve_name(curve) {
    raise @core.UnsupportedAlg("moonauth: JWK curve " + crv + " does not match algorithm")
  }
  @ecdsa.PublicKey::of_xy(x[:], y[:], curve=curve) catch {
    _ => raise @core.KeyError("moonauth: invalid EC JWK material")
  }
}

///|
/// JWK `crv` 的标准名。
fn curve_name(curve : @ecdsa.Curve) -> String {
  match curve {
    P256 => "P-256"
    P384 => "P-384"
    P521 => "P-521"
    Secp256k1 => "secp256k1"
  }
}

// ════════ 错误映射 ════════

///|
/// `@jwt.Rejected` → `AuthError`（ARCH §4.3）。
fn map_rejected(e : @jwt.Rejected, token : String) -> @core.AuthError {
  match e {
    Shape(msg) => @core.ParseError("moonauth: id_token: " + msg)
    Algorithm(got~, ..) => @core.UnsupportedAlg(got)
    Signature => @core.SignatureInvalid
    Expired(_) => @core.TokenExpired
    TooEarly(_) => @core.TokenNotYetValid
    Issuer(want~, got~) => @core.IssuerMismatch(got, want)
    Audience(want~) => @core.AudienceMismatch(unverified_aud(token), want.join(","))
    Subject(..) => @core.ParseError("moonauth: id_token sub mismatch")
    IssuedAt(_) => @core.TokenNotYetValid
    Type(got~, ..) => @core.UnsupportedAlg(got)
    Missing(claim~) => @core.ParseError("moonauth: id_token missing claim: " + claim)
  }
}

///|
/// 从未验签的 payload 里尽力取 `aud`，仅用于构造 `AudienceMismatch` 的 `actual` 展示。
fn unverified_aud(token : String) -> String {
  let parsed : Map[String, Json]? = try {
    Some(@jwt.claims_unverified(token[:]))
  } catch {
    _ => None
  }
  match parsed {
    None => ""
    Some(m) =>
      match m.get("aud") {
        Some(v) => json_to_string(v)
        None => ""
      }
  }
}

// ════════ claims 校验与归一 ════════

///|
/// 手动校验 `iss`（支持 `IdTokenExpectations.issuers` 多值，任一命中即通过）。
fn check_issuer(
  claims : Map[String, Json],
  issuers : Array[String],
) -> Unit raise @core.AuthError {
  if issuers.length() > 0 {
    let actual = match str_claim(claims, "iss") {
      Some(s) => s
      None => ""
    }
    if !issuers.contains(actual) {
      raise @core.IssuerMismatch(actual, issuers.join(","))
    }
  }
}

///|
/// 手动校验 `nonce`（`@jwt` 不内置 nonce 校验）。
fn check_nonce(claims : Map[String, Json], nonce : String?) -> Unit raise @core.AuthError {
  match nonce {
    None => ()
    Some(expected) => {
      let actual = match str_claim(claims, "nonce") {
        Some(s) => s
        None => ""
      }
      if actual != expected {
        raise @core.NonceMismatch
      }
    }
  }
}

///|
/// 🔴 OIDC Core §3.1.3.7（实现契约 §4.2 azp；黑客审计实测确认）：`aud` 为**多值
/// 数组**时，`azp` 必须存在且等于期望受众之一——否则「为其他受众签发」的 token
/// （aud 数组恰好包含我们的 client_id、azp=他方应用）可通过全部校验并被复用。
/// 单值 `aud` 不强制 `azp`（Google/Entra 单资源形态，向后兼容）。
fn check_azp(
  claims : Map[String, Json],
  audiences : Array[String],
) -> Unit raise @core.AuthError {
  let aud_values = audience_of(claims)
  if aud_values.length() > 1 {
    match str_claim(claims, "azp") {
      Some(azp) =>
        if !audiences.contains(azp) {
          raise @core.AudienceMismatch(azp, audiences.join(","))
        }
      None => raise @core.AudienceMismatch("<missing azp>", audiences.join(","))
    }
  }
}

///|
/// 已验签的 claims → 库自有 `IdTokenClaims`（**无 `@json.Json` 泄漏**：附加声明一律
/// 字符串化进 `raw : Map[String, String]`）。
fn build_claims(claims : Map[String, Json]) -> @core.IdTokenClaims raise @core.AuthError {
  let subject = match str_claim(claims, "sub") {
    Some(s) => s
    None => raise @core.ParseError("moonauth: id_token missing sub")
  }
  let issuer = match str_claim(claims, "iss") {
    Some(s) => s
    None => raise @core.ParseError("moonauth: id_token missing iss")
  }
  let raw : Map[String, String] = Map([])
  for k, v in claims {
    raw[k] = json_to_string(v)
  }
  {
    subject,
    issuer,
    audience: audience_of(claims),
    expires_at: num_claim(claims, "exp"),
    issued_at: num_claim(claims, "iat"),
    nonce: str_claim(claims, "nonce"),
    email: str_claim(claims, "email"),
    email_verified: bool_claim(claims, "email_verified"),
    raw,
  }
}

///|
/// 取字符串声明。
fn str_claim(claims : Map[String, Json], name : String) -> String? {
  match claims.get(name) {
    Some(String(s)) => Some(s)
    _ => None
  }
}

///|
/// 取数值声明（NumericDate），缺失或形态不符时取 `0`。
fn num_claim(claims : Map[String, Json], name : String) -> Int64 {
  match claims.get(name) {
    Some(Number(d, ..)) => d.to_int64()
    _ => 0L
  }
}

///|
/// 取布尔声明：兼容 `true` / `"true"`（Apple `is_private_email` 式双形态）。
fn bool_claim(claims : Map[String, Json], name : String) -> Bool? {
  match claims.get(name) {
    Some(True) => Some(true)
    Some(False) => Some(false)
    Some(String(s)) =>
      if s == "true" {
        Some(true)
      } else if s == "false" {
        Some(false)
      } else {
        None
      }
    _ => None
  }
}

///|
/// 归一 `aud`：字符串或字符串数组 → `Array[String]`。
fn audience_of(claims : Map[String, Json]) -> Array[String] {
  match claims.get("aud") {
    Some(String(s)) => [s]
    Some(Array(items)) => {
      let out : Array[String] = []
      for item in items {
        match item {
          String(s) => out.push(s)
          _ => ()
        }
      }
      out
    }
    _ => []
  }
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
