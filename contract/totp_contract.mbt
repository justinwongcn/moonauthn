//! moonauth / contract —— `TotpPrimitive` 的参数化契约（SDK-04 / LIB-17）。
//!
//! 契约函数 `run_totp(make)` 把**同一套断言**跑在任意实现上（库自实现 / 官方 SDK 适配层）。
//!
//! 断言集：
//! - 密钥生成：`generate_secret(160)` 返回 20 字节；
//! - `otpauth://` URI 形状（前缀 / secret / issuer / algorithm / digits / period）；
//! - **RFC 6238 附录 B 的 6 条 SHA-1 向量**（8 位 / 30 秒）；
//! - 错误口令被拒；漂移窗口生效；
//! - 恢复码：互不相同、形如 `XXXX-XXXX`；哈希为 64 位小写十六进制且确定性。
//!
//! ## 🔴 调用方契约
//! seam `TotpPrimitive.verify(Self, secret, code, at_unix, window)` **不含** `digits` /
//! `period` / `algorithm`（签名由 SDK-01 冻结），故它们是**实现级配置**。本契约的 RFC
//! 向量针对 **SHA-1 / 8 位 / 30 秒**，因此：
//!
//! > `make` 必须返回一个以 `digits = 8`、`period = 30`、`algorithm = "SHA1"` 构造的实现。
//!
//! 这与 `run_oauth`「调用方须把实现接到预置 2 条响应的 `HttpClient`」同属「以固定向量
//! 驱动」的取法——契约定义行为，向量由调用方按其部署配置提供。
//!
//! 说明：本文件是**同步**契约（`TotpPrimitive` 是同步 seam），且只依赖 `@core`
//! （RFC 种子用字节串字面量，无需 `@utf8`）。

///|
/// RFC 6238 附录 B 的 SHA-1 共享密钥（20 字节 ASCII `"12345678901234567890"`）。
pub fn rfc6238_sha1_seed() -> Bytes {
  b"12345678901234567890"
}

///|
/// 对给定 `TotpPrimitive` 实现跑完整断言集。
///
/// 前置条件见文件头「调用方契约」：被测实现须为 SHA-1 / 8 位 / 30 秒。
pub fn run_totp(make : () -> &@core.TotpPrimitive) -> Array[CaseResult] {
  let subject = make()
  let seed = rfc6238_sha1_seed()
  let out : Array[CaseResult] = []

  // —— 密钥生成 ——
  out.push(
    totp_case("totp: generate_secret(160) yields 20 bytes", () => {
      let secret = subject.generate_secret(160)
      if secret.length() == 20 {
        None
      } else {
        Some("expected 20 bytes, got \{secret.length()}")
      }
    }),
  )

  // —— otpauth URI 形状 ——
  out.push(
    totp_case("totp: otpauth_uri has the expected shape", () => {
      let opts : @core.TotpOptions = {
        digits: 8,
        period: 30,
        algorithm: "SHA1",
      }
      let uri = subject.otpauth_uri(seed, "alice@example.com", "Acme", opts)
      let checks : Array[(String, Bool)] = [
        ("otpauth://totp/ prefix", uri.has_prefix("otpauth://totp/")),
        ("label Acme:alice", uri.contains("/Acme:alice")),
        ("secret= parameter", uri.contains("secret=")),
        ("issuer= parameter", uri.contains("issuer=Acme")),
        ("algorithm= parameter", uri.contains("algorithm=SHA1")),
        ("digits= parameter", uri.contains("digits=8")),
        ("period= parameter", uri.contains("period=30")),
      ]
      let missing : Array[String] = []
      for check in checks {
        let (label, ok) = check
        if !ok {
          missing.push(label)
        }
      }
      if missing.length() == 0 {
        None
      } else {
        Some("uri missing/mismatched: " + missing.join(",") + " | uri=" + uri)
      }
    }),
  )

  // —— RFC 6238 附录 B：SHA-1 / 8 位 / 30 秒（6 条官方向量）——
  out.push(
    totp_case("totp: RFC 6238 SHA-1 vector at 59s", () => {
      expect_code(subject, seed, "94287082", 59L, 0)
    }),
  )
  out.push(
    totp_case("totp: RFC 6238 SHA-1 vector at 1111111109s", () => {
      expect_code(subject, seed, "07081804", 1111111109L, 0)
    }),
  )
  out.push(
    totp_case("totp: RFC 6238 SHA-1 vector at 1111111111s", () => {
      expect_code(subject, seed, "14050471", 1111111111L, 0)
    }),
  )
  out.push(
    totp_case("totp: RFC 6238 SHA-1 vector at 1234567890s", () => {
      expect_code(subject, seed, "89005924", 1234567890L, 0)
    }),
  )
  out.push(
    totp_case("totp: RFC 6238 SHA-1 vector at 2000000000s", () => {
      expect_code(subject, seed, "69279037", 2000000000L, 0)
    }),
  )
  out.push(
    totp_case("totp: RFC 6238 SHA-1 vector at 20000000000s", () => {
      expect_code(subject, seed, "65353130", 20000000000L, 0)
    }),
  )

  // —— 错误口令被拒 ——
  out.push(
    totp_case("totp: verify rejects a wrong code", () => {
      if subject.verify(seed, "00000000", 59L, 0) {
        Some("accepted an unrelated code")
      } else {
        None
      }
    }),
  )

  // —— 漂移窗口 ——
  out.push(
    totp_case("totp: verify honours the drift window", () => {
      // t=59 的口令在 t=89（+1 步）配 window=1 应通过；在 t=119（+2 步）应被拒。
      if !subject.verify(seed, "94287082", 89L, 1) {
        Some("rejected the previous step inside a +/-1 window")
      } else if subject.verify(seed, "94287082", 119L, 1) {
        Some("accepted a code two steps away with a +/-1 window")
      } else {
        None
      }
    }),
  )

  // —— 恢复码生成 ——
  out.push(
    totp_case("totp: generate_recovery_codes returns distinct XXXX-XXXX codes", () => {
      let codes = subject.generate_recovery_codes(5)
      if codes.length() != 5 {
        return Some("expected 5 codes, got \{codes.length()}")
      }
      let seen : Array[String] = []
      for code in codes {
        if code.length() != 9 || code.get_char(4) != Some('-') {
          return Some("malformed recovery code: " + code)
        }
        if seen.contains(code) {
          return Some("duplicate recovery code: " + code)
        }
        seen.push(code)
      }
      None
    }),
  )

  // —— 恢复码哈希 ——
  out.push(
    totp_case("totp: hash_recovery_codes is a deterministic sha-256 hex", () => {
      let codes : Array[String] = ["AAAA-AAAA", "BBBB-BBBB"]
      let first = subject.hash_recovery_codes(codes)
      let second = subject.hash_recovery_codes(codes)
      if first.length() != 2 {
        return Some("expected 2 hashes, got \{first.length()}")
      }
      for i in 0..<2 {
        let hash = first[i]
        if hash.length() != 64 || !is_lower_hex(hash) {
          return Some("hash is not 64-char lowercase hex: " + hash)
        }
        if hash != second[i] {
          return Some("hash is not deterministic across calls")
        }
      }
      if first[0] == first[1] {
        return Some("distinct codes produced identical hashes")
      }
      None
    }),
  )

  out
}

// ════════ 用例包装 ════════

///|
/// 执行一条用例：`body` 返回 `None` 通过、`Some(detail)` 失败；
/// `body` 抛出的 `AuthError` 记为「意外错误」用例失败。
fn totp_case(
  name : String,
  body : () -> String? raise @core.AuthError,
) -> CaseResult {
  let detail = try {
    body()
  } catch {
    e => Some("unexpected error: " + @core.auth_error_message(e))
  }
  match detail {
    None => CaseResult::pass(name)
    Some(d) => CaseResult::fail(name, d)
  }
}

///|
/// 断言给定向量口令在 `at_unix` 处（`window = 0`）通过校验；否则返回失败原因。
fn expect_code(
  subject : &@core.TotpPrimitive,
  seed : Bytes,
  code : String,
  at_unix : Int64,
  window : Int,
) -> String? raise @core.AuthError {
  if subject.verify(seed, code, at_unix, window) {
    None
  } else {
    Some("expected the RFC code \{code} to verify at \{at_unix}s")
  }
}

///|
/// 是否为 64 字符的纯小写十六进制串。
fn is_lower_hex(s : String) -> Bool {
  let mut ok = true
  for i in 0..<s.length() {
    let c = s.get_char(i).unwrap().to_int()
    if !((c >= 48 && c <= 57) || (c >= 97 && c <= 102)) {
      ok = false
    }
  }
  ok
}
