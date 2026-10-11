//! moonauth / contract —— `WebAuthnVerifier` 的参数化契约（SDK-04 / LIB-17）。
//!
//! - `run_webauthn(make)`：用**内置的固定向量**跑断言集（与 `run_oauth` / `run_totp` 同形）。
//! - `run_webauthn_with(make, fixtures)`：用**调用方提供的向量**跑同一套断言——契约函数与
//!   向量解耦（依赖倒置），同一断言集可对「库自实现 / 官方 SDK 适配层 + 各自向量」各跑一次。
//!
//! 断言集：
//! - 注册：有效 attestation 通过；rpId / challenge / type / origin / crossOrigin 负例；
//! - 认证：有效 assertion 通过；签名 / `signCount` 回退 / type / origin / crossOrigin 负例。
//!
//! ## 关于内置向量
//! 内置向量是**离线生成后硬编码**的：`none` 格式 attestation（无签名）+ 一个由固定 P-256
//! 私钥签出的 assertion。这样 `contract/` 无需引入任何密码学依赖，保持纯 `@core`。
//! 负例由契约在有效向量上现场「变异」得到（契约无法伪造有效签名，故正例必须来自向量）。
//!
//! 🔴 若走 `run_webauthn_with`，夹具的 `expected_assertion_sign_count` **必须大于 0**
//! （`signCount` 回退负例以它为已存储计数构造 `received <= stored` 的回退；0/0 属合法例外）。
//!
//! 说明：本文件是**同步**契约（`WebAuthnVerifier` 是同步 seam）。逐条用例用 `webauthn_case`
//! 包裹，把「本不该出现的异常」也收集成失败用例，而不是让契约中断。

///|
/// 契约夹具：`run_webauthn*` 所需的全部 WebAuthn 向量。
///
/// - `registration` / `assertion`：**必然通过**的有效向量；
/// - `expected_*`：实现应从有效向量中还原出的期望值（用于断言解析正确）。
pub(all) struct WebAuthnFixtures {
  /// 一个必然通过的注册输入。
  registration : @core.RegistrationInput
  /// `registration` 对应的凭据 ID（实现应原样返回）。
  expected_credential_id : Bytes
  /// `registration` 的认证器签名计数器（实现应原样返回）。
  expected_registration_sign_count : Int
  /// 一个必然通过的登录输入。
  assertion : @core.AssertionInput
  /// `assertion` 的认证器签名计数器（实现应原样返回）。
  expected_assertion_sign_count : Int
}

///|
/// 用**内置向量**对给定 `WebAuthnVerifier` 实现跑完整断言集。
pub fn run_webauthn(
  make : () -> &@core.WebAuthnVerifier,
) -> Array[CaseResult] {
  run_webauthn_with(make, builtin_fixtures())
}

///|
/// 用**调用方提供的向量**跑完整断言集（同一套断言，任意向量）。
pub fn run_webauthn_with(
  make : () -> &@core.WebAuthnVerifier,
  fixtures : WebAuthnFixtures,
) -> Array[CaseResult] {
  let subject = make()
  let out : Array[CaseResult] = []
  let registration = fixtures.registration
  let assertion = fixtures.assertion

  // —— 注册：正例 ——
  out.push(
    webauthn_case("webauthn: registration accepts a valid attestation", () => {
      let result = subject.verify_registration(registration)
      if result.credential_id != fixtures.expected_credential_id {
        Some("credential_id does not match the attested credential")
      } else if result.sign_count != fixtures.expected_registration_sign_count {
        Some(
          "sign_count mismatch: got \{result.sign_count}, expected \{fixtures.expected_registration_sign_count}",
        )
      } else if result.public_key.length() == 0 {
        Some("returned an empty credential public key")
      } else {
        None
      }
    }),
  )

  // —— 注册：负例 ——
  out.push(
    webauthn_case("webauthn: registration rejects a mismatched rpId", () => {
      let bad = registration_with(registration, rp_id=registration.rp_id + ".evil")
      expect_error_code("rp_id_mismatch", () => {
        subject.verify_registration(bad) |> ignore
      })
    }),
  )
  out.push(
    webauthn_case("webauthn: registration rejects a mismatched challenge", () => {
      let bad = registration_with(
        registration,
        expected_challenge=registration.expected_challenge + "x",
      )
      expect_error_code("challenge_mismatch", () => {
        subject.verify_registration(bad) |> ignore
      })
    }),
  )
  out.push(
    webauthn_case("webauthn: registration rejects a wrong ceremony type", () => {
      let bad = registration_with(
        registration,
        client_data_json=client_data_json(
          "webauthn.get",
          registration.expected_challenge,
          registration.expected_origin,
          false,
        ),
      )
      expect_error_code("type_mismatch", () => {
        subject.verify_registration(bad) |> ignore
      })
    }),
  )
  out.push(
    webauthn_case("webauthn: registration rejects a mismatched origin", () => {
      let bad = registration_with(
        registration,
        client_data_json=client_data_json(
          "webauthn.create",
          registration.expected_challenge,
          "https://evil.example",
          false,
        ),
      )
      expect_error_code("origin_mismatch", () => {
        subject.verify_registration(bad) |> ignore
      })
    }),
  )
  out.push(
    webauthn_case("webauthn: registration rejects a cross-origin clientData", () => {
      let bad = registration_with(
        registration,
        client_data_json=client_data_json(
          "webauthn.create",
          registration.expected_challenge,
          registration.expected_origin,
          true,
        ),
      )
      expect_error_code("cross_origin_rejected", () => {
        subject.verify_registration(bad) |> ignore
      })
    }),
  )

  // —— 认证：正例 ——
  out.push(
    webauthn_case("webauthn: assertion accepts a valid signature", () => {
      let result = subject.verify_assertion(assertion)
      if result.sign_count != fixtures.expected_assertion_sign_count {
        Some(
          "sign_count mismatch: got \{result.sign_count}, expected \{fixtures.expected_assertion_sign_count}",
        )
      } else {
        None
      }
    }),
  )

  // —— 认证：负例 ——
  out.push(
    webauthn_case("webauthn: assertion rejects a tampered signature", () => {
      let bad = assertion_with(assertion, signature=tamper(assertion.signature))
      expect_error_code("signature_invalid", () => {
        subject.verify_assertion(bad) |> ignore
      })
    }),
  )
  out.push(
    webauthn_case("webauthn: assertion rejects a signCount regression", () => {
      // 令存储计数 = 有效向量的实测计数：`received != 0 && received <= stored` 成立。
      let bad = assertion_with(
        assertion,
        stored_sign_count=fixtures.expected_assertion_sign_count,
      )
      expect_error_code("sign_count_regression", () => {
        subject.verify_assertion(bad) |> ignore
      })
    }),
  )
  out.push(
    webauthn_case("webauthn: assertion rejects a wrong ceremony type", () => {
      let bad = assertion_with(
        assertion,
        client_data_json=client_data_json(
          "webauthn.create",
          assertion.expected_challenge,
          assertion.expected_origin,
          false,
        ),
      )
      expect_error_code("type_mismatch", () => {
        subject.verify_assertion(bad) |> ignore
      })
    }),
  )
  out.push(
    webauthn_case("webauthn: assertion rejects a mismatched origin", () => {
      let bad = assertion_with(
        assertion,
        client_data_json=client_data_json(
          "webauthn.get",
          assertion.expected_challenge,
          "https://evil.example",
          false,
        ),
      )
      expect_error_code("origin_mismatch", () => {
        subject.verify_assertion(bad) |> ignore
      })
    }),
  )
  out.push(
    webauthn_case("webauthn: assertion rejects a cross-origin clientData", () => {
      let bad = assertion_with(
        assertion,
        client_data_json=client_data_json(
          "webauthn.get",
          assertion.expected_challenge,
          assertion.expected_origin,
          true,
        ),
      )
      expect_error_code("cross_origin_rejected", () => {
        subject.verify_assertion(bad) |> ignore
      })
    }),
  )

  out
}

// ════════ 内置向量 ════════

///|
/// 挑战（base64url）。
let builtin_challenge : String = "dGVzdC1jaGFsbGVuZ2UtMDAx"

///|
/// 期望来源。
let builtin_origin : String = "https://example.com"

///|
/// Relying Party ID。
let builtin_rp_id : String = "example.com"

///|
/// 内置注册 attestation：`none` 格式，authData flags = 0x45（UP + UV + AT），signCount = 0。
/// （CBOR `{fmt:"none", authData:<…>, attStmt:{}}`，离线生成后硬编码。）
let builtin_registration_attestation_hex : String = "a363666d74646e6f6e6568617574684461746158a4a379a6f6eeafb9a55e378c118034e2751e682fab9f2d30ab13d2125586ce194745000000000102030405060708090a0b0c0d0e0f10002000112233445566778899aabbccddeeff00112233445566778899aabbccddeeffa501020326200121582060fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb62258207903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d44622996761747453746d74a0"

///|
/// 内置认证 authenticatorData：rpIdHash(32) || flags(0x05 = UP+UV) || signCount(5)。
let builtin_assertion_auth_data_hex : String = "a379a6f6eeafb9a55e378c118034e2751e682fab9f2d30ab13d2125586ce19470500000005"

///|
/// 内置认证签名（DER 编码的 ES256）。
let builtin_assertion_signature_hex : String = "30460221009913704ebc8af53e580ac256bdac5cc028b2c9739b2ccbda19ac1e9efb060cf402210088d3f2a17083341e9810ea2fe405fb003051b79204e8f2ccba3ae431150e0d10"

///|
/// 内置凭据公钥（ES256 COSE_Key）。
let builtin_assertion_cose_hex : String = "a501020326200121582060fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb62258207903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"

///|
/// 内置认证 clientDataJSON（**签名覆盖的精确字节**，故须硬编码而非另行合成）。
let builtin_assertion_client_data_hex : String = "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a226447567a6443316a61474673624756755a3255744d444178222c226f726967696e223a2268747470733a2f2f6578616d706c652e636f6d227d"

///|
/// 内置凭据 ID（32 字节）。
let builtin_credential_id_hex : String = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

///|
/// 内置认证签名计数器。
let builtin_assertion_sign_count : Int = 5

///|
/// 组装内置夹具。
fn builtin_fixtures() -> WebAuthnFixtures {
  let registration : @core.RegistrationInput = {
    client_data_json: client_data_json(
      "webauthn.create",
      builtin_challenge,
      builtin_origin,
      false,
    ),
    attestation_object: hex_bytes(builtin_registration_attestation_hex),
    expected_challenge: builtin_challenge,
    expected_origin: builtin_origin,
    rp_id: builtin_rp_id,
  }
  let assertion : @core.AssertionInput = {
    client_data_json: hex_bytes(builtin_assertion_client_data_hex),
    authenticator_data: hex_bytes(builtin_assertion_auth_data_hex),
    signature: hex_bytes(builtin_assertion_signature_hex),
    credential_public_key: hex_bytes(builtin_assertion_cose_hex),
    expected_challenge: builtin_challenge,
    expected_origin: builtin_origin,
    rp_id: builtin_rp_id,
    stored_sign_count: 0,
  }
  {
    registration,
    expected_credential_id: hex_bytes(builtin_credential_id_hex),
    expected_registration_sign_count: 0,
    assertion,
    expected_assertion_sign_count: builtin_assertion_sign_count,
  }
}

// ════════ 用例包装 ════════

///|
/// 执行一条用例：`body` 返回 `None` 通过、`Some(detail)` 失败；
/// `body` 抛出的 `AuthError` 记为「意外错误」用例失败。
fn webauthn_case(
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
/// 断言 `body` 抛出分类码为 `expected` 的 `AuthError`；
/// 未抛错或码不符 → 返回失败原因。
fn expect_error_code(
  expected : String,
  body : () -> Unit raise @core.AuthError,
) -> String? {
  try {
    body()
    Some("expected \"" + expected + "\" but the call unexpectedly succeeded")
  } catch {
    e => {
      let code = @core.auth_error_code(e)
      if code == expected {
        None
      } else {
        Some("expected \"" + expected + "\" but got \"" + code + "\"")
      }
    }
  }
}

// ════════ 夹具变异工具 ════════

///|
/// 复制注册输入并按命名参数覆盖若干字段（未提供者原样保留）。
fn registration_with(
  input : @core.RegistrationInput,
  client_data_json? : Bytes,
  attestation_object? : Bytes,
  expected_challenge? : String,
  expected_origin? : String,
  rp_id? : String,
) -> @core.RegistrationInput {
  {
    client_data_json: client_data_json.unwrap_or(input.client_data_json),
    attestation_object: attestation_object.unwrap_or(input.attestation_object),
    expected_challenge: expected_challenge.unwrap_or(input.expected_challenge),
    expected_origin: expected_origin.unwrap_or(input.expected_origin),
    rp_id: rp_id.unwrap_or(input.rp_id),
  }
}

///|
/// 复制登录输入并按命名参数覆盖若干字段（未提供者原样保留）。
fn assertion_with(
  input : @core.AssertionInput,
  client_data_json? : Bytes,
  authenticator_data? : Bytes,
  signature? : Bytes,
  credential_public_key? : Bytes,
  expected_challenge? : String,
  expected_origin? : String,
  rp_id? : String,
  stored_sign_count? : Int,
) -> @core.AssertionInput {
  {
    client_data_json: client_data_json.unwrap_or(input.client_data_json),
    authenticator_data: authenticator_data.unwrap_or(input.authenticator_data),
    signature: signature.unwrap_or(input.signature),
    credential_public_key: credential_public_key.unwrap_or(
      input.credential_public_key,
    ),
    expected_challenge: expected_challenge.unwrap_or(input.expected_challenge),
    expected_origin: expected_origin.unwrap_or(input.expected_origin),
    rp_id: rp_id.unwrap_or(input.rp_id),
    stored_sign_count: stored_sign_count.unwrap_or(input.stored_sign_count),
  }
}

///|
/// 翻转字节序列首位，制造一个必然验签失败的「篡改签名」。
fn tamper(bytes : Bytes) -> Bytes {
  if bytes.length() == 0 {
    return b"\x00"
  }
  Bytes::makei(bytes.length(), fn(i) {
    if i == 0 {
      (bytes[i].to_int() ^ 0xFF).to_byte()
    } else {
      bytes[i]
    }
  })
}

// ════════ 合成 / 解码工具 ════════

///|
/// 合成一个 `clientDataJSON`（字段顺序与浏览器一致：type / challenge / origin / [crossOrigin]）。
fn client_data_json(
  ceremony_type : String,
  challenge : String,
  origin : String,
  cross_origin : Bool,
) -> Bytes {
  let base = "{\"type\":\"" +
    ceremony_type +
    "\",\"challenge\":\"" +
    challenge +
    "\",\"origin\":\"" +
    origin +
    "\""
  if cross_origin {
    ascii_bytes(base + ",\"crossOrigin\":true}")
  } else {
    ascii_bytes(base + "}")
  }
}

///|
/// ASCII 字符串 → 字节（`clientDataJSON` 全为 ASCII；避免为此引入 `@utf8`）。
fn ascii_bytes(s : String) -> Bytes {
  Bytes::makei(s.length(), fn(i) {
    (s.get_char(i).unwrap().to_int() & 0xFF).to_byte()
  })
}

///|
/// 十六进制字符串 → 字节（用于内置向量；避免为此引入 `@utf8` / 编解码依赖）。
fn hex_bytes(s : String) -> Bytes {
  let n = s.length() / 2
  Bytes::makei(n, fn(i) {
    (hex_nibble(s.get_char(2 * i).unwrap()) * 16 +
      hex_nibble(s.get_char(2 * i + 1).unwrap())).to_byte()
  })
}

///|
/// 单个十六进制字符 → 数值（非法记为 0，仅在已知合法输入上使用）。
fn hex_nibble(c : Char) -> Int {
  let v = c.to_int()
  if v >= 48 && v <= 57 {
    v - 48
  } else if v >= 97 && v <= 102 {
    v - 87
  } else if v >= 65 && v <= 70 {
    v - 55
  } else {
    0
  }
}
