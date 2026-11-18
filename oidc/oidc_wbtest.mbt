//! 白盒单测：`check_azp` 双条款契约（provider 无关——`IdTokenVerifier` seam 的
//! 全部消费者 google/apple/microsoft 共享本契约）。
//!
//! 黑客审计 F13（多受众 azp 缺失）+ OCR 审查（azp ∉ token aud 声明 / 单值 aud +
//! 外部 azp / raw `aud` 数组非字符串元素）的对应回归。

///|
fn wb_claims(json_text : String) -> Map[String, Json] raise @core.AuthError {
  let parsed : Json = @json.parse(json_text) catch {
    _ => raise @core.ParseError("moonauth: wb_claims input is not valid JSON")
  }
  match parsed {
    Object(m) => m
    _ => raise @core.ParseError("moonauth: wb_claims input is not a JSON object")
  }
}

///|
test "check_azp: multi-aud without azp is rejected" {
  let claims = wb_claims(
    "{\"aud\":[\"client-1\",\"other\"],\"sub\":\"u\"}",
  )
  let outcome = try {
    check_azp(claims, ["client-1"])
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(outcome, "audience_mismatch")
}

///|
/// 🔴 azp ∈ 期望受众集合，但**不在 token 自身的 aud 声明**里 → 拒绝（两集合不可互换）。
test "check_azp: azp outside the token aud claim is rejected even if expected" {
  let claims = wb_claims(
    "{\"aud\":[\"client-1\",\"client-3\"],\"azp\":\"client-2\",\"sub\":\"u\"}",
  )
  let outcome = try {
    check_azp(claims, ["client-1", "client-2"])
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(outcome, "audience_mismatch")
}

///|
test "check_azp: azp within aud claim and expectations passes" {
  let claims = wb_claims(
    "{\"aud\":[\"client-1\",\"other-resource\"],\"azp\":\"client-1\",\"sub\":\"u\"}",
  )
  let outcome = try {
    check_azp(claims, ["client-1"])
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(outcome, "no-error")
}

///|
test "check_azp: single-aud with foreign azp is rejected" {
  let claims = wb_claims(
    "{\"aud\":\"client-1\",\"azp\":\"attacker-client\",\"sub\":\"u\"}",
  )
  let outcome = try {
    check_azp(claims, ["client-1"])
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(outcome, "audience_mismatch")
}

///|
/// 单值 aud 无 azp → 放行（Google/Entra 单资源形态，向后兼容）。
test "check_azp: single-aud without azp passes (backward compatible)" {
  let claims = wb_claims("{\"aud\":\"client-1\",\"sub\":\"u\"}")
  let outcome = try {
    check_azp(claims, ["client-1"])
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(outcome, "no-error")
}

///|
/// 🔴 raw `aud` 数组含非字符串元素 → `ParseError`（fail-closed，不得静默丢弃）。
test "check_azp: non-string element in aud array is parse_error" {
  let claims = wb_claims(
    "{\"aud\":[\"client-1\",42],\"azp\":\"client-1\",\"sub\":\"u\"}",
  )
  let outcome = try {
    check_azp(claims, ["client-1"])
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(outcome, "parse_error")
}

///|
/// 无 `aud` 声明（OIDC 中非法，mooncred 受众阶段会先拒绝；此处验证 check_azp 的
/// fail-closed 兜底）：azp 无法落在 aud 声明内 → 仍 `audience_mismatch`。
test "check_azp: missing aud claim is fail-closed (audience_mismatch)" {
  let claims = wb_claims("{\"azp\":\"client-1\",\"sub\":\"u\"}")
  let outcome = try {
    check_azp(claims, ["client-1"])
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(outcome, "audience_mismatch")
}
