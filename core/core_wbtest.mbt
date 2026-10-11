//! moonauth / core —— 白盒测试（可访问包内私有 helper）。

///|
test "percent_decode handles percent, plus and passthrough" {
  @debug.assert_eq(percent_decode("a%20b"), "a b")
  @debug.assert_eq(percent_decode("a+b"), "a b")
  @debug.assert_eq(percent_decode("%E4%BD%A0%E5%A5%BD"), "你好")
  @debug.assert_eq(percent_decode("100%"), "100%")
  @debug.assert_eq(percent_decode("%2"), "%2")
  @debug.assert_eq(percent_decode(""), "")
}

///|
test "parse_urlencoded splits pairs and tolerates missing values" {
  let m = parse_urlencoded("code=abc&state=xyz&empty=&flag")
  @debug.assert_eq(m.get("code"), Some("abc"))
  @debug.assert_eq(m.get("state"), Some("xyz"))
  @debug.assert_eq(m.get("empty"), Some(""))
  @debug.assert_eq(m.get("flag"), Some(""))
  @debug.assert_eq(m.get("missing"), None)
}

///|
test "provider table is complete and consistent" {
  let ids = provider_ids()
  @debug.assert_eq(ids.length(), 6)
  @debug.assert_eq(ids[0], "google")
  @debug.assert_eq(ids[1], "apple")
  @debug.assert_eq(ids[2], "wechat")
  @debug.assert_eq(ids[3], "qq")
  @debug.assert_eq(ids[4], "alipay")
  @debug.assert_eq(ids[5], "x")
  for d in all_providers() {
    assert_true(d.doc_url.length() > 0)
    assert_true(d.display_name.length() > 0)
  }
}

///|
test "platform capability flags match the design table" {
  match provider_descriptor("wechat") {
    Some(d) => {
      assert_false(d.supports_pkce)
      assert_false(d.supports_id_token)
    }
    None => abort("wechat descriptor missing")
  }
  match provider_descriptor("qq") {
    Some(d) => assert_false(d.supports_id_token)
    None => abort("qq descriptor missing")
  }
  match provider_descriptor("alipay") {
    Some(d) => assert_false(d.supports_pkce)
    None => abort("alipay descriptor missing")
  }
  match provider_descriptor("google") {
    Some(d) => {
      assert_true(d.supports_pkce)
      assert_true(d.supports_id_token)
    }
    None => abort("google descriptor missing")
  }
  match provider_descriptor("apple") {
    Some(d) => assert_true(d.supports_id_token)
    None => abort("apple descriptor missing")
  }
  match provider_descriptor("x") {
    Some(d) => {
      assert_true(d.supports_pkce)
      assert_false(d.supports_id_token)
    }
    None => abort("x descriptor missing")
  }
  assert_true(provider_descriptor("unknown") is None)
}

///|
test "auth error codes cover every variant" {
  @debug.assert_eq(auth_error_code(Network("boom")), "network")
  @debug.assert_eq(auth_error_code(HttpStatus(500, "x")), "http_status")
  @debug.assert_eq(auth_error_code(MissingParam("code")), "missing_param")
  @debug.assert_eq(auth_error_code(StateMismatch), "state_mismatch")
  @debug.assert_eq(auth_error_code(NonceMismatch), "nonce_mismatch")
  @debug.assert_eq(auth_error_code(ChallengeNotFound), "challenge_not_found")
  @debug.assert_eq(auth_error_code(ChallengeExpired), "challenge_expired")
  @debug.assert_eq(auth_error_code(ChallengeAlreadyUsed), "challenge_already_used")
  @debug.assert_eq(auth_error_code(ChallengeMismatch), "challenge_mismatch")
  @debug.assert_eq(auth_error_code(SignatureInvalid), "signature_invalid")
  @debug.assert_eq(auth_error_code(TokenExpired), "token_expired")
  @debug.assert_eq(auth_error_code(TokenNotYetValid), "token_not_yet_valid")
  @debug.assert_eq(auth_error_code(IssuerMismatch("a", "b")), "issuer_mismatch")
  @debug.assert_eq(auth_error_code(AudienceMismatch("a", "b")), "audience_mismatch")
  @debug.assert_eq(auth_error_code(UnsupportedAlg("HS256")), "unsupported_alg")
  @debug.assert_eq(auth_error_code(KeyError("k")), "key_error")
  @debug.assert_eq(auth_error_code(OriginMismatch("a", "b")), "origin_mismatch")
  @debug.assert_eq(auth_error_code(RpIdMismatch), "rp_id_mismatch")
  @debug.assert_eq(auth_error_code(CrossOriginRejected), "cross_origin_rejected")
  @debug.assert_eq(auth_error_code(SignCountRegression(5, 3)), "sign_count_regression")
  @debug.assert_eq(auth_error_code(TypeMismatch("a", "b")), "type_mismatch")
  @debug.assert_eq(auth_error_code(ProviderError("40029", "bad")), "provider_error")
  @debug.assert_eq(auth_error_code(ParseError("bad json")), "parse_error")
  @debug.assert_eq(auth_error_code(InvalidInput("short")), "invalid_input")
  @debug.assert_eq(auth_error_code(RandomUnavailable), "random_unavailable")
  @debug.assert_eq(auth_error_code(Unsupported("nope")), "unsupported")
  assert_true(auth_error_message(Unsupported("nope")).length() > 0)
}

///|
test "error_map helpers produce the expected variants" {
  @debug.assert_eq(auth_error_code(auth_network("x")), "network")
  @debug.assert_eq(auth_error_code(auth_http_status(503, "down")), "http_status")
  @debug.assert_eq(auth_error_code(auth_parse("bad")), "parse_error")
  @debug.assert_eq(auth_error_code(auth_signature_invalid()), "signature_invalid")
  @debug.assert_eq(auth_error_code(auth_token_expired()), "token_expired")
  @debug.assert_eq(auth_error_code(auth_token_not_yet_valid()), "token_not_yet_valid")
  @debug.assert_eq(auth_error_code(auth_issuer_mismatch("a", "b")), "issuer_mismatch")
  @debug.assert_eq(auth_error_code(auth_audience_mismatch("a", "b")), "audience_mismatch")
  @debug.assert_eq(auth_error_code(auth_unsupported_alg("HS256")), "unsupported_alg")
  @debug.assert_eq(auth_error_code(auth_key_error("k")), "key_error")
  @debug.assert_eq(auth_error_code(auth_origin_mismatch("a", "b")), "origin_mismatch")
  @debug.assert_eq(auth_error_code(auth_rp_id_mismatch()), "rp_id_mismatch")
  @debug.assert_eq(auth_error_code(auth_cross_origin_rejected()), "cross_origin_rejected")
  @debug.assert_eq(auth_error_code(auth_sign_count_regression(5, 3)), "sign_count_regression")
  @debug.assert_eq(auth_error_code(auth_type_mismatch("a", "b")), "type_mismatch")
  @debug.assert_eq(auth_error_code(auth_challenge_not_found()), "challenge_not_found")
  @debug.assert_eq(auth_error_code(auth_challenge_expired()), "challenge_expired")
  @debug.assert_eq(auth_error_code(auth_challenge_already_used()), "challenge_already_used")
  @debug.assert_eq(auth_error_code(auth_challenge_mismatch()), "challenge_mismatch")
  @debug.assert_eq(auth_error_code(auth_provider_error("40029", "bad")), "provider_error")
  @debug.assert_eq(auth_error_code(auth_invalid_input("short")), "invalid_input")
  @debug.assert_eq(auth_error_code(auth_random_unavailable()), "random_unavailable")
  @debug.assert_eq(auth_error_code(auth_unsupported("nope")), "unsupported")
  @debug.assert_eq(auth_error_code(auth_missing_param("code")), "missing_param")
  @debug.assert_eq(auth_error_code(auth_state_mismatch()), "state_mismatch")
  @debug.assert_eq(auth_error_code(auth_nonce_mismatch()), "nonce_mismatch")
}

///|
test "jwt rejection reasons map to the documented AuthError" {
  @debug.assert_eq(auth_error_code(auth_from_jwt_reason("exp", "", "")), "token_expired")
  @debug.assert_eq(auth_error_code(auth_from_jwt_reason("nbf", "", "")), "token_not_yet_valid")
  @debug.assert_eq(auth_error_code(auth_from_jwt_reason("iss", "a", "b")), "issuer_mismatch")
  @debug.assert_eq(auth_error_code(auth_from_jwt_reason("aud", "a", "b")), "audience_mismatch")
  @debug.assert_eq(auth_error_code(auth_from_jwt_reason("alg", "HS256", "")), "unsupported_alg")
  @debug.assert_eq(auth_error_code(auth_from_jwt_reason("typ", "a", "b")), "unsupported_alg")
  @debug.assert_eq(auth_error_code(auth_from_jwt_reason("sig", "", "")), "signature_invalid")
  @debug.assert_eq(auth_error_code(auth_from_jwt_reason("other", "", "")), "parse_error")
}

///|
test "system clock returns a plausible unix timestamp" {
  let clock = SystemClock::new()
  let now = clock.now_unix()
  assert_true(now > 1_600_000_000L)
}

///|
/// 锁定「自定义响应头能透传」：`map_response_headers` 必须把 `@http` 的大小写不敏感键
/// 逐一映射为库自有的 `Map[String, String]`，且**保持键的原样大小写**、值不变。
/// 这是 `provider/qq` 按 `content-type` 判断响应体形态（form-encoded vs JSON）的前提。
test "response header mapping preserves custom headers verbatim" {
  let upstream : Map[@http.CaseInsensitiveString, String] = Map([
    (@http.CaseInsensitiveString("Content-Type"), "application/x-www-form-urlencoded"),
    (@http.CaseInsensitiveString("X-Custom-Header"), "abc"),
    (@http.CaseInsensitiveString("X-Trace-Id"), "0123"),
  ])
  let mapped = map_response_headers(upstream)
  @debug.assert_eq(mapped.length(), 3)
  @debug.assert_eq(
    mapped.get("Content-Type"),
    Some("application/x-www-form-urlencoded"),
  )
  @debug.assert_eq(mapped.get("X-Custom-Header"), Some("abc"))
  @debug.assert_eq(mapped.get("X-Trace-Id"), Some("0123"))
  // 不存在的键为 None
  @debug.assert_eq(mapped.get("X-Absent"), None)
}

///|
/// 空响应头集合映射为空 Map（不 panic）。
test "response header mapping handles an empty header set" {
  let upstream : Map[@http.CaseInsensitiveString, String] = Map([])
  let mapped = map_response_headers(upstream)
  @debug.assert_eq(mapped.length(), 0)
}

///|
test "default I/O implementations can be constructed" {
  let http = AsyncHttpClient::new()
  let _ = http
  let http2 = AsyncHttpClient::new(timeout_ms=5000)
  let _ = http2
}
