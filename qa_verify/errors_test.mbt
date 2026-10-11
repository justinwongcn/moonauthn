//! moonauth / qa_verify —— AuthError 穷尽性、分类码唯一性、映射助手确定性。

///|
/// 26 个变体的实例数组（与 core/errors.mbt 一一对应）。
fn all_error_variants() -> Array[@core.AuthError] {
  [
    @core.Network("x"),
    @core.HttpStatus(500, "y"),
    @core.MissingParam("code"),
    @core.StateMismatch,
    @core.NonceMismatch,
    @core.ChallengeNotFound,
    @core.ChallengeExpired,
    @core.ChallengeAlreadyUsed,
    @core.ChallengeMismatch,
    @core.SignatureInvalid,
    @core.TokenExpired,
    @core.TokenNotYetValid,
    @core.IssuerMismatch("a", "b"),
    @core.AudienceMismatch("a", "b"),
    @core.UnsupportedAlg("HS256"),
    @core.KeyError("k"),
    @core.OriginMismatch("a", "b"),
    @core.RpIdMismatch,
    @core.CrossOriginRejected,
    @core.SignCountRegression(1, 0),
    @core.TypeMismatch("a", "b"),
    @core.ProviderError("40029", "bad"),
    @core.ParseError("bad"),
    @core.InvalidInput("short"),
    @core.RandomUnavailable,
    @core.Unsupported("nope"),
  ]
}

///|
/// 跨包穷尽 match：**不含 `_` 兜底**。能编译通过 = 编译期证明
/// `pub(all) suberror` 的全部变体对下游可见且可穷尽覆盖。
fn qa_classify(err : @core.AuthError) -> String {
  match err {
    Network(_) => "a"
    HttpStatus(_, _) => "b"
    MissingParam(_) => "c"
    StateMismatch => "d"
    NonceMismatch => "e"
    ChallengeNotFound => "f"
    ChallengeExpired => "g"
    ChallengeAlreadyUsed => "h"
    ChallengeMismatch => "i"
    SignatureInvalid => "j"
    TokenExpired => "k"
    TokenNotYetValid => "l"
    IssuerMismatch(_, _) => "m"
    AudienceMismatch(_, _) => "n"
    UnsupportedAlg(_) => "o"
    KeyError(_) => "p"
    OriginMismatch(_, _) => "q"
    RpIdMismatch => "r"
    CrossOriginRejected => "s"
    SignCountRegression(_, _) => "t"
    TypeMismatch(_, _) => "u"
    ProviderError(_, _) => "v"
    ParseError(_) => "w"
    InvalidInput(_) => "x"
    RandomUnavailable => "y"
    Unsupported(_) => "z"
  }
}

///|
test "cross-package exhaustive match compiles and covers all variants" {
  let variants = all_error_variants()
  @debug.assert_eq(variants.length(), 26)
  // 全变体都能被无兜底 match 分类，且分类两两不同（26 条分支互不相同）
  let seen : Map[String, Unit] = Map([])
  for v in variants {
    seen[qa_classify(v)] = ()
  }
  @debug.assert_eq(seen.length(), 26)
}

///|
test "every variant maps to a distinct, non-empty code" {
  let variants = all_error_variants()
  let codes : Array[String] = []
  for v in variants {
    let c = @core.auth_error_code(v)
    assert_true(c.length() > 0)
    codes.push(c)
  }
  // O(n^2) 去重检查：任何两个变体的 code 都不允许相等
  let mut duplicates = 0
  for i = 0; i < codes.length(); i = i + 1 {
    for j = i + 1; j < codes.length(); j = j + 1 {
      if codes[i] == codes[j] {
        duplicates = duplicates + 1
      }
    }
  }
  @debug.assert_eq(duplicates, 0)
  @debug.assert_eq(codes.length(), 26)
}

///|
test "every variant maps to a non-empty message" {
  for v in all_error_variants() {
    assert_true(@core.auth_error_message(v).length() > 0)
  }
}

///|
test "auth_from_jwt_reason: documented mappings + determinism" {
  @debug.assert_eq(@core.auth_error_code(@core.auth_from_jwt_reason("exp", "", "")), "token_expired")
  @debug.assert_eq(@core.auth_error_code(@core.auth_from_jwt_reason("nbf", "", "")), "token_not_yet_valid")
  @debug.assert_eq(@core.auth_error_code(@core.auth_from_jwt_reason("iss", "a", "b")), "issuer_mismatch")
  @debug.assert_eq(@core.auth_error_code(@core.auth_from_jwt_reason("aud", "a", "b")), "audience_mismatch")
  @debug.assert_eq(@core.auth_error_code(@core.auth_from_jwt_reason("alg", "HS256", "")), "unsupported_alg")
  @debug.assert_eq(@core.auth_error_code(@core.auth_from_jwt_reason("sig", "", "")), "signature_invalid")
  // 确定性：同输入两次结果一致
  @debug.assert_eq(
    @core.auth_error_message(@core.auth_from_jwt_reason("iss", "a", "b")),
    @core.auth_error_message(@core.auth_from_jwt_reason("iss", "a", "b")),
  )
}

///|
test "auth_from_jwt_reason: 'typ' now maps to UnsupportedAlg (ARCH §4.3 aligned)" {
  // 修订前该用例固化的是「typ → type_mismatch」（与 error_map 注释 / ARCH §4.3 不符）。
  // 本次修订后实现对齐 ARCH：typ → UnsupportedAlg。
  @debug.assert_eq(@core.auth_error_code(@core.auth_from_jwt_reason("typ", "a", "b")), "unsupported_alg")
}

///|
test "auth_from_jwt_reason: boundary inputs (empty / very long) do not crash" {
  @debug.assert_eq(@core.auth_error_code(@core.auth_from_jwt_reason("", "", "")), "parse_error")
  let sb = StringBuilder()
  for i = 0; i < 5000; i = i + 1 {
    sb.write_string("z")
  }
  let long = sb.to_string()
  assert_true(long.length() >= 5000)
  @debug.assert_eq(@core.auth_error_code(@core.auth_from_jwt_reason(long, "a", "b")), "parse_error")
}

///|
test "auth_network_from / auth_parse_from are deterministic and non-empty" {
  let n1 = @core.auth_network_from(@core.Network("boom"))
  let n2 = @core.auth_network_from(@core.Network("boom"))
  @debug.assert_eq(@core.auth_error_code(n1), "network")
  @debug.assert_eq(@core.auth_error_message(n1), @core.auth_error_message(n2))
  assert_true(@core.auth_error_message(n1).length() > 0)
  let p1 = @core.auth_parse_from(@core.ParseError("bad"))
  @debug.assert_eq(@core.auth_error_code(p1), "parse_error")
  assert_true(@core.auth_error_message(p1).length() > 0)
  // 空描述也不应产生空消息
  let n3 = @core.auth_network_from(@core.Network(""))
  assert_true(@core.auth_error_message(n3).length() > 0)
}
