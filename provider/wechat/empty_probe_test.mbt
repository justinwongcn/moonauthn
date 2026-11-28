//! 健壮性回归：空 openid 视为缺失；空 uid 兜底防线。

///|
test "wechat: empty openid in token response is rejected" {
  let code = try {
    let _ = @wechat.wechat_parse_token("{\"access_token\":\"at\",\"openid\":\"\"}")
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "parse_error")
}

///|
/// 双空兜底：unionid/openid 均空串时不得产出空 uid 身份（identity 层防线）。
test "wechat: empty unionid and openid cannot produce an empty uid" {
  let outcome = try {
    let identity = @wechat.wechat_identity("{\"nickname\":\"n\"}", "")
    "uid=[" + identity.uid + "]"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(outcome, "parse_error")
}
