//! 健壮性回归：空 openid 视为缺失（契约 §2.2 subject 非空）。

///|
test "qq: empty openid in me response is rejected" {
  let code = try {
    let _ = @qq.qq_parse_openid("callback( {\"openid\":\"\"} );", "appid")
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "parse_error")
}
