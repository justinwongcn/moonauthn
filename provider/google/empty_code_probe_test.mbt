//! 健壮性回归：空字符串 `code` 必须 fail-closed——
//! 契约 §3.2.5「检查授权码存在且**长度合理**」；此前 `Some("")` 直接通过存在性
//! 检查并发起注定失败的出站 token 请求。

///|
async test "google: empty code is rejected as missing_param" {
  let config = @contract.google_mock_config()
  let secrets : @core.SuppliedSecrets = {
    state: Some("st-123"),
    code_verifier: Some("verifier-1abcdefghijklmnopqrstuvwxyz0123456789-._~"),
    nonce: Some("nonce-1"),
  }
  let start = @google.begin_auth(config, secrets)
  let callback = @core.CallbackParams::from_query_string("code=&state=st-123")
  let code = try {
    let _ = @google.complete_auth(config, callback, start)
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "missing_param")
}
