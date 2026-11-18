//! moonauth / core —— 黑盒测试（仅经公开 API）。

///|
test "callback params parse a query string through the public API" {
  let cb = @core.CallbackParams::from_query_string("code=abc&state=st&flag")
  @debug.assert_eq(cb.get("code"), Some("abc"))
  @debug.assert_eq(cb.get("state"), Some("st"))
  @debug.assert_eq(cb.get("flag"), Some(""))
  @debug.assert_eq(cb.get("none"), None)
}

///|
test "callback params from form body and from pairs" {
  let fb = @core.CallbackParams::from_form_body("id_token=xyz&code=1")
  @debug.assert_eq(fb.get("id_token"), Some("xyz"))
  @debug.assert_eq(fb.get("code"), Some("1"))
  let pb = @core.CallbackParams::from_pairs(Map([("k", "v")]))
  @debug.assert_eq(pb.get("k"), Some("v"))
}

///|
test "provider descriptors are queryable through the public API" {
  match @core.provider_descriptor("google") {
    Some(d) => {
      @debug.assert_eq(d.id, "google")
      @debug.assert_eq(d.display_name, "Google")
      assert_true(d.supports_id_token)
    }
    None => abort("google descriptor missing")
  }
  @debug.assert_eq(@core.provider_ids().length(), 11)
  @debug.assert_eq(@core.all_providers().length(), 11)
}

///|
test "auth error code helper is public" {
  @debug.assert_eq(@core.auth_error_code(@core.RandomUnavailable), "random_unavailable")
}

// ════════ 回调错误参数（provider_error）════════

///|
/// `error` + `error_description` → `ProviderError(error, 描述)`。
test "callback error params yield provider_error" {
  let cb = @core.CallbackParams::from_query_string(
    "error=access_denied&error_description=user%20denied&state=st",
  )
  match cb.provider_error() {
    Some(@core.ProviderError(code, msg)) => {
      @debug.assert_eq(code, "access_denied")
      @debug.assert_eq(msg, "user denied")
    }
    _ => abort("expected ProviderError")
  }
}

///|
/// `error_uri` 出现时并入消息（GitHub 形态）。
test "callback error_uri is folded into the message" {
  let cb = @core.CallbackParams::from_query_string(
    "error=verification_failed&error_description=bad%20sig&error_uri=https://docs.example/e",
  )
  match cb.provider_error() {
    Some(@core.ProviderError(code, msg)) => {
      @debug.assert_eq(code, "verification_failed")
      @debug.assert_eq(msg, "bad sig; https://docs.example/e")
    }
    _ => abort("expected ProviderError")
  }
}

///|
/// 无 `error` / `error` 为空串 → `None`（不误伤正常成功回调）。
test "callback without error params yields None" {
  let ok = @core.CallbackParams::from_query_string("code=c&state=st")
  match ok.provider_error() {
    None => ()
    Some(_) => abort("expected None for a callback without error params")
  }
  let empty = @core.CallbackParams::from_query_string("error=&state=st")
  match empty.provider_error() {
    None => ()
    Some(_) => abort("expected None for an empty error param")
  }
}
