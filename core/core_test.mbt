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
  @debug.assert_eq(@core.provider_ids().length(), 10)
  @debug.assert_eq(@core.all_providers().length(), 10)
}

///|
test "auth error code helper is public" {
  @debug.assert_eq(@core.auth_error_code(@core.RandomUnavailable), "random_unavailable")
}
