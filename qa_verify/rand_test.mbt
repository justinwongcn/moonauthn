//! moonauth / qa_verify —— rand 默认实现的独立复核（黑盒）。

///|
test "GetrandomSource honors the requested byte count" {
  let src = @rand.GetrandomSource::new()
  @debug.assert_eq(src.bytes(0).length(), 0)
  @debug.assert_eq(src.bytes(1).length(), 1)
  @debug.assert_eq(src.bytes(16).length(), 16)
  @debug.assert_eq(src.bytes(64).length(), 64)
}

///|
test "GetrandomSource produces distinct draws (sanity, not a proof of CSPRNG)" {
  let src = @rand.GetrandomSource::new()
  assert_true(src.bytes(32) != src.bytes(32))
}
