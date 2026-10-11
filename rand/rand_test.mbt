//! moonauth / rand —— 黑盒测试。

///|
test "GetrandomSource returns the requested number of bytes" {
  let src = @rand.GetrandomSource::new()
  @debug.assert_eq(src.bytes(0).length(), 0)
  @debug.assert_eq(src.bytes(1).length(), 1)
  @debug.assert_eq(src.bytes(16).length(), 16)
  @debug.assert_eq(src.bytes(32).length(), 32)
}

///|
test "GetrandomSource draws are effectively never equal" {
  let src = @rand.GetrandomSource::new()
  assert_true(src.bytes(32) != src.bytes(32))
}
