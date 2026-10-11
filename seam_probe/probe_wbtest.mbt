//! 白盒测试：验证 core 的 seam 可被外部包实现（SDK-01 可替换性）。
//! `drive` 为 async，故测试写成 `async test`。

///|
async test "seam 跨包实现可用（SDK-01 可替换性）" {
  let out = drive(MyHttp::new(), MyClock::new(), MyVerifier::new()) catch {
    _ => "err"
  }
  assert_eq(out, "official-sub{\"ok\":true}1700000000")
}

///|
/// 契约证据：`ChallengeStore` 声明 `raise AuthError` 后，调用方能把**存储故障**
/// 与「值不存在」区分开——故障被捕获为 `AuthError`（`"network"`），
/// 而正常实现的「不存在」仍是 `None`（`"absent"`）。二者绝不混淆。
async test "ChallengeStore failure is a catchable AuthError, distinct from None" {
  // 故障存储 → 捕获到 AuthError(network)
  assert_eq(take_code(MyFailingStore::new(), "k"), "network")
  // 正常存储 + 不存在的键 → 成功语义的 None
  assert_eq(take_code(MyStore::new(), "absent-key"), "absent")
}
