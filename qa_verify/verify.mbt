//! moonauth / qa_verify —— T01 独立验证包（QA 严过关）。
//!
//! 本包**不修改**任何既有子包，仅通过公开 API 对 T01 交付物做对抗性验证。
//! T01 修订后 I/O 相关 seam 均为 async，故本包的测试多为 `async test`。

///|
/// 占位符号，确保本包存在非测试文件。
pub fn qa_verify_marker() -> String {
  "qa_verify"
}

// ════════ 存储故障语义回归件 ════════

///|
/// 必定失败的 `ChallengeStore` 实现（模拟 Redis 等远程存储不可用）。
/// 用于验证：基础设施故障必须经 seam **抛出**，而**不能**被降级成 `None`
/// （否则会把「存储不可用」伪装成「challenge 不存在」）。
///
/// 注意：本实现之所以能编译，说明 `ChallengeStore` 实现**可以** raise；
/// 但 `ChallengeStore` trait 本身**未声明** `raise AuthError`（与 `HttpClient` 等不一致），
/// 因此调用方 `catch` 到的静态类型是 `Error` 而非 `AuthError`。
pub(all) struct FailingStore {}

///|
pub fn FailingStore::new() -> FailingStore {
  FailingStore::{}
}

///|
pub impl @core.ChallengeStore for FailingStore with fn put(self, key, value, ttl_seconds) {
  let _ = self
  let _ = key
  let _ = value
  let _ = ttl_seconds
  raise @core.Network("qa_verify: store down")
}

///|
pub impl @core.ChallengeStore for FailingStore with fn take(self, key) {
  let _ = self
  let _ = key
  raise @core.Network("qa_verify: store down")
}

///|
pub impl @core.ChallengeStore for FailingStore with fn peek(self, key) {
  let _ = self
  let _ = key
  raise @core.Network("qa_verify: store down")
}

///|
pub extend FailingStore with @core.ChallengeStore::{peek, put, take}
