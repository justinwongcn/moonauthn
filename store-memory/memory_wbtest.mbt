//! moonauth / store-memory —— 白盒测试。
//!
//! 用自带的 `TestClock` 驱动 TTL，验证 `MemoryChallengeStore` 的一次性、过期与
//! 机会式清扫语义（LIB-07）。由于 seam `ChallengeStore` 为 async，测试一律写成
//! `async test`。

///|
/// 可手动推进的测试时钟。
priv struct TestClock {
  mut now : Int64
}

///|
impl @core.Clock for TestClock with fn now_unix(self) {
  self.now
}

///|
async test "take is one-shot and consumes the entry" {
  let clock : TestClock = { now: 1000L }
  let store = MemoryChallengeStore::new(clock)
  store.put("k", "v", 60)
  @debug.assert_eq(store.peek("k"), Some("v"))
  @debug.assert_eq(store.take("k"), Some("v"))
  // 二次 take 必为 None（取后即失效）
  @debug.assert_eq(store.take("k"), None)
  // 已消费，peek 亦为 None
  @debug.assert_eq(store.peek("k"), None)
}

///|
async test "entries expire according to TTL" {
  let clock : TestClock = { now: 1000L }
  let store = MemoryChallengeStore::new(clock)
  store.put("k", "v", 60)
  @debug.assert_eq(store.peek("k"), Some("v"))
  clock.now = clock.now + 59L
  @debug.assert_eq(store.peek("k"), Some("v"))
  clock.now = clock.now + 1L
  // 恰好到期即视为过期
  @debug.assert_eq(store.peek("k"), None)
  @debug.assert_eq(store.take("k"), None)
}

///|
async test "put overwrites and unknown keys are None" {
  let clock : TestClock = { now: 500L }
  let store = MemoryChallengeStore::new(clock)
  @debug.assert_eq(store.take("missing"), None)
  @debug.assert_eq(store.peek("missing"), None)
  store.put("k", "v1", 10)
  store.put("k", "v2", 10)
  @debug.assert_eq(store.peek("k"), Some("v2"))
}

///|
async test "zero ttl is immediately expired" {
  let clock : TestClock = { now: 42L }
  let store = MemoryChallengeStore::new(clock)
  store.put("k", "v", 0)
  @debug.assert_eq(store.peek("k"), None)
  @debug.assert_eq(store.take("k"), None)
}

///|
/// 机会式清扫：某个 key 写入后**既不被 `take` 也不被复用**时，早期实现会永久驻留；
/// 现在 `put` 每累计 `SWEEP_INTERVAL` 次会触发全量清扫，过期条目不再残留。
async test "put triggers opportunistic sweep and expired entries do not linger" {
  let clock : TestClock = { now: 1000L }
  let store = MemoryChallengeStore::new(clock)
  // 写入一条短 TTL 的条目（后不再 take / 复用）
  store.put("victim", "v", 1) // expires_at = 1001
  @debug.assert_eq(store.values.length(), 1)
  // 时间推进到过期之后
  clock.now = 2000L
  // 仍留在内存里（尚未触发清扫）
  @debug.assert_eq(store.expiries.length(), 1)
  // 持续写入以跨越清扫阈值（其余条目的 TTL 很长，不会被误删）
  for i = 0; i < 16; i = i + 1 {
    store.put("k\{i}", "x", 100000)
  }
  // 清扫已发生：victim 从两张 Map 中都消失
  @debug.assert_eq(store.values.get("victim"), None)
  @debug.assert_eq(store.expiries.get("victim"), None)
  // 未过期的条目仍在（16 条新条目；victim 已被回收）
  @debug.assert_eq(store.values.length(), 16)
  @debug.assert_eq(store.expiries.length(), 16)
}

///|
/// 清扫不应误删未过期条目。
async test "opportunistic sweep never removes fresh entries" {
  let clock : TestClock = { now: 0L }
  let store = MemoryChallengeStore::new(clock)
  for i = 0; i < 32; i = i + 1 {
    store.put("fresh\{i}", "v", 1000)
  }
  // 32 次写入已触发清扫，但全部条目仍在有效期内
  @debug.assert_eq(store.values.length(), 32)
  @debug.assert_eq(store.expiries.length(), 32)
  @debug.assert_eq(store.peek("fresh31"), Some("v"))
}
