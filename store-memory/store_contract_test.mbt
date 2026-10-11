//! moonauth / store-memory —— `MemoryChallengeStore` 过 `ChallengeStore` 参数化契约。

///|
/// 🔴 库自带实现必须 100% 通过 `ChallengeStore` 契约（一次性 / peek 不消费 /
/// TTL 边界 / 覆盖写 / 键隔离）；下游自写实现（Redis 等）复跑同一套断言即可。
async test "ChallengeStore contract: MemoryChallengeStore passes every case" {
  let clock : &@core.Clock = @contract.FixedClock::new(@contract.fixed_now_unix())
  let cases = @contract.run_store(() => {
    let subject : &@core.ChallengeStore = @store_memory.MemoryChallengeStore::new(clock)
    subject
  })
  @contract.assert_all_pass(cases)
}
