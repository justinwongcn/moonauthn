//! moonauth / store-memory —— 默认 `ChallengeStore` 实现：`MemoryChallengeStore`。
//!
//! 纯内存实现：两个 `Map` + 注入的 `Clock`。TTL 语义来自 `Clock`，因此测试可注入
//! 固定时钟做确定性重放。
//!
//! 一次性语义（LIB-07）：
//! - `take` **取后即失效**：同一 key 二次 `take` 必为 `None`；
//! - 过期条目视为 `None`；
//! - `peek` 只读、不消费。
//!
//! 🔴 seam `ChallengeStore` 现为 async，故本实现的方法签名一律 `async`（实现侧写
//! `with fn`）。内部没有任何真正的异步操作：内存访问是同步的，直接返回即可，
//! 但签名必须与 trait 对齐，以便下游用 Redis / 数据库等**异步存储**替换。
//!
//! 内存回收：过期条目在 `take` 时被清理；此外 `put` 会**机会式**触发全量清扫
//! （见 `SWEEP_INTERVAL` 与 `sweep_expired`），避免长驻进程因「只写不取」的 key
//! 无界增长。

///|
/// 两次全量清扫之间累计的 `put` 次数阈值。
///
/// **取舍**：全量清扫是 O(n)；若每次 `put` 都扫，高频写入时开销失控；若永不扫，
/// 长驻进程会无界增长。这里采用**摊销（amortized）周期清扫**——
/// 每 `SWEEP_INTERVAL` 次 `put` 触发一次全量清扫：
/// - 每次 `put` 的**平均**清扫成本降到 O(n / SWEEP_INTERVAL)；
/// - 只要持续写入，过期条目**终会被回收**（不会永久驻留）；
/// - 写入停止时残留量被「已写入条目数」上界，不随时间增长。
///
/// 取 16 是在「清扫及时性」与「摊销开销」之间的折中：单次 `put` 的清扫均摊为
/// 约 1/16 次全表扫描，对典型 challenge 规模（数百条）而言可忽略。
const SWEEP_INTERVAL : Int = 16

///|
/// 默认 `ChallengeStore` 实现（进程内 `Map` + 注入 `Clock`）。
///
/// 内部用两张标准 `Map` 分别保存「值」与「绝对过期时刻（Unix 秒）」，
/// 因此公开定义不依赖任何私有类型。`puts_since_sweep` 用于摊销式机会清扫。
pub struct MemoryChallengeStore {
  clock : &@core.Clock
  values : Map[String, String]
  expiries : Map[String, Int64]
  mut puts_since_sweep : Int
}

///|
/// 以注入的 `Clock` 构造。
pub fn MemoryChallengeStore::new(clock : &@core.Clock) -> MemoryChallengeStore {
  { clock: clock, values: Map([]), expiries: Map([]), puts_since_sweep: 0 }
}

///|
/// 判断 key 是否已过期（`now >= expires_at` 即过期，因此 `ttl = 0` 立即失效；
/// 缺失的过期记录视为已过期）。
fn MemoryChallengeStore::is_expired(self : MemoryChallengeStore, key : String) -> Bool {
  match self.expiries.get(key) {
    Some(expires_at) => self.clock.now_unix() >= expires_at
    None => true
  }
}

///|
/// 机会式全量清扫：移除**所有**已过期条目（`now >= expires_at`）。
///
/// 实现要点：先遍历 `expiries` 收集待删键，再统一删除，避免在遍历 `Map` 的同时修改它。
/// 清扫后把 `puts_since_sweep` 归零，开始下一个摊销周期。
fn MemoryChallengeStore::sweep_expired(self : MemoryChallengeStore) -> Unit {
  let now = self.clock.now_unix()
  let stale : Array[String] = []
  for key, expires_at in self.expiries {
    if now >= expires_at {
      stale.push(key)
    }
  }
  for key in stale {
    self.values.remove(key)
    self.expiries.remove(key)
  }
  self.puts_since_sweep = 0
}

///|
/// 实现 seam（async）：写入一条带 TTL 的值。同名键会被覆盖。
///
/// 每累计 `SWEEP_INTERVAL` 次写入，顺带做一次机会式清扫（见 `sweep_expired`），
/// 从而在「只写不取」的负载下也能回收过期条目。
pub impl @core.ChallengeStore for MemoryChallengeStore with fn put(
  self,
  key,
  value,
  ttl_seconds,
) {
  self.values[key] = value
  self.expiries[key] = self.clock.now_unix() + ttl_seconds.to_int64()
  self.puts_since_sweep = self.puts_since_sweep + 1
  if self.puts_since_sweep >= SWEEP_INTERVAL {
    self.sweep_expired()
  }
}

///|
/// 实现 seam（async）：一次性取用。无论是否过期，取用后条目都被移除。
/// 返回 `None` 表示「不存在 / 已用 / 过期」。
pub impl @core.ChallengeStore for MemoryChallengeStore with fn take(self, key) {
  match self.values.get(key) {
    None => None
    Some(value) => {
      let expired = self.is_expired(key)
      self.values.remove(key)
      self.expiries.remove(key)
      if expired {
        None
      } else {
        Some(value)
      }
    }
  }
}

///|
/// 实现 seam（async）：只读检查，不消费。过期条目视为 `None`（但不移除）。
pub impl @core.ChallengeStore for MemoryChallengeStore with fn peek(self, key) {
  match self.values.get(key) {
    None => None
    Some(value) =>
      if self.is_expired(key) {
        None
      } else {
        Some(value)
      }
  }
}

///|
/// 显式把 seam 方法提升为 `MemoryChallengeStore` 的常规方法，避免隐式提升的弃用告警。
pub extend MemoryChallengeStore with @core.ChallengeStore::{put, take, peek}
