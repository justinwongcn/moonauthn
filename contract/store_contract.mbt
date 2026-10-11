//! moonauth / contract —— `ChallengeStore` 的**参数化契约**（SDK-04）。
//!
//! `ChallengeStore` 是下游最可能替换的 seam（内存 → Redis / 数据库），其安全语义
//! 必须可对任意实现复跑：
//! - **一次性**：`take` 取后即失效，二次 `take` 必为 `None`（防重放的根）；
//! - **peek 不消费**：检查但不破坏一次性；
//! - **TTL 边界**：`now >= expires_at` 即过期（`ttl = 0` 在写入时刻即已到期）；
//! - **覆盖写**：同键后写覆盖先写；
//! - **键隔离**：不同键互不可见。
//!
//! 🔴 「存储故障 → raise 而非 None」无法对任意实现参数化（故障注入是实现特定的），
//! 由各实现自测（参见 `seam_probe` 的失败存储用例、`passkey_test` 的必然失败存储）。

///|
/// ① roundtrip + 一次性：`take` 取后即失效，二次 `take` 必为 `None`。
async fn store_case_one_time(make : () -> &@core.ChallengeStore) -> CaseResult {
  let store = make()
  store.put("k1", "v1", 60)
  let first = store.take("k1")
  let second = store.take("k1")
  if first is Some("v1") && second is None {
    CaseResult::pass("store: take is one-time")
  } else {
    CaseResult::fail("store: take is one-time", "first=\{Repr(first)} second=\{Repr(second)}")
  }
}

///|
/// ② peek 只读不消费。
async fn store_case_peek(make : () -> &@core.ChallengeStore) -> CaseResult {
  let store = make()
  store.put("k1", "v1", 60)
  let peeked = store.peek("k1")
  let taken = store.take("k1")
  if peeked is Some("v1") && taken is Some("v1") {
    CaseResult::pass("store: peek does not consume")
  } else {
    CaseResult::fail("store: peek does not consume", "peek=\{Repr(peeked)} take=\{Repr(taken)}")
  }
}

///|
/// ③ TTL 边界：`ttl = 0` → `expires_at = now`，取用时刻 `now >= expires_at` 即过期。
async fn store_case_ttl_boundary(make : () -> &@core.ChallengeStore) -> CaseResult {
  let store = make()
  store.put("k1", "v1", 0)
  let taken = store.take("k1")
  if taken is None {
    CaseResult::pass("store: ttl=0 is already expired at take time")
  } else {
    CaseResult::fail("store: ttl=0 is already expired at take time", "take=\{Repr(taken)}")
  }
}

///|
/// ④ 覆盖写：同键后写覆盖先写。
async fn store_case_overwrite(make : () -> &@core.ChallengeStore) -> CaseResult {
  let store = make()
  store.put("k1", "old", 60)
  store.put("k1", "new", 60)
  let taken = store.take("k1")
  if taken is Some("new") {
    CaseResult::pass("store: put overwrites the previous value")
  } else {
    CaseResult::fail("store: put overwrites the previous value", "take=\{Repr(taken)}")
  }
}

///|
/// ⑤ 键隔离：不同键互不可见。
async fn store_case_isolation(make : () -> &@core.ChallengeStore) -> CaseResult {
  let store = make()
  store.put("k1", "v1", 60)
  store.put("k2", "v2", 60)
  let a = store.take("k1")
  let b = store.take("k2")
  if a is Some("v1") && b is Some("v2") {
    CaseResult::pass("store: distinct keys are isolated")
  } else {
    CaseResult::fail("store: distinct keys are isolated", "a=\{Repr(a)} b=\{Repr(b)}")
  }
}

///|
/// 对一个 `ChallengeStore` 实现跑完整断言集。
///
/// 🔴 **调用方契约**：`make()` 每次产出**全新、空**的存储实例（用例间互不污染），
/// 其时钟取 `FixedClock(fixed_now_unix())`（TTL 边界用例依赖此刻）。
pub async fn run_store(make : () -> &@core.ChallengeStore) -> Array[CaseResult] {
  let out : Array[CaseResult] = []
  out.push(store_case_one_time(make))
  out.push(store_case_peek(make))
  out.push(store_case_ttl_boundary(make))
  out.push(store_case_overwrite(make))
  out.push(store_case_isolation(make))
  out
}
