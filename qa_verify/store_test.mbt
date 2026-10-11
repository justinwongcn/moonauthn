//! moonauth / qa_verify —— MemoryChallengeStore 语义边界 + 机会式清扫 + 存储故障语义。
//!
//! T01 修订后 `ChallengeStore` 为 async，故全部为 `async test`。

///|
/// 建一个固定时钟 + store。
fn mk_store_from(start : Int64) -> (@contract.FixedClock, @store_memory.MemoryChallengeStore) {
  let clock = @contract.FixedClock::new(start)
  let store = @store_memory.MemoryChallengeStore::new(clock)
  (clock, store)
}

///|
async test "take is one-shot: second take is None, and a fresh put revives the key" {
  let (_, store) = mk_store_from(1000L)
  store.put("k", "v", 60)
  @debug.assert_eq(store.take("k"), Some("v"))
  @debug.assert_eq(store.take("k"), None)
  @debug.assert_eq(store.peek("k"), None)
  store.put("k", "v2", 60)
  @debug.assert_eq(store.peek("k"), Some("v2"))
}

///|
async test "peek never consumes; interleaving peek/take behaves per contract" {
  let (_, store) = mk_store_from(0L)
  store.put("k", "v", 100)
  @debug.assert_eq(store.peek("k"), Some("v"))
  @debug.assert_eq(store.peek("k"), Some("v"))
  @debug.assert_eq(store.peek("k"), Some("v"))
  @debug.assert_eq(store.take("k"), Some("v"))
  @debug.assert_eq(store.peek("k"), None)
  @debug.assert_eq(store.take("k"), None)
}

///|
async test "ttl boundary: now == expires_at is expired, peek and take agree at the same instant" {
  let (clock, store) = mk_store_from(1000L)
  store.put("k", "v", 60) // expires_at = 1060
  clock.set(1059L)
  @debug.assert_eq(store.peek("k"), Some("v"))
  clock.set(1060L)
  @debug.assert_eq(store.peek("k"), None)
  @debug.assert_eq(store.take("k"), None)
}

///|
async test "take on an expired entry returns None and cleans it (reuse works, stable None)" {
  let (clock, store) = mk_store_from(2000L)
  store.put("k", "v", 5) // expires_at = 2005
  clock.set(2005L)
  @debug.assert_eq(store.take("k"), None)
  @debug.assert_eq(store.take("k"), None)
  @debug.assert_eq(store.peek("k"), None)
  store.put("k", "fresh", 5)
  @debug.assert_eq(store.take("k"), Some("fresh"))
}

///|
async test "zero and negative ttl are immediately expired" {
  let (_, store) = mk_store_from(42L)
  store.put("z", "v", 0)
  @debug.assert_eq(store.peek("z"), None)
  @debug.assert_eq(store.take("z"), None)
  store.put("n", "v", -100)
  @debug.assert_eq(store.peek("n"), None)
  @debug.assert_eq(store.take("n"), None)
}

///|
async test "overwrite replaces the ttl in both directions (no residual old expiry)" {
  let (clock, store) = mk_store_from(0L)
  store.put("k", "v1", 10) // exp = 10
  clock.set(5L)
  store.put("k", "v2", 1000) // exp = 1005
  clock.set(100L)
  @debug.assert_eq(store.peek("k"), Some("v2"))
  store.put("k", "v3", 10) // exp = 110
  clock.set(120L)
  @debug.assert_eq(store.peek("k"), None)
  @debug.assert_eq(store.take("k"), None)
}

///|
async test "far-future clock keeps returning None stably" {
  let (clock, store) = mk_store_from(0L)
  store.put("k", "v", 1)
  clock.set(4_000_000_000L)
  @debug.assert_eq(store.take("k"), None)
  @debug.assert_eq(store.take("k"), None)
  @debug.assert_eq(store.peek("k"), None)
}

///|
async test "unknown keys are None for both peek and take" {
  let (_, store) = mk_store_from(0L)
  @debug.assert_eq(store.peek("nope"), None)
  @debug.assert_eq(store.take("nope"), None)
}

///|
async test "empty-string value is a present value, not treated as absent" {
  let (_, store) = mk_store_from(0L)
  store.put("k", "", 100)
  @debug.assert_eq(store.peek("k"), Some(""))
  @debug.assert_eq(store.take("k"), Some(""))
  @debug.assert_eq(store.take("k"), None)
}

// ════════ 机会式清扫（SWEEP_INTERVAL = 16）════════

///|
/// 对抗性：清扫**不得**误删未过期条目。40 次 put 已触发多次全量清扫；
/// 全部条目 TTL 很长 → 每条都必须仍在（peek 命中）。
async test "opportunistic sweep never removes fresh entries" {
  let (_, store) = mk_store_from(0L)
  for i = 0; i < 40; i = i + 1 {
    store.put("k\{i}", "v", 100000)
  }
  @debug.assert_eq(store.peek("k0"), Some("v"))
  @debug.assert_eq(store.peek("k17"), Some("v"))
  @debug.assert_eq(store.peek("k39"), Some("v"))
}

///|
/// 对抗性：覆盖写刷新了 TTL 后，清扫必须按**新** TTL 判断，不得因旧 TTL 误删。
async test "sweep uses the refreshed expiry after overwrite" {
  let (clock, store) = mk_store_from(1000L)
  store.put("k", "old", 1) // exp = 1001
  clock.set(1500L) // 旧条目此刻已过期
  store.put("k", "new", 100000) // 覆盖刷新 exp = 101500
  for i = 0; i < 20; i = i + 1 {
    store.put("f\{i}", "v", 100000)
  }
  clock.set(1600L)
  @debug.assert_eq(store.peek("k"), Some("new"))
}

// ════════ 存储故障语义（新增 raise 的回归）════════

///|
/// 🔴 安全语义：存储故障必须被**抛出**，绝不能被降级成 `None`
/// （否则「基础设施故障」会被伪装成「challenge 不存在」）。
async test "failing store surfaces an error for take/peek/put (never None)" {
  let s = @qa_verify.FailingStore::new()
  let take_raised = try {
    let _ = @core.ChallengeStore::take(s, "k")
    false
  } catch {
    _ => true
  }
  let peek_raised = try {
    let _ = @core.ChallengeStore::peek(s, "k")
    false
  } catch {
    _ => true
  }
  let put_raised = try {
    @core.ChallengeStore::put(s, "k", "v", 60)
    false
  } catch {
    _ => true
  }
  assert_true(take_raised)
  assert_true(peek_raised)
  assert_true(put_raised)
}

///|
/// 故障抛出的值应当是 `AuthError` 变体（可被按 `AuthError` 匹配识别）。
async test "failing store raises an AuthError value" {
  let s = @qa_verify.FailingStore::new()
  let is_auth = try {
    let _ = @core.ChallengeStore::take(s, "k")
    false
  } catch {
    e =>
      match e {
        @core.Network(_) => true
        _ => false
      }
  }
  assert_true(is_auth)
}

///|
/// 🔴 上轮 `E4014`（`has type Error / wanted AuthError`）回归：
/// `ChallengeStore` 声明 `raise AuthError` 后，调用方可直接用
/// `catch { e => auth_error_code(e) }`——**此用例能编译并通过即证明该编译错误已消除**。
async test "E4014 regression: direct auth_error_code(e) compiles for ChallengeStore failures" {
  let s = @qa_verify.FailingStore::new()
  let code = try {
    let _ = @core.ChallengeStore::take(s, "k")
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "network")
}

///|
/// 安全语义对照：**故障（AuthError）** 与 **值不存在（None）** 绝不混淆。
async test "failure (AuthError) is distinct from absent (None)" {
  let (_, store) = mk_store_from(0L)
  // 正常存储 + 不存在的键 → 成功语义的 None
  @debug.assert_eq(store.take("absent"), None)
  // 故障存储 → AuthError（而非被伪装成 None）
  let s = @qa_verify.FailingStore::new()
  let code = try {
    let _ = @core.ChallengeStore::take(s, "k")
    "no-error"
  } catch {
    e => @core.auth_error_code(e)
  }
  @debug.assert_eq(code, "network")
}

///|
/// 正常路径：`MemoryChallengeStore` 不得无缘无故抛错（签名对齐不应引入乱抛）。
async test "MemoryChallengeStore does not raise on the happy path" {
  let (_, store) = mk_store_from(0L)
  let ok = try {
    store.put("k", "v", 60)
    let _ = store.peek("k")
    let _ = store.take("k")
    let _ = store.take("missing")
    true
  } catch {
    _ => false
  }
  assert_true(ok)
}
