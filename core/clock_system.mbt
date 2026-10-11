//! moonauth / core —— 默认 `Clock` 实现：`SystemClock`。

///|
/// 默认 `Clock` 实现：读取系统 wall-clock，返回**秒级** Unix 时间戳。
/// 跨 native / js 均可工作（经 `@env.now()`，其语义为「自 Unix epoch 起的毫秒」）。
pub(all) struct SystemClock {}

///|
/// 构造 `SystemClock`。
pub fn SystemClock::new() -> SystemClock {
  SystemClock::{}
}

///|
/// 实现 seam：返回当前 Unix 秒。
pub impl Clock for SystemClock with fn now_unix(self) {
  let _ = self
  (@env.now() / 1000UL).reinterpret_as_int64()
}

///|
/// 显式把 seam 方法提升为 `SystemClock` 的常规方法，避免隐式提升的弃用告警。
pub extend SystemClock with Clock::{now_unix}
