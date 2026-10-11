//! moonauth / rand —— 默认 `RandomSource` 实现：`GetrandomSource`。
//!
//! 🔴 **本包是全库唯一引用 `mizchi/experimental_crypto/getrandom` 的地方。**
//! 除本包外任何子包都不得 import getrandom；需要随机源的地方一律经 `core.RandomSource`
//! seam 注入。这样「不依赖 CSPRNG 的纯验签子集」（除本包外全部子包）可在无 getrandom
//! 的 target（如 wasm-gc）上编译，且调用方可用自定义 `RandomSource` 完全绕开。

///|
/// 默认 `RandomSource` 实现：封装 OS CSPRNG（经 `@getrandom`）。
pub(all) struct GetrandomSource {}

///|
/// 构造 `GetrandomSource`。
pub fn GetrandomSource::new() -> GetrandomSource {
  GetrandomSource::{}
}

///|
/// 实现 seam：取 `n` 字节密码学安全随机数。
///
/// `@getrandom` 的失败在边界处立即 `catch` 并转换为 `AuthError::RandomUnavailable`；
/// `@getrandom` 的类型不会出现在公开签名上。
pub impl @core.RandomSource for GetrandomSource with fn bytes(self, n) {
  let _ = self
  @getrandom.bytes(n) catch {
    _ => raise @core.RandomUnavailable
  }
}

///|
/// 显式把 seam 方法提升为 `GetrandomSource` 的常规方法，避免隐式提升的弃用告警。
pub extend GetrandomSource with @core.RandomSource::{bytes}
