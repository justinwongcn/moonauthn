//! moonauth / core —— 基础 I/O seam（4 个）。
//!
//! 🔴 全部 trait 必须写成 `pub(open) trait`：MoonBit 的 `pub trait` 是**只读**的，
//! 跨包无法实现；而 seam 的全部意义就是让下游 / 官方 SDK 提供替代实现。
//! 用 `pub trait` 会让「可替换性」（SDK-01）直接不成立。
//!
//! 🔴 涉及 I/O（或为 I/O 留出空间）的 seam 一律声明为 `async fn`：MoonBit 服务端
//! 主流是 async（`moonbitlang/async` / `moonback` / `mars`），同步 seam 无法在
//! 既有 async 上下文中执行真实网络 I/O（桥接 `run_async_main` 会触发嵌套 abort）。
//! 实现侧写 `with fn`（**不是** `with async fn`），调用侧在 async 上下文内直接调用。

///|
/// 出站 HTTP。库内一切网络请求只经此接口（LIB-02 / LIB-19）。
///
/// 声明为 `async fn`：真实网络 I/O 必须在调用方的 async 上下文内执行。
pub(open) trait HttpClient {
  async fn send(Self, req : HttpRequest) -> HttpResponse raise AuthError
}

///|
/// 时间源。TOTP 窗口、challenge TTL、state 过期、JWKS 缓存 TTL 全部取自此。
/// 返回**秒级** Unix 时间戳。
///
/// 保持**同步**：纯计算，无 I/O，且会在 async / 同步两种上下文中被广泛读取。
pub(open) trait Clock {
  now_unix(Self) -> Int64
}

///|
/// 随机源（CSPRNG）。`state` / `code_verifier` / `nonce` / `challenge` 的唯一随机来源。
///
/// 🔴 库内*唯一*引用 `getrandom` 的默认实现位于 `rand` 子包（`GetrandomSource`）；
/// 需要 wasm-gc / 自定义随机源的调用方可注入自己的 `RandomSource` 以完全绕开 `getrandom`。
///
/// 保持**同步**：纯计算（一次系统熵读取），不引入 async 传染。
pub(open) trait RandomSource {
  bytes(Self, n : Int) -> Bytes raise AuthError
}

///|
/// 一次性临时态存取（challenge 的一次性 + TTL）。
///
/// 库**不**持有状态：本接口用于「希望由库代管一次性语义」的调用方；
/// 调用方也可完全自管（stateless 模式），此时不注入本接口。
///
/// 声明为 `async fn`：默认实现是内存 Map（无真正异步），但下游可用
/// Redis / 数据库 / 网络存储替代——这些替代实现**必须**能执行异步 I/O，
/// 因此签名一律 async，避免再次出现「同步 seam 无法执行异步 I/O」的结构性缺陷。
///
/// 🔴 三个方法一律 `raise AuthError`：**存储故障必须与「值不存在」区分开**。
/// 若 `take` / `peek` 在存储连接失败时返回 `None`，调用方会把「基础设施故障」
/// 误判成「challenge 不存在」——在 passkey 场景下等同于误判为**重放攻击 / 凭据失效**，
/// 属安全语义事故。因此远程实现（Redis 等）的故障经 `AuthError` 抛出，绝不吞成 `None`。
///
/// 语义约定：
/// - `put` 记录一条带 TTL 的值；存储故障 → `raise`（如 `Network` / `Unsupported`）；
/// - `take` **一次性**：取后即失效；返回 `None` = 不存在 / 已用 / 过期（**成功**语义），
///   存储故障 → `raise`；
/// - `peek` **只读**：检查但不消费，返回 `None` = 不存在 / 过期（**成功**语义），
///   存储故障 → `raise`。
///
/// 注：默认内存实现无真正故障路径，故**不抛错**是合法的（实现允许不抛）。
pub(open) trait ChallengeStore {
  async fn put(Self, key : String, value : String, ttl_seconds : Int) -> Unit raise AuthError
  async fn take(Self, key : String) -> String? raise AuthError
  async fn peek(Self, key : String) -> String? raise AuthError
}
