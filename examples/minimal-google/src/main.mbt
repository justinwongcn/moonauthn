//! moonauth / example —— 最小 Google 登录示例（**独立模块**）。
//!
//! 🔴 **LIB-20 隔离演示**：本模块**只** `import justinwongcn/moonauth/provider/google`，
//! 其依赖图里**不含**其余任何 provider（apple / wechat / qq / alipay / x / github / discord / dingtalk / feishu），也不含
//! `passkey` / `totp`。若 `provider/*` 之间存在耦合，本示例将无法独立编译。
//!
//! 运行：`moon run examples/minimal-google/src`（native）。
//!
//! 说明：`begin_auth` / `complete_auth` 为 **async seam**，需在 async 上下文中调用
//! （并在 `moon.mod` 里显式声明 `moonbitlang/async` 依赖）。本示例刻意保持**同步**、
//! **零额外依赖**，以最纯粹地演示「只依赖 `provider/google` 即可装配」——完整异步
//! 流程见 `contract/google_contract.mbt` 与 `provider/google/google_test.mbt`。

///|
/// 演示：构造装配点 + 默认实现，读取生效端点（全部同步、零网络）。
fn main {
  let config = @google.GoogleConfig::new("client-1", "https://app.example/cb")
  let provider = @google.DefaultGoogleProvider::new(config)
  let effective = provider.config()
  println("[minimal-google] provider = google")
  println(
    "[minimal-google] authorization_endpoint = " +
    effective.authorization_endpoint,
  )
  println("[minimal-google] token_endpoint = " + effective.token_endpoint)
  println("[minimal-google] scopes = " + effective.scopes.join(" "))
}
