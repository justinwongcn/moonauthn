//! moonauth / http_e2e —— 响应头**端到端**透传验收（native 专有）。
//!
//! 本包为 **native-only 的测试包**：它为了「起一个真实本地 HTTP 服务器」而使用了
//! `moonbitlang/async/socket`（其 `Addr` 是 native 专有类型）。这不违反「库本体只用
//! `async/http`、禁用 `async/socket`」的约束——该约束针对的是 **库本体（core 及
//! 各能力子包）**，目的是保证 js target 可编译；测试包不参与库产物，且本包已用
//! `options(supported_targets: "+native")` 限定 target，js 构建会自动跳过。
//!
//! 目的：锁定 §四·修复 2 —— `AsyncHttpClient` 必须把 `async/http` 响应的自定义头
//! 透传为库自有的 `Map[String, String]`（此前恒为 `Map([])`），这是 T03 `provider/qq`
//! 按 `content-type` 判断响应体形态（form-encoded vs JSON）的前提。

///|
/// 占位符号，确保本包存在非测试文件（包仅含测试文件时部分工具链行为不一致）。
pub fn http_e2e_marker() -> String {
  "http_e2e"
}
