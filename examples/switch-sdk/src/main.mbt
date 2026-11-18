//! moonauth / example —— **切换到官方 SDK** 的端到端示范（SDK-01 / SDK-05）。
//!
//! 主旨：库对每个能力都定义了**极窄的 `pub(open) trait` seam**。官方 SDK 出现时，
//! 你只需**为自己的类型实现该 trait**，再用 `with_*` 注入，**业务代码零改动**。
//!
//! 本示例把「验 `id_token`」这一能力替换成一个**自造的官方 SDK 适配器**
//! （`OfficialSdkIdTokenVerifier`），并证明它确实接管了验签——因为返回的 `uid`
//! 来自官方适配器（`official-user-1`），而非库默认 JWKS 验签器。
//!
//! 运行：`moon run examples/switch-sdk/src`（native，固定向量，零网络）。

///|
/// 一个「官方 SDK 风格」的 `IdTokenVerifier` 适配器。
///
/// 真实场景里，`verify` 内部会调用官方 SDK；本示例为保持离线确定性，直接返回固定 claims。
struct OfficialSdkIdTokenVerifier {
  /// 便于演示：适配层可以自由携带自己的配置。
  tag : String
}

///|
/// 🔴 关键点：**跨包实现库的 seam** —— 因为 trait 声明为 `pub(open) trait`，
/// 下游包才能在**自己的包里**实现它（普通 `pub trait` 只读、不可跨包实现）。
impl @core.IdTokenVerifier for OfficialSdkIdTokenVerifier with fn verify(
  self,
  token,
  expect,
) {
  let _ = token
  let _ = expect
  {
    subject: "official-user-1",
    issuer: "https://issuer.example",
    audience: ["client-1"],
    expires_at: 0L,
    issued_at: 0L,
    nonce: None,
    email: Some("official@example.com"),
    email_verified: Some(true),
    // 把适配层自己的信息放进 raw，调用方可见。
    raw: Map([("verified_by", self.tag)]),
  }
}

///|
/// 端到端：装配 Google provider，但**替换**其 `id_token` 验签实现。
async fn main {
  // ① 正常装配点（token 端点走 mock，零网络）。
  let config = @contract.google_mock_config()
  // ② 注入官方 SDK 适配器，替换库默认的 JWKS 验签器。
  let official : &@core.IdTokenVerifier = OfficialSdkIdTokenVerifier::{
    tag: "official-sdk",
  }
  let provider = @google.DefaultGoogleProvider::new(config).with_id_token(official)

  // ③ 流程不变：begin → 回调 → complete。
  let start = provider.begin_auth({
    state: Some("st-c1"),
    code_verifier: Some("vabcdefghijklmnopqrstuvwxyz0123456789-._~abcdef"),
    nonce: Some("nonce-1"),
  })
  let callback = @core.CallbackParams::from_query_string(
    "code=auth-code-1&state=st-c1",
  )
  let identity = provider.complete_auth(callback, start)

  // ④ 证明替换生效：uid 来自官方适配器，raw 里带它的 tag。
  println("[switch-sdk] uid          = " + identity.uid)
  println("[switch-sdk] email        = " + identity.email.unwrap_or("-"))
  println(
    "[switch-sdk] verified_by  = " + identity.extra.get("verified_by").unwrap_or("-"),
  )
  println("[switch-sdk] done：官方 SDK 已按能力粒度接管 id_token 验签")
}
