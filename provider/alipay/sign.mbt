//! moonauth / provider/alipay —— RSA2 签名串构造与签名。
//!
//! 🔴🔴 **签名串规则**（支付宝官方）：
//! 1. 取全部参数（公共参数 + 业务参数）；
//! 2. **去掉 `sign`**；**去掉值为空的参数**；
//! 3. 按参数名 **ASCII 升序** 排列；
//! 4. 以 `key=value` 用 `&` 连接，**值用原始值（不 URL 编码）**；
//! 5. 用应用私钥做 **SHA256withRSA**，结果 **标准 Base64** 放进 `sign`。
//!
//! 🔴🔴 **排序必须用 `@core.sort_lexicographic` / `@core.sorted_keys`**：
//! MoonBit 默认 `String::compare` 是**先比长度、再比内容**（**不是**字典序），
//! 用它拼出的签名串必错——而支付宝只回 `isv.invalid-signature`，
//! **不会提示是排序问题**，足以耗掉整天。故此处一律走 `core` 的字典序原语。

///|
/// 构造签名串：去 `sign`、去空值、`key` **ASCII 升序**、原始值不编码。
///
/// 顺序由 `@core.sorted_keys` 保证（**不是**默认 `String::compare` / `Array::sort`）。
pub fn alipay_signing_string(params : Map[String, String]) -> String {
  let filtered : Map[String, String] = Map([])
  for k, v in params {
    if k != "sign" && v.length() > 0 {
      filtered[k] = v
    }
  }
  let keys = @core.sorted_keys(filtered)
  let parts : Array[String] = []
  for k in keys {
    parts.push(k + "=" + filtered[k])
  }
  parts.join("&")
}

///|
/// 对参数做 RSA2 签名，返回**标准 Base64** 的签名值。
///
/// 复用 `@core.SecretSigner`（默认 `MooncryptSecretSigner` 的 RS256 = SHA256withRSA）。
pub fn alipay_sign(
  config : AlipayConfig,
  params : Map[String, String],
) -> String raise @core.AuthError {
  let content = alipay_signing_string(params)
  let sig = @core.SecretSigner::sign(
    config.signer,
    @core.SignAlg::RS256,
    config.private_key,
    @utf8.encode(content),
  )
  @oauth.base64_std_encode(sig)
}
