//! moonauth / provider/wechat —— 授权 URL 组装（🔴 **严格参数顺序**）。
//!
//! 🔴🔴 **微信要求参数顺序严格固定**：
//! `appid` → `redirect_uri` → `response_type` → `scope` → `state` → `#wechat_redirect`。
//! 因此本文件**用一个字符串模板顺序拼接**，**绝不用 `Map` 迭代**——Map 迭代顺序不可控，
//! 一旦顺序错乱，微信会直接拒绝（且不给出「顺序」相关的提示，极难排查）。
//! 这是本库「微信协议由 `provider/wechat` 自有实现承担、不复用 `oauth` 的机械组装」的原因。

///|
/// 构造微信授权 URL（严格顺序 + `#wechat_redirect` 锚点）。
///
/// `redirect_uri` / `state` 等动态值一律百分号编码——`state` 可能由调用方自带
///（`SuppliedSecrets.state`），不编码时其中的 `&` / `#` / 空格会截断甚至注入 query。
pub fn wechat_authorize_url(config : WeChatConfig, state : String) -> String {
  config.authorization_endpoint +
  "?appid=" +
  wechat_percent_encode(config.appid) +
  "&redirect_uri=" +
  wechat_percent_encode(config.redirect_uri) +
  "&response_type=code" +
  "&scope=" +
  wechat_percent_encode(config.scope) +
  "&state=" +
  wechat_percent_encode(state) +
  "#wechat_redirect"
}

///|
/// `application/x-www-form-urlencoded` 百分号编码（RFC 3986 §2.3 非保留集之外全编码；
/// 空格 → `%20`）。
pub fn wechat_percent_encode(s : String) -> String {
  let bytes = @utf8.encode(s)
  let out : Array[Byte] = []
  let hex = @utf8.encode("0123456789ABCDEF")
  for b in bytes {
    let c = b.to_int()
    if wechat_is_unreserved(c) {
      out.push(b)
    } else {
      out.push(b'%')
      out.push(hex[(c >> 4) & 0x0F])
      out.push(hex[c & 0x0F])
    }
  }
  @utf8.decode_lossy(Bytes::from_array(out))
}

///|
/// 是否为 RFC 3986 非保留字符：`A-Z a-z 0-9 - _ . ~`。
fn wechat_is_unreserved(c : Int) -> Bool {
  (c >= 65 && c <= 90) ||
  (c >= 97 && c <= 122) ||
  (c >= 48 && c <= 57) ||
  c == 45 ||
  c == 95 ||
  c == 46 ||
  c == 126
}
