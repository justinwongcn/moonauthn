//! moonauth / provider/apple —— `form_post` 回调解析与 `user` 姓名提取。
//!
//! Apple 以 `response_mode=form_post` 回传：浏览器把结果 **POST** 到 `redirect_uri`，
//! body 为 `application/x-www-form-urlencoded`。字段：`code` / `id_token` / `state`，
//! 以及**仅首次授权**才出现的 `user`（一个 JSON 字符串）。

///|
/// 解析 `form_post` 回调体（`application/x-www-form-urlencoded`）→ `CallbackParams`。
pub fn apple_callback(body : String) -> @core.CallbackParams {
  @core.CallbackParams::from_form_body(body)
}

///|
/// 从 **首次授权** 的 `user` JSON 里提取显示名（`name.firstName` + `name.lastName`）。
///
/// Apple 只在用户**首次**授权时返回 `user`；后续登录不再返回，库**不缓存**它——
/// 需要持久化的调用方应在首次拿到后自行保存。
/// 形如 `{"name":{"firstName":"Ada","lastName":"Lovelace"},"email":"..."}`；
/// 解析失败 / 无姓名时返回 `None`。
pub fn apple_user_name(user_json : String) -> String? {
  let parsed : Json? = try {
    Some(@json.parse(user_json))
  } catch {
    _ => None
  }
  match parsed {
    Some(Object(top)) =>
      match top.get("name") {
        Some(Object(name)) => {
          let first = match name.get("firstName") {
            Some(String(s)) => s
            _ => ""
          }
          let last = match name.get("lastName") {
            Some(String(s)) => s
            _ => ""
          }
          let full = if first == "" {
            last
          } else if last == "" {
            first
          } else {
            first + " " + last
          }
          if full == "" {
            None
          } else {
            Some(full)
          }
        }
        _ => None
      }
    _ => None
  }
}
