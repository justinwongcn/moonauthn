//! moonauth / provider/x —— claims（用户信息）→ `ExternalIdentity` 归一化。
//!
//! `GET /2/users/me` 返回形如：
//! `{"data":{"id":"2244994945","name":"X Dev","username":"XDevelopers"}}`。
//!
//! 主键取 `data.id`（**数值用户 ID**）——`username`（@handle）可被用户更改，
//! 数值 id 不可变，故 `uid_kind = Stable`。

///|
/// 把 `/2/users/me` 的 JSON 响应归一为 `ExternalIdentity`。
pub fn x_identity(user_json : String) -> @core.ExternalIdentity raise @core.AuthError {
  let parsed : Json = @json.parse(user_json) catch {
    _ => raise @core.ParseError("moonauth: x userinfo is not valid JSON")
  }
  match parsed {
    Object(top) =>
      match top.get("data") {
        Some(Object(data)) => {
          let id = match data.get("id") {
            Some(String(s)) =>
              if s.length() > 0 {
                s
              } else {
                raise @core.ParseError("moonauth: x userinfo has empty id")
              }
            _ => raise @core.ParseError("moonauth: x userinfo missing data.id")
          }
          let name = match data.get("name") {
            Some(String(s)) => Some(s)
            _ => None
          }
          let raw : Map[String, String] = Map([])
          for k, v in data {
            raw[k] = x_json_to_string(v)
          }
          {
            provider: "x",
            uid: id,
            uid_kind: @core.UidKind::Stable,
            email: None,
            email_verified: false,
            display_name: name,
            avatar: None,
            extra: raw,
          }
        }
        _ => raise @core.ParseError("moonauth: x userinfo missing data object")
      }
    _ => raise @core.ParseError("moonauth: x userinfo is not a JSON object")
  }
}

///|
/// `Json` → 字符串视图（数值保留原始书写形态）。
fn x_json_to_string(value : Json) -> String {
  match value {
    String(s) => s
    True => "true"
    False => "false"
    Null => "null"
    Number(d, repr~) =>
      match repr {
        Some(r) => r
        None => d.to_string()
      }
    _ => value.stringify()
  }
}
