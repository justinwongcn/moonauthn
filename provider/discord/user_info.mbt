//! moonauth / provider/discord —— `/users/@me` 抓取与身份归一化。
//!
//! 取值表（见平台文档 `docs/platforms/discord.md`）：
//! - `uid = id`（Discord 雪片号，JSON 里就是**字符串**），`uid_kind = Stable`；
//! - `display_name = global_name ?? username`；
//! - `email` / `email_verified`：需 `email` scope（`verified` 是布尔）；
//! - `avatar`：响应里是**哈希**，按 Discord 规则拼
//!   `https://cdn.discordapp.com/avatars/{id}/{hash}.png`（`a_` 前缀的动图哈希用
//!   `.gif`）；哈希为 `null` → `None`（默认头像的下标公式需 64 位雪片运算，
//!   库不代算，记档于平台文档）；
//! - 其余字段进 `extra`（字符串视图，无第三方类型泄漏）。

///|
/// 取用户信息：`GET /users/@me`。
async fn discord_fetch_user(
  config : DiscordConfig,
  access_token : String,
) -> String raise @core.AuthError {
  let resp = config.http.send({
    method: @core.HttpMethod::Get,
    url: config.user_info_endpoint,
    headers: Map([
      ("Authorization", "Bearer " + access_token),
      ("Accept", "application/json"),
    ]),
    body: None,
  })
  if resp.status < 200 || resp.status >= 300 {
    raise @core.HttpStatus(resp.status, resp.body)
  }
  resp.body
}

///|
/// 归一化：`/users/@me` **响应 JSON 文本** → `ExternalIdentity`。
///
/// 🔴 入参收原始文本而非 `Map[String, Json]`：`Json` 是第三方类型，不得出现在
/// `pub` 签名上（SDK-03，同 `qq_identity` 先例）。
pub fn discord_identity(user_json : String) -> @core.ExternalIdentity raise @core.AuthError {
  let user = discord_object(user_json, "user response")
  let uid = match discord_string_opt(user.get("id")) {
    // 🔴 空串视为缺失（契约 §2.2；同 dingtalk/feishu non_empty 先例）。
    Some(id) => if id.length() > 0 {
      id
    } else {
      raise @core.ParseError("moonauth: discord user response has empty id")
    }
    None => raise @core.ParseError("moonauth: discord user response missing id")
  }
  let display_name = match discord_string_opt(user.get("global_name")) {
    Some(name) => Some(name)
    None => discord_string_opt(user.get("username"))
  }
  let email = discord_string_opt(user.get("email"))
  let email_verified = match user.get("verified") {
    Some(True) => true
    _ => false
  }
  let avatar = match (user.get("avatar"), uid) {
    (Some(String(hash)), _) => Some(discord_avatar_url(uid, hash))
    _ => None
  }
  let extra : Map[String, String] = Map([])
  for k, v in user {
    extra[k] = discord_json_to_string(v)
  }
  {
    provider: "discord",
    uid,
    uid_kind: @core.UidKind::Stable,
    email,
    email_verified,
    display_name,
    avatar,
    extra,
  }
}

///|
/// 按 Discord 规则拼头像 URL：`a_` 前缀（动图哈希）→ `.gif`，否则 `.png`。
///
/// 🔴 `uid` / `hash` 一律百分号编码：两者来自平台响应，
/// 正常形态为数字雪花 ID 与 hex/`a_` 前缀哈希，但异常形态（含 `/` `?` `#`）会
/// 篡改 URL——与库内「动态值一律 percent_encode」教义对齐。
fn discord_avatar_url(uid : String, hash : String) -> String {
  let ext = if hash.has_prefix("a_") {
    "gif"
  } else {
    "png"
  }
  "https://cdn.discordapp.com/avatars/\{discord_percent_encode(uid)}/\{discord_percent_encode(hash)}.\{ext}"
}

///|
/// `application/x-www-form-urlencoded` 百分号编码（空格 → `%20`；RFC 3986 非保留集
/// 之外全编码）——与 dingtalk/qq/wechat 的同名私有助手同构。
fn discord_percent_encode(s : String) -> String {
  let bytes = @utf8.encode(s)
  let out : Array[Byte] = []
  let hex = @utf8.encode("0123456789ABCDEF")
  for b in bytes {
    let c = b.to_int()
    if discord_is_unreserved(c) {
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
/// 是否为 RFC 3986 非保留字符。
fn discord_is_unreserved(c : Int) -> Bool {
  (c >= 65 && c <= 90) ||
  (c >= 97 && c <= 122) ||
  (c >= 48 && c <= 57) ||
  c == 45 ||
  c == 95 ||
  c == 46 ||
  c == 126
}

///|
/// 解析 JSON 对象；非对象 / 非法 JSON → `ParseError`。
fn discord_object(body : String, what : String) -> Map[String, Json] raise @core.AuthError {
  let parsed : Json = @json.parse(body) catch {
    _ => raise @core.ParseError("moonauth: discord " + what + " is not valid JSON")
  }
  match parsed {
    Object(m) => m
    _ => raise @core.ParseError("moonauth: discord " + what + " is not a JSON object")
  }
}

///|
/// `Json` → 可选字符串（数值保留原始书写形态；`null` / 缺失 → `None`）。
fn discord_string_opt(value : Json?) -> String? {
  match value {
    Some(String(s)) => Some(s)
    Some(Number(d, repr~)) =>
      match repr {
        Some(r) => Some(r)
        None => Some(d.to_string())
      }
    _ => None
  }
}

///|
/// `Json` → 字符串视图（数值保留原始书写形态）。
fn discord_json_to_string(value : Json) -> String {
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
