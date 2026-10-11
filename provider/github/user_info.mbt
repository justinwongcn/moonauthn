//! moonauth / provider/github —— `/user` / `/user/emails` 抓取与身份归一化。
//!
//! 取值表（见平台文档 `docs/platforms/github.md`）：
//! - `uid = id`（GitHub 的稳定用户标识），`uid_kind = Stable`；
//! - `display_name = name ?? login`，`avatar = avatar_url`；
//! - `email`：`/user.email`（公开邮箱）；为 `null` 时补拉 `/user/emails`
//!   取首个 `primary && verified` 项——该调用是**可选增强**，失败不失败登录；
//! - 其余字段进 `extra`（字符串视图，无第三方类型泄漏）。

///|
/// 取用户信息：`GET /user`。
///
/// 🔴 GitHub API **强制要求 `User-Agent` 头**，缺失一律 403——这是 GitHub 的
/// 平台特性，不是本库的 bug（`docs/platforms/github.md` 踩坑点 #1）。
async fn github_fetch_user(
  config : GitHubConfig,
  access_token : String,
) -> Map[String, Json] raise @core.AuthError {
  let resp = config.http.send({
    method: @core.HttpMethod::Get,
    url: config.user_info_endpoint,
    headers: Map([
      ("Authorization", "Bearer " + access_token),
      ("Accept", "application/vnd.github+json"),
      ("User-Agent", "moonauth"),
    ]),
    body: None,
  })
  if resp.status < 200 || resp.status >= 300 {
    raise @core.HttpStatus(resp.status, resp.body)
  }
  github_object(resp.body, "user response")
}

///|
/// 从 `/user/emails` 取首个 `primary && verified` 邮箱（含 verified 标记）。
///
/// 🔴 该调用是**可选增强**：未授予 `user:email` scope 时 GitHub 回非 2xx——
/// 此时登录已成立（`uid` 已拿到），邮箱保持 `None`，**不因增强失败而失败登录**
/// （失败吞掉的取舍记档于平台文档）。
async fn github_fetch_primary_email(
  config : GitHubConfig,
  access_token : String,
) -> EmailPick? raise @core.AuthError {
  let resp = config.http.send({
    method: @core.HttpMethod::Get,
    url: config.user_emails_endpoint,
    headers: Map([
      ("Authorization", "Bearer " + access_token),
      ("Accept", "application/vnd.github+json"),
      ("User-Agent", "moonauth"),
    ]),
    body: None,
  })
  if resp.status < 200 || resp.status >= 300 {
    return None
  }
  let parsed : Json = @json.parse(resp.body) catch {
    _ => return None
  }
  match parsed {
    Array(items) => {
      for item in items {
        match item {
          Object(m) => {
            let primary = match m.get("primary") {
              Some(True) => true
              _ => false
            }
            let verified = match m.get("verified") {
              Some(True) => true
              _ => false
            }
            match (primary, verified, m.get("email")) {
              (true, true, Some(String(s))) => return Some({ email: s, verified: true })
              _ => ()
            }
          }
          _ => ()
        }
      }
      None
    }
    _ => None
  }
}

///|
/// 归一化入口：`/user` 对象（必要时补拉邮箱）→ `ExternalIdentity`。
async fn github_identity(
  config : GitHubConfig,
  access_token : String,
  user : Map[String, Json],
) -> @core.ExternalIdentity raise @core.AuthError {
  let picked : EmailPick? = match user.get("email") {
    // 公开邮箱（`null` 或缺失 → 走 /user/emails 增强）。
    Some(String(s)) => Some({ email: s, verified: false })
    _ => github_fetch_primary_email(config, access_token)
  }
  let email = match picked {
    Some(p) => Some(p.email)
    None => None
  }
  let email_verified = match picked {
    Some(p) => p.verified
    None => false
  }
  let display_name = match user.get("name") {
    Some(String(s)) => Some(s)
    _ => github_string_opt(user.get("login"))
  }
  let avatar = github_string_opt(user.get("avatar_url"))
  let uid = match github_string_opt(user.get("id")) {
    Some(id) => id
    None => raise @core.ParseError("moonauth: github user response missing id")
  }
  let extra : Map[String, String] = Map([])
  for k, v in user {
    extra[k] = github_json_to_string(v)
  }
  {
    provider: "github",
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
/// `/user/emails` 里选出的邮箱（GitHub 的邮箱列表自带 `verified` 标记）。
priv struct EmailPick {
  email : String
  verified : Bool
}

///|
/// 解析 JSON 对象；非对象 / 非法 JSON → `ParseError`。
fn github_object(body : String, what : String) -> Map[String, Json] raise @core.AuthError {
  let parsed : Json = @json.parse(body) catch {
    _ => raise @core.ParseError("moonauth: github " + what + " is not valid JSON")
  }
  match parsed {
    Object(m) => m
    _ => raise @core.ParseError("moonauth: github " + what + " is not a JSON object")
  }
}

///|
/// `Json` → 可选字符串（数值保留原始书写形态；`null` / 缺失 → `None`）。
fn github_string_opt(value : Json?) -> String? {
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
fn github_json_to_string(value : Json) -> String {
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
