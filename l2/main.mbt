//! moonauth / l2 —— **L2 真实回流 harness**（Owner 手动运行；不入 CI、不入库凭据）。
//!
//! 流程（**回调自动捕获**——Owner 只需在浏览器完成登录授权）：
//! 1. 读 `l2/config.json`（凭据，已 gitignore；模板 `config.example.json`）；
//! 2. 按 `platform` 构造 provider 配置 → `begin_auth` → 打印授权 URL；
//! 3. Owner 在浏览器完成登录授权——浏览器跳转到
//!    `http://localhost:9876/callback?code=...&state=...`；
//! 4. harness 的回调服务器**自动捕获** query → `complete_auth` → 打印 L2 记录。
//!
//! 双模式兜底：若浏览器与 harness 不在同一台机器（远程开发），回调自动捕获不可达——
//! 此时把地址栏完整 URL 粘贴到 `l2/callback.txt` 并保存，轮询同样会捕获（paste 模式）。
//!
//! 🔴 凭据绝不入库：`l2/config.json` / `l2/callback.txt` / `l2/records/` 均已 gitignore。
//! 🔴 apple 不在本 harness（form_post 回调的 code 在 POST 体里 + 需付费开发者资质）；
//!    qq 需备案域名。

let config_path : String = "l2/config.json"
let callback_path : String = "l2/callback.txt"

///|
struct L2Capture {
  mut path : String
  mut paste : String
}

///|
fn jstr(o : Map[String, Json], key : String) -> String {
  match o.get(key) {
    Some(String(s)) => s
    _ => ""
  }
}

///|
fn jobj(o : Map[String, Json], key : String) -> Map[String, Json] raise @core.AuthError {
  match o.get(key) {
    Some(Object(m)) => m
    _ => raise @core.ParseError("moonauth: l2 config.json 缺少配置节: " + key)
  }
}

///|
fn jstr_array(o : Map[String, Json], key : String) -> Array[String] {
  let out : Array[String] = []
  match o.get(key) {
    Some(Array(items)) =>
      for it in items {
        match it {
          String(s) => out.push(s)
          _ => ()
        }
      }
    _ => ()
  }
  out
}

///|
fn jint(o : Map[String, Json], key : String, default : Int) -> Int {
  match o.get(key) {
    Some(Number(d, ..)) => d.to_int()
    _ => default
  }
}

///|
/// 回调捕获服务器：浏览器 redirect 命中 `/callback?...` 时记录完整 path（含 query）
/// 并回显友好页面。`capture` 以引用共享，主流程轮询读取。
async fn start_callback_server(
  group : @async.TaskGroup[Unit],
  port : Int,
  capture : L2Capture,
) -> Unit {
  let server = @http.Server(@socket.Addr::parse("127.0.0.1:\{port}"))
  group.add_defer(() => server.close())
  group.spawn_bg(no_wait=true) <| () => {
    server.run_forever() <| ((req, _body, conn) => {
      capture.path = req.path
      conn
      ..send_response(200, "OK", extra_headers={
        "Content-Type": "text/html; charset=utf-8",
      })
      .write(
        "<html><body style=\"font-family:sans-serif\"><h3>✓ 授权完成</h3><p>已收到回调，可以关闭此窗口，回到终端查看 L2 记录。</p></body></html>",
      )
    })
  }
}

///|
/// 双模式等待：①回调服务器捕获（浏览器 redirect 自动命中）；②Owner 粘贴到
/// `callback.txt` 的 URL（远程开发场景）。超时 `timeout_s` 秒。
async fn wait_capture(capture : L2Capture, timeout_s : Int) -> String raise @core.AuthError {
  println("== 等待授权回调 ==")
  println(
    "在浏览器完成登录授权后，回调会被自动捕获；若 harness 与浏览器不在同一台机器，把地址栏完整 URL 粘贴到 \{callback_path} 并保存。超时 \{timeout_s}s。",
  )
  let mut waited = 0
  while waited < timeout_s {
    if capture.path.length() > 0 {
      println("已捕获浏览器回调（等待 \{waited}s）")
      return capture.path
    }
    let paste = @async_fs.read_file(callback_path).text() catch {
      _ => ""
    }
    if paste.length() > 0 {
      println("已捕获粘贴的回调 URL（等待 \{waited}s）")
      return paste
    }
    @async.sleep(1000)
    waited = waited + 1
  }
  raise @core.Network(
    "moonauth: L2 等待回调超时（\{timeout_s}s）——回调未命中且 callback.txt 为空",
  )
}

///|
/// 从回调 path/URL 提取 query：取 `?` 之后、`#` 之前的部分；无 `?` 时原样返回。
fn extract_query(raw : String) -> String {
  let after_q = match raw.split_once("?") {
    Some((_, rest)) => rest.to_owned()
    None => raw
  }
  match after_q.split_once("#") {
    Some((q, _)) => q.to_owned()
    None => after_q
  }
}

///|
fn print_record(platform : String, identity : @core.ExternalIdentity) -> Unit {
  println("════ L2 记录（\{platform}）════")
  println("provider   = \{identity.provider}")
  println("uid        = \{identity.uid}")
  let kind = match identity.uid_kind {
    @core.UidKind::Stable => "Stable"
    @core.UidKind::Degraded => "Degraded"
  }
  println("uid_kind   = \{kind}")
  let email = match identity.email {
    Some(s) => s
    None => "<none>"
  }
  println("email      = \{email} (verified=\{identity.email_verified})")
  let name = match identity.display_name {
    Some(s) => s
    None => "<none>"
  }
  println("name       = \{name}")
  println("extra 声明:")
  for k, v in identity.extra {
    println("  \{k} = \{v}")
  }
}

///|
/// 各平台分支：读配置节 → 构造 provider 配置 → begin_auth → 等待回调 → 归一身份。
async fn run() -> Unit raise @core.AuthError {
  let raw_cfg = @async_fs.read_file(config_path).text() catch {
    _ => {
      println(
        "L2: 未找到 \{config_path}——请复制 config.example.json 为 config.json 并填写凭据",
      )
      return
    }
  }
  let parsed : Json = @json.parse(raw_cfg) catch {
    _ => raise @core.ParseError("moonauth: l2 config.json 不是 JSON 对象")
  }
  let cfg = match parsed {
    Object(m) => m
    _ => raise @core.ParseError("moonauth: l2 config.json 不是 JSON 对象")
  }
  let platform = jstr(cfg, "platform")
  if platform.length() == 0 {
    raise @core.ParseError("moonauth: l2 config.json 缺少 platform 字段")
  }
  let timeout_s = jint(cfg, "timeout_seconds", 600)
  let section = jobj(cfg, platform)
  let callback_port = jint(cfg, "callback_port", 9876)
  let capture = L2Capture::{ path: "", paste: "" }
  try {
    @async.with_task_group() <| group => {
      start_callback_server(group, callback_port, capture)
      try {
      let secrets : @core.SuppliedSecrets = {
        state: None,
        code_verifier: None,
        nonce: None,
      }
      let identity = if platform == "google" {
      let config = @google.GoogleConfig::new(
          jstr(section, "client_id"),
          jstr(section, "redirect_uri"),
        )
        .with_client_secret(jstr(section, "client_secret"))
      let start = @google.begin_auth(config, secrets)
      println("== 授权 URL（浏览器打开并登录）==")
      println(start.url)
      let query = extract_query(wait_capture(capture, timeout_s))
      let callback = @core.CallbackParams::from_query_string(query)
      @google.complete_auth(config, callback, start)
    } else if platform == "microsoft" {
      // client_secret 留空 = 公开客户端（PKCE-only，不发 secret——零注册冒烟用
      // Azure CLI 一方公开客户端 client_id 即属此形态）。
      let config = @microsoft.MicrosoftConfig::new(
          jstr(section, "client_id"),
          jstr(section, "redirect_uri"),
        )
        .with_tenant(jstr(section, "tenant"))
        .with_allowed_tenant_ids(jstr_array(section, "allowed_tenant_ids"))
      let secret = jstr(section, "client_secret")
      let config = if secret.length() > 0 {
        config.with_client_secret(secret)
      } else {
        config
      }
      let start = @microsoft.begin_auth(config, secrets)
      println("== 授权 URL（浏览器打开并登录）==")
      println(start.url)
      let query = extract_query(wait_capture(capture, timeout_s))
      let callback = @core.CallbackParams::from_query_string(query)
      @microsoft.complete_auth(config, callback, start)
    } else if platform == "github" {
      let config = @github.GitHubConfig::new(jstr(section, "client_id"), jstr(section, "redirect_uri"))
      .with_client_secret(jstr(section, "client_secret"))
      let start = @github.begin_auth(config, secrets)
      println("== 授权 URL（浏览器打开并登录）==")
      println(start.url)
      let query = extract_query(wait_capture(capture, timeout_s))
      let callback = @core.CallbackParams::from_query_string(query)
      @github.complete_auth(config, callback, start)
    } else if platform == "discord" {
      let config = @discord.DiscordConfig::new(
          jstr(section, "client_id"),
          jstr(section, "redirect_uri"),
        )
        .with_client_secret(jstr(section, "client_secret"))
      let start = @discord.begin_auth(config, secrets)
      println("== 授权 URL（浏览器打开并登录）==")
      println(start.url)
      let query = extract_query(wait_capture(capture, timeout_s))
      let callback = @core.CallbackParams::from_query_string(query)
      @discord.complete_auth(config, callback, start)
    } else if platform == "x" {
      let config = @x.XConfig::new(jstr(section, "client_id"), jstr(section, "redirect_uri"))
      let start = @x.begin_auth(config, secrets)
      println("== 授权 URL（浏览器打开并登录）==")
      println(start.url)
      let query = extract_query(wait_capture(capture, timeout_s))
      let callback = @core.CallbackParams::from_query_string(query)
      @x.complete_auth(config, callback, start)
    } else if platform == "dingtalk" {
      let config = @dingtalk.DingTalkConfig::new(
          jstr(section, "client_id"),
          jstr(section, "client_secret"),
          jstr(section, "redirect_uri"),
        )
      let start = @dingtalk.begin_auth(config, secrets)
      println("== 授权 URL（浏览器打开并登录）==")
      println(start.url)
      let query = extract_query(wait_capture(capture, timeout_s))
      let callback = @core.CallbackParams::from_query_string(query)
      @dingtalk.complete_auth(config, callback, start)
    } else if platform == "feishu" {
      let config = @feishu.FeishuConfig::new(
          jstr(section, "client_id"),
          jstr(section, "client_secret"),
          jstr(section, "redirect_uri"),
        )
      let start = @feishu.begin_auth(config, secrets)
      println("== 授权 URL（浏览器打开并登录）==")
      println(start.url)
      let query = extract_query(wait_capture(capture, timeout_s))
      let callback = @core.CallbackParams::from_query_string(query)
      @feishu.complete_auth(config, callback, start)
    } else if platform == "alipay" {
      let config = @alipay.AlipayConfig::new(
          jstr(section, "app_id"),
          @core.SigningKey::Pem(jstr(section, "private_key_pem")),
          jstr(section, "redirect_uri"),
        )
        .with_endpoints(
          jstr(section, "gateway"),
          jstr(section, "authorize"),
          jstr(section, "scope"),
        )
      let start = @alipay.begin_auth(config, secrets)
      println("== 授权 URL（沙箱版钱包或浏览器打开并登录）==")
      println(start.url)
      let query = extract_query(wait_capture(capture, timeout_s))
      let callback = @core.CallbackParams::from_query_string(query)
      @alipay.complete_auth(config, callback, start)
    } else if platform == "wechat" {
      let config = @wechat.WeChatConfig::new(
          jstr(section, "client_id"),
          jstr(section, "client_secret"),
          jstr(section, "redirect_uri"),
        )
        .with_endpoints(
          jstr(section, "authorize"),
          jstr(section, "token"),
          jstr(section, "userinfo"),
        )
        .with_scope(jstr(section, "scope"))
      let start = @wechat.begin_auth(config, secrets)
      println("== 授权 URL（微信内打开并授权；PC 浏览器会显示二维码）==")
      println(start.url)
      let query = extract_query(wait_capture(capture, timeout_s))
      let callback = @core.CallbackParams::from_query_string(query)
      @wechat.complete_auth(config, callback, start)
    } else if platform == "qq" {
      let config = @qq.QQConfig::new(
          jstr(section, "client_id"),
          jstr(section, "client_secret"),
          jstr(section, "redirect_uri"),
        )
      let start = @qq.begin_auth(config, secrets)
      println("== 授权 URL（浏览器打开并登录）==")
      println(start.url)
      let query = extract_query(wait_capture(capture, timeout_s))
      let callback = @core.CallbackParams::from_query_string(query)
      @qq.complete_auth(config, callback, start)
    } else {
      raise @core.ParseError(
        "moonauth: l2 未知 platform: " + platform + "（支持 google/microsoft/github/discord/x/dingtalk/feishu/alipay/wechat/qq；apple 需付费资质不在 harness）",
      )
    }
    print_record(platform, identity)
      } catch {
        e => println("L2 失败: " + @core.auth_error_message(e))
      }
    }
  } catch {
    e => println("L2 外层失败: \{e}")
  }
}

///|
async fn main {
  try {
    run()
  } catch {
    e => println("L2 失败: " + @core.auth_error_message(e))
  }
}
