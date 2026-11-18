//! moonauth / l2 —— **L2 真实回流 harness**（Owner 手动运行；不入 CI、不入库凭据）。
//!
//! 用途：验证各平台「成功响应形状」（实现契约 §14.1 的真实请求验证）。
//!
//! 流程（粘贴回调 URL 模式，零回调服务器、零端口占用）：
//! 1. 读 `l2/config.json`（凭据，已 gitignore；模板 `config.example.json`）；
//! 2. 按 `platform` 构造 provider 配置 → `begin_auth` → 打印授权 URL；
//! 3. Owner 在浏览器完成登录授权——浏览器跳转到 redirect_uri（无需本地监听，
//!    打不开也正常）；
//! 4. 把地址栏**完整回调 URL** 粘贴到 `l2/callback.txt` 并保存；
//! 5. harness 轮询捕获（1s 间隔，超时 `timeout_seconds`）→ 解析 query →
//!    `complete_auth` → 打印 L2 记录。
//!
//! 🔴 凭据绝不入库：`l2/config.json` / `l2/callback.txt` / `l2/records/` 均已 gitignore。
//! 🔴 apple 不在本 harness（form_post 回调的 code 在 POST 体里，粘贴模式拿不到 +
//! 需付费开发者资质）；qq 需备案域名。

let config_path : String = "l2/config.json"
let callback_path : String = "l2/callback.txt"

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
/// 等待回调 URL：轮询 `callback_path`（1s 间隔），超时 `timeout_s` 秒。
/// 捕获后返回**原始粘贴内容**（完整 URL 或裸 query 均可）。
async fn wait_callback(timeout_s : Int) -> String raise @core.AuthError {
  println("== 等待回调 ==")
  println(
    "完成授权后，把浏览器地址栏的完整回调 URL 写入 \{callback_path} 并保存（\{timeout_s}s 内）",
  )
  let mut waited = 0
  while waited < timeout_s {
    let txt = @async_fs.read_file(callback_path).text() catch {
      _ => ""
    }
    if txt.length() > 0 {
      println("已捕获回调 URL（等待 \{waited}s）")
      return txt
    }
    @async.sleep(1000)
    waited = waited + 1
  }
  raise @core.Network(
    "moonauth: L2 等待回调超时（\{timeout_s}s）——未捕获 " + callback_path,
  )
}

///|
/// 从粘贴内容提取 query：取 `?` 之后、`#` 之前的部分；无 `?` 时原样返回。
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
  let identity = if platform == "google" {
    run_google(section, timeout_s)
  } else if platform == "microsoft" {
    run_microsoft(section, timeout_s)
  } else if platform == "github" {
    run_github(section, timeout_s)
  } else if platform == "discord" {
    run_discord(section, timeout_s)
  } else if platform == "x" {
    run_x(section, timeout_s)
  } else if platform == "dingtalk" {
    run_dingtalk(section, timeout_s)
  } else if platform == "feishu" {
    run_feishu(section, timeout_s)
  } else if platform == "alipay" {
    run_alipay(section, timeout_s)
  } else if platform == "wechat" {
    run_wechat(section, timeout_s)
  } else if platform == "qq" {
    run_qq(section, timeout_s)
  } else {
    raise @core.ParseError(
      "moonauth: l2 未知 platform: " + platform + "（支持 google/microsoft/github/discord/x/dingtalk/feishu/alipay/wechat/qq）",
    )
  }
  print_record(platform, identity)
}

///|
/// google：GCP 免费创建 OAuth 客户端（Web，redirect 填 http://localhost:9876/callback），
/// 测试用户添加自己的账号（外部应用测试模式即时生效）。
async fn run_google(
  sec : Map[String, Json],
  timeout_s : Int,
) -> @core.ExternalIdentity raise @core.AuthError {
  let config = @google.GoogleConfig::new(jstr(sec, "client_id"), jstr(sec, "redirect_uri"))
  let secret = jstr(sec, "client_secret")
  let config = if secret.length() > 0 {
    config.with_client_secret(secret)
  } else {
    config
  }
  let secrets : @core.SuppliedSecrets = {
    state: None,
    code_verifier: None,
    nonce: None,
  }
  let start = @google.begin_auth(config, secrets)
  println("== 授权 URL（浏览器打开并登录）==")
  println(start.url)
  let query = extract_query(wait_callback(timeout_s))
  let callback = @core.CallbackParams::from_query_string(query)
  @google.complete_auth(config, callback, start)
}

///|
/// microsoft：Entra 免费租户应用注册（Web redirect，http://localhost 允许）；
/// tenant 默认 organizations；allowed_tenant_ids 非空时启用租户白名单。
async fn run_microsoft(
  sec : Map[String, Json],
  timeout_s : Int,
) -> @core.ExternalIdentity raise @core.AuthError {
  let config = @microsoft.MicrosoftConfig::new(jstr(sec, "client_id"), jstr(sec, "redirect_uri"))
  .with_client_secret(jstr(sec, "client_secret"))
  .with_tenant(jstr(sec, "tenant"))
  .with_allowed_tenant_ids(jstr_array(sec, "allowed_tenant_ids"))
  let secrets : @core.SuppliedSecrets = {
    state: None,
    code_verifier: None,
    nonce: None,
  }
  let start = @microsoft.begin_auth(config, secrets)
  println("== 授权 URL（浏览器打开并登录）==")
  println(start.url)
  let query = extract_query(wait_callback(timeout_s))
  let callback = @core.CallbackParams::from_query_string(query)
  @microsoft.complete_auth(config, callback, start)
}

///|
/// github：OAuth App 即时创建（Settings → Developer settings），回调
/// http://localhost:9876/callback；测试用户 = 自己的 GitHub 账号。
async fn run_github(
  sec : Map[String, Json],
  timeout_s : Int,
) -> @core.ExternalIdentity raise @core.AuthError {
  let config = @github.GitHubConfig::new(jstr(sec, "client_id"), jstr(sec, "redirect_uri"))
  .with_client_secret(jstr(sec, "client_secret"))
  let secrets : @core.SuppliedSecrets = {
    state: None,
    code_verifier: None,
    nonce: None,
  }
  let start = @github.begin_auth(config, secrets)
  println("== 授权 URL（浏览器打开并登录）==")
  println(start.url)
  let query = extract_query(wait_callback(timeout_s))
  let callback = @core.CallbackParams::from_query_string(query)
  @github.complete_auth(config, callback, start)
}

///|
/// discord：开发者后台即时创建应用（OAuth2 → redirect）。
async fn run_discord(
  sec : Map[String, Json],
  timeout_s : Int,
) -> @core.ExternalIdentity raise @core.AuthError {
  let config = @discord.DiscordConfig::new(jstr(sec, "client_id"), jstr(sec, "redirect_uri"))
  .with_client_secret(jstr(sec, "client_secret"))
  let secrets : @core.SuppliedSecrets = {
    state: None,
    code_verifier: None,
    nonce: None,
  }
  let start = @discord.begin_auth(config, secrets)
  println("== 授权 URL（浏览器打开并登录）==")
  println(start.url)
  let query = extract_query(wait_callback(timeout_s))
  let callback = @core.CallbackParams::from_query_string(query)
  @discord.complete_auth(config, callback, start)
}

///|
/// x：免费开发者账号（User authentication settings 开启 OAuth 2.0）。
async fn run_x(
  sec : Map[String, Json],
  timeout_s : Int,
) -> @core.ExternalIdentity raise @core.AuthError {
  let config = @x.XConfig::new(jstr(sec, "client_id"), jstr(sec, "redirect_uri"))
  let secrets : @core.SuppliedSecrets = {
    state: None,
    code_verifier: None,
    nonce: None,
  }
  let start = @x.begin_auth(config, secrets)
  println("== 授权 URL（浏览器打开并登录）==")
  println(start.url)
  let query = extract_query(wait_callback(timeout_s))
  let callback = @core.CallbackParams::from_query_string(query)
  @x.complete_auth(config, callback, start)
}

///|
/// dingtalk：个人可创建企业内部应用（扫码登录）；测试组织可用于授权账号。
async fn run_dingtalk(
  sec : Map[String, Json],
  timeout_s : Int,
) -> @core.ExternalIdentity raise @core.AuthError {
  let config = @dingtalk.DingTalkConfig::new(
    jstr(sec, "client_id"),
    jstr(sec, "client_secret"),
    jstr(sec, "redirect_uri"),
  )
  let secrets : @core.SuppliedSecrets = {
    state: None,
    code_verifier: None,
    nonce: None,
  }
  let start = @dingtalk.begin_auth(config, secrets)
  println("== 授权 URL（浏览器打开并登录）==")
  println(start.url)
  let query = extract_query(wait_callback(timeout_s))
  let callback = @core.CallbackParams::from_query_string(query)
  @dingtalk.complete_auth(config, callback, start)
}

///|
/// feishu：免费创建企业自建应用 + 测试企业（免审核）；redirect 配置在应用安全设置。
async fn run_feishu(
  sec : Map[String, Json],
  timeout_s : Int,
) -> @core.ExternalIdentity raise @core.AuthError {
  let config = @feishu.FeishuConfig::new(
    jstr(sec, "client_id"),
    jstr(sec, "client_secret"),
    jstr(sec, "redirect_uri"),
  )
  let secrets : @core.SuppliedSecrets = {
    state: None,
    code_verifier: None,
    nonce: None,
  }
  let start = @feishu.begin_auth(config, secrets)
  println("== 授权 URL（浏览器打开并登录）==")
  println(start.url)
  let query = extract_query(wait_callback(timeout_s))
  let callback = @core.CallbackParams::from_query_string(query)
  @feishu.complete_auth(config, callback, start)
}

///|
/// alipay：**官方沙箱**（沙箱 appid + 应用私钥/支付宝公钥 + 沙箱网关 + 沙箱版钱包
/// 登录授权）；gateway/authorize 按 config 覆盖（默认生产端点，L2 请用沙箱值）。
async fn run_alipay(
  sec : Map[String, Json],
  timeout_s : Int,
) -> @core.ExternalIdentity raise @core.AuthError {
  let config = @alipay.AlipayConfig::new(
    jstr(sec, "app_id"),
    @core.SigningKey::Pem(jstr(sec, "private_key_pem")),
    jstr(sec, "redirect_uri"),
  )
  .with_endpoints(
    jstr(sec, "gateway"),
    jstr(sec, "authorize"),
    jstr(sec, "scope"),
  )
  let secrets : @core.SuppliedSecrets = {
    state: None,
    code_verifier: None,
    nonce: None,
  }
  let start = @alipay.begin_auth(config, secrets)
  println("== 授权 URL（沙箱版钱包或浏览器打开并登录）==")
  println(start.url)
  let query = extract_query(wait_callback(timeout_s))
  let callback = @core.CallbackParams::from_query_string(query)
  @alipay.complete_auth(config, callback, start)
}

///|
/// wechat：L2 用**公众号测试号**（个人免费即时开通，网页授权回调域名可填
/// 127.0.0.1）——端点经 config 覆盖为公众号网页授权形态（snsapi_userinfo）；
/// qrconnect 主形态需企业资质，验收差异已记平台文档。
async fn run_wechat(
  sec : Map[String, Json],
  timeout_s : Int,
) -> @core.ExternalIdentity raise @core.AuthError {
  let config = @wechat.WeChatConfig::new(
    jstr(sec, "client_id"),
    jstr(sec, "client_secret"),
    jstr(sec, "redirect_uri"),
  )
  .with_endpoints(
    jstr(sec, "authorize"),
    jstr(sec, "token"),
    jstr(sec, "userinfo"),
  )
  .with_scope(jstr(sec, "scope"))
  let secrets : @core.SuppliedSecrets = {
    state: None,
    code_verifier: None,
    nonce: None,
  }
  let start = @wechat.begin_auth(config, secrets)
  println("== 授权 URL（微信内打开并授权；PC 浏览器会显示二维码）==")
  println(start.url)
  let query = extract_query(wait_callback(timeout_s))
  let callback = @core.CallbackParams::from_query_string(query)
  @wechat.complete_auth(config, callback, start)
}

///|
/// qq：个人可注册开发者，但**回调域名必须 ICP 备案**——L2 需备案域名（或推迟）。
async fn run_qq(
  sec : Map[String, Json],
  timeout_s : Int,
) -> @core.ExternalIdentity raise @core.AuthError {
  let config = @qq.QQConfig::new(
    jstr(sec, "client_id"),
    jstr(sec, "client_secret"),
    jstr(sec, "redirect_uri"),
  )
  let secrets : @core.SuppliedSecrets = {
    state: None,
    code_verifier: None,
    nonce: None,
  }
  let start = @qq.begin_auth(config, secrets)
  println("== 授权 URL（浏览器打开并登录）==")
  println(start.url)
  let query = extract_query(wait_callback(timeout_s))
  let callback = @core.CallbackParams::from_query_string(query)
  @qq.complete_auth(config, callback, start)
}

///|
async fn main {
  try {
    run()
  } catch {
    e => println("L2 失败: " + @core.auth_error_message(e))
  }
}
