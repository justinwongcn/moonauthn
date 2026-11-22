//! moonauth / core —— provider 元信息数据表（provider_descriptor）。
//!
//! 纯数据、无逻辑分支。新增 provider 时，只需在此表登记一行（架构 §10.7 第 9 步），
//! 不触碰任何既有子包。

///|
/// 库内平台文档的 URL 前缀。
const DOC_URL_PREFIX : String = "https://github.com/justinwongcn/moonauthn/blob/main/docs/platforms/"

///|
/// 返回十个平台的描述表（顺序稳定：google, apple, wechat, qq, alipay, x, github, discord, dingtalk, feishu）。
pub fn all_providers() -> Array[ProviderDescriptor] {
  [
    {
      id: "google",
      display_name: "Google",
      supports_pkce: true,
      supports_id_token: true,
      uid_kind: Stable,
      doc_url: DOC_URL_PREFIX + "google.md",
    },
    {
      id: "apple",
      display_name: "Apple",
      supports_pkce: true,
      supports_id_token: true,
      uid_kind: Stable,
      doc_url: DOC_URL_PREFIX + "apple.md",
    },
    {
      id: "wechat",
      display_name: "WeChat",
      supports_pkce: false,
      supports_id_token: false,
      uid_kind: Stable,
      doc_url: DOC_URL_PREFIX + "wechat.md",
    },
    {
      id: "qq",
      display_name: "QQ",
      supports_pkce: false,
      supports_id_token: false,
      uid_kind: Stable,
      doc_url: DOC_URL_PREFIX + "qq.md",
    },
    {
      id: "alipay",
      display_name: "Alipay",
      supports_pkce: false,
      supports_id_token: false,
      uid_kind: Stable,
      doc_url: DOC_URL_PREFIX + "alipay.md",
    },
    {
      id: "x",
      display_name: "X",
      supports_pkce: true,
      supports_id_token: false,
      uid_kind: Stable,
      doc_url: DOC_URL_PREFIX + "x.md",
    },
    {
      id: "github",
      display_name: "GitHub",
      supports_pkce: true,
      supports_id_token: false,
      uid_kind: Stable,
      doc_url: DOC_URL_PREFIX + "github.md",
    },
    {
      id: "discord",
      display_name: "Discord",
      supports_pkce: true,
      supports_id_token: false,
      uid_kind: Stable,
      doc_url: DOC_URL_PREFIX + "discord.md",
    },
    {
      id: "dingtalk",
      display_name: "DingTalk",
      supports_pkce: true,
      supports_id_token: false,
      uid_kind: Stable,
      doc_url: DOC_URL_PREFIX + "dingtalk.md",
    },
    {
      id: "feishu",
      display_name: "Feishu / Lark",
      supports_pkce: true,
      supports_id_token: false,
      uid_kind: Stable,
      doc_url: DOC_URL_PREFIX + "feishu.md",
    },
    {
      id: "microsoft",
      display_name: "Microsoft Entra ID",
      supports_pkce: true,
      supports_id_token: true,
      uid_kind: Stable,
      doc_url: DOC_URL_PREFIX + "microsoft.md",
    },
  ]
}

///|
/// 按 `id` 查询单个 provider 描述；不存在时返回 `None`。
pub fn provider_descriptor(id : String) -> ProviderDescriptor? {
  for p in all_providers() {
    if p.id == id {
      return Some(p)
    }
  }
  None
}

///|
/// 返回全部 provider 的 `id`（顺序与 `all_providers` 一致）。
pub fn provider_ids() -> Array[String] {
  all_providers().map(p => p.id)
}
