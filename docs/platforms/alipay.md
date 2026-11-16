# 支付宝（Alipay）接入

> 子包：`justinwongcn/moonauth/provider/alipay`
> 协议：**非标准 OAuth 2.0**。走网关 `POST openapi.alipay.com/gateway.do`，RSA2 签名。

## 1. 申请步骤

1. 打开[支付宝开放平台](https://open.alipay.com/) → 创建**网页/移动应用**。
2. 在应用里开通 **「获取会员信息」**（`auth_user`）能力。
3. **应用私钥 / 公钥**：用官方工具生成 RSA2 密钥对，上传**应用公钥**，下载**支付宝公钥**。
   - 库只用**应用私钥**做签名（`SigningKey`）；验签支付宝响应需要**支付宝公钥**（由你自行处理）。
4. 在「授权回调地址」里登记你的回调。
5. 记下 **App ID**。

## 2. 库内配置

```moonbit
let private_key : @core.SigningKey = @core.SigningKey::Pem(app_private_key_pem)
let config = @alipay.AlipayConfig::new("APP_ID", private_key, "https://your.app/auth/alipay/callback")
```

| 字段 | 默认值 |
|---|---|
| `gateway_endpoint` | `https://openapi.alipay.com/gateway.do` |
| `authorize_endpoint` | `https://openauth.alipay.com/oauth2/publicAppAuthorize.htm` |
| `scope` | `auth_user` |

链式覆盖：`with_endpoints(gateway, authorize, scope)` / `with_signer` / `with_http` / `with_clock` / `with_random`。

## 3. 用法

```moonbit
let start = @alipay.begin_auth(config, @core.SuppliedSecrets::{ state: None, code_verifier: None, nonce: None })
// 302 到 start.url（publicAppAuthorize.htm?...）
// 回调用 `auth_code`（旧版）或 `code`（新版）
let callback = @core.CallbackParams::from_query_string("auth_code=...&state=...")
let identity = @alipay.complete_auth(config, callback, start)
```

底层可单用（签名 / 网关）：

```moonbit
@alipay.alipay_signing_string(params)   // 拼「待签名字符串」（去空值、key ASCII 升序、原值不编码）
@alipay.alipay_sign(config, params)     // SHA256withRSA + Base64 -> sign
@alipay.alipay_gateway_call(config, method, charset, params)
@alipay.alipay_fetch_token(config, auth_code)       // alipay.system.oauth.token
@alipay.alipay_fetch_userinfo(config, access_token) // alipay.user.info.share
```

## 4. 🔴 踩坑点（**最容易“必错却难查”**的一家）

- 🔴🔴 **参数 key 必须按 ASCII 升序**：支付宝要求 `app_id` → `biz_content` → `charset` → `format` → `method` →
  `sign_type` → `timestamp` → `version` 的**逐字节**顺序。
  ⚠️ **MoonBit 的 `String::compare` 不是字典序**——它**先比长度**再比内容，用它排序会得到完全不同的顺序，
  而支付宝只回 `isv.invalid-signature`、**不提示是排序问题**。
  库一律走 `@core` 的字节字典序工具（`sort_lexicographic` / `sorted_keys`），**不要**自己用默认排序。
- **去空值**：`sign` 字段本身、以及**值为空字符串**的参数都要**剔除**后再签名。
- **原值不 URL 编码**：签名串里用**原始值**拼接；URL 编码只在**发送时**对整串做，**不参与签名**。
- **签名算法是 `RSA2`**（即 SHA256withRSA），签名结果 **Base64** 后放入 `sign`。
- **公共参数固定**：`format=JSON`、`charset=utf-8`、`sign_type=RSA2`、`version=1.0`（库已按官方示例拼装）。
- **换 token 与取用户是两次网关调用**：`alipay.system.oauth.token` → `access_token`（含 `open_id` / `user_id`），
  再 `alipay.user.info.share` 取详情。
- 🔴 **身份键：`open_id` 优先、`user_id` 兜底**（2026-11-17 按官方口径修正）。支付宝官方说明：
  「新商户建议使用 `open_id` 替代该字段；对于新商户，`user_id` 字段未来计划逐步回收，存量商户可继续使用」，
  两字段在响应中**二选一**。库的 `uid` 取值：`open_id`（userinfo / token 任一带出即采用）→ `user_id` →
  都缺失时 `ParseError`。`uid_kind` 恒为 `Stable`（平台保证在本应用内稳定，与 QQ `openid` 同类）；
  跨应用关联需 `union_id`（仅商家应用分组等条件下返回，**返回条件待真实应用验证，本库暂不读取**）。
  ⚠️ 存量应用若曾以 `user_id` 建立绑定，切换/升级应用形态后标识可能变化——绑定策略由调用方负责。
- **`auth_code` vs `code`**：回调可能给旧版 `auth_code` 或新版 `code`，库两者都接受。
- **错误体**：响应 JSON 里若有 `error_response`，库归一为 `ProviderError`（`sub_code` / `sub_msg` 保留在消息里）。
- **`state` 回转风险**（调研核对补充）：官方页面强调的回调核心参数是 `auth_code` / `app_id` / `scope`；
  `state` 的实际回转行为必须用真实网站应用验证——若真实环境不回转 `state`，库的默认硬校验会
  直接 `MissingParam` / `StateMismatch`。生产可用前必须实测（L2 清单项）。

## 5. 相关源码

- 配置：`provider/alipay/config.mbt`
- 签名串 / 签名：`provider/alipay/sign.mbt`
- 网关 / 身份：`provider/alipay/gateway.mbt`
- facade：`provider/alipay/facade.mbt`
