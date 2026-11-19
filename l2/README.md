# L2 真实回流 harness（手动运行，不入 CI）

用途：验证各平台「成功响应形状」（实现契约 §14.1 的真实请求验证）。工具形态 =
**双模式**：①回调自动捕获（默认——harness 起回调服务器于
`http://localhost:<callback_port>`，浏览器 redirect 自动命中并回显友好页面）；
②粘贴兜底（浏览器与 harness 不同机时，把地址栏完整 URL 写入 `l2/callback.txt`）。

## 流程

1. `cp l2/config.example.json l2/config.json`，填对应平台的凭据；
2. `moon run l2 --target native`；
3. harness 打印**授权 URL** → 浏览器打开并完成登录授权；
4. 回调被自动捕获（同机）；不同机则把地址栏完整 URL 粘贴到 `l2/callback.txt`；
5. harness 捕获 → `complete_auth` → 打印 **L2 记录**（provider/uid/uid_kind/email/
   extra 声明）→ 存入平台验收清单。

## 平台注册清单（轻量路径）

| 平台 | 注册位置 | 要点 |
|---|---|---|
| microsoft | **零注册冒烟可用**（见下节）；生产用 entra.microsoft.com 应用注册 | redirect 填 localhost |
| google | console.cloud.google.com → OAuth 客户端（Web） | redirect 填 `http://localhost:9876/callback`；测试用户加自己 |
| github | github.com/settings/developers → OAuth App | 即时生效，测试用户 = 自己 |
| discord | discord.com/developers → OAuth2 | redirect 填 localhost |
| x | developer.x.com → App → User authentication | 开启 OAuth 2.0，redirect 填 localhost |
| dingtalk | open.dingtalk.com → 企业内部应用（扫码登录） | 个人可建；测试组织用于授权账号 |
| feishu | open.feishu.cn → 企业自建应用 + 测试企业 | 免审核，redirect 填 localhost |
| alipay | open.alipay.com → 控制台 → **沙箱** | 沙箱 appid/网关 + 沙箱版钱包登录授权 |
| wechat | mp.weixin.qq.com → **公众号测试号** | 网页授权回调域名填 `127.0.0.1`（替代路径，非 qrconnect 主形态） |
| qq | connect.qq.com（需 **ICP 备案域名**） | 无备案则推迟 |
| apple | 不在本 harness | form_post 回调 + 付费开发者资质，推迟 |

## 零注册冒烟：microsoft（2026-11-20 已实测通过）

Azure CLI 的 client_id（`04b07795-8ddb-461a-bbee-02f9e1bf7b46`）是微软一方多租户
**公开客户端**——无需应用注册即可发起 OIDC 授权码 + PKCE 流程（仅冒烟验库；
生产请用你自己的应用注册 + 显式 tenant-id）。配置：

```json
{
  "platform": "microsoft",
  "callback_port": 9876,
  "timeout_seconds": 900,
  "microsoft": {
    "client_id": "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
    "redirect_uri": "http://localhost:9876",
    "tenant": "common"
  }
}
```

- 🔴 redirect 用**无路径** `http://localhost:9876`——Azure CLI 注册的是无路径
  `http://localhost`，loopback 匹配端口可变但**路径必须一致**；
- 🔴 `client_secret` 留空（或不填该字段）= 公开客户端 PKCE-only，不发 secret；
- 实测已覆盖：消费者租户（MSA）per-tenant issuer 验签、`email_verified=false`
  归一、nonce/state 回程（详见 `docs/platforms/microsoft.md` §6）。

## 注意

- `l2/config.json` / `l2/callback.txt` / `l2/records/` 已 gitignore——凭据绝不入库；
- harness 退出后**删除 `l2/callback.txt` 残留**（旧 state 会立即被下一轮 paste
  模式捕获，导致 state mismatch）；
- 微信测试号的授权需在**微信内**打开授权 URL（PC 浏览器显示二维码，扫码亦可）；
- alipay 用**沙箱版钱包**或浏览器打开沙箱授权页；
- 记录格式 = 本 harness 打印的「L2 记录」块，逐平台粘贴进验收清单。
