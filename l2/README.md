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

- `l2/config.json` / `l2/callback.txt` / `l2/records/` / `l2/*.pem` 已 gitignore——凭据绝不入库；
- **运行前确认无残留 `l2.exe` 进程**（多实例并存时回调捕获互相竞争，曾导致
  捕获内容缺 query → state 缺失误报）；
- harness 退出后**删除 `l2/callback.txt` 残留**（旧 state 会立即被下一轮 paste
  模式捕获，导致 state mismatch）；
- `moon run` 输出重定向到文件是**块缓冲**，授权 URL 拿不到——用
  `script -q l2/harness.log moon run l2 --target native`（pty 行缓冲）；
- 记录格式 = 本 harness 打印的「L2 记录」块，逐平台粘贴进验收清单。

## 被墙平台的本地转发层（forwarder.py）

MoonBit HTTP 客户端不支持代理环境变量；被墙平台（google/discord/x）的
token/userinfo 端点可经本地转发层走 HTTP 代理：

```bash
python3 l2/forwarder.py \
  --listen 127.0.0.1:9877 \
  --proxy  http://127.0.0.1:7890 \
  --map /api=https://discord.com/api \
  --map /x2=https://api.twitter.com/2
```

然后在 config.json 平台节里给 token/userinfo 指向 `http://127.0.0.1:9877/...`
（google 加 `jwks_uri`，`issuer` 固定官方值——验签 issuer 与传输通道无关）。
授权端点保持官方 URL（浏览器侧自行可达）。2026-11-20 discord 已用此形态实测通过。

## 手机端授权回调形态（wechat）

公众号网页授权只能在微信客户端内打开，手机授权后回跳 `redirect_uri`——
回跳目标是**手机的 127.0.0.1**。解法：回调域与 redirect_uri 用**桌面局域网 IP**，
config 顶层 `"callback_host": "0.0.0.0"` 让 harness 监听全部接口接收手机回跳
（手机与桌面须同一 Wi-Fi）。另有测试号前置：**用户须先关注测试号**，否则授权页
报登录失败；后台「授权回调页面域名」保存后微信侧有传播延迟。

## 2026-11-20 真实回流结果（google 补记：同日稍晚重试成功）

google 客户端配置生效后重试一次通过——浏览器走系统代理，harness 的 token/jwks
走 forwarder（`--map /token=https://oauth2.googleapis.com/token --map
/jwks=https://www.googleapis.com/oauth2/v3/certs`），`issuer` 固定官方值。
真实 Google token 上 azp/aud 校验、nonce 回程、RS256 JWKS 验签全部成立。



| 平台 | 结果 | 要点 |
|---|---|---|
| microsoft | ✅ | 零注册（Azure CLI 公开客户端），消费者租户 issuer 验签，MSA `email_verified=false` 归一 |
| github | ✅ | `uid=124032292` Stable；`/user` email=null → **邮箱回退**（/user/emails）实测生效 `verified=true`；PKCE 被接受 |
| discord | ✅ | `uid=913455297832579086` Stable；forwarder 转发链路全通（chunked 请求体 + 强制 identity 编码两个坑已修） |
| feishu | ✅ | `uid=union_id` Stable；未开邮箱权限 → `email=<none>`（**文档化降级行为**实测成立）；免审权限 + 个人版自发布 |
| google | ✅ | `uid=sub` Stable，`email verified=true`；真实 Google JWKS RS256 验签（token/jwks 经 forwarder）；**azp=aud=client_id 双条款校验**在真实 token 上执行 |
| alipay | ⏸ | 沙箱配置全部完成（appid/网关/自定义公钥/本地私钥），卡在沙箱登录页验证码图/二维码间歇性加载失败 |
| wechat | ⏸ | 测试号 appID/secret/回调域（LAN IP）就绪，卡在「域名与后台配置不一致」（配置已核实正确，疑微信侧传播延迟） |
| x | ⏸ | 登录页白屏（被墙 CDN 经代理加载失败），需稳定代理环境 |
| dingtalk | ⏸ | Owner 决定跳过（当前组织无开发者权限，测试组织创建流程未走完） |

已到手的 **5 条**记录在 `l2/records/`（gitignored，含真实身份数据，不入库）。
这里只修正本地留痕数量，**不代表申报书的 9/9 目标已完成**。
