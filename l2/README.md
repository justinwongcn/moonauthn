# L2 真实回流 harness（手动运行，不入 CI）

用途：验证各平台「成功响应形状」（实现契约 §14.1 的真实请求验证）。工具形态 =
**粘贴回调 URL 模式**（零回调服务器、零端口占用、零外部网络依赖）。

## 流程

1. `cp l2/config.example.json l2/config.json`，填对应平台的凭据；
2. `moon run l2 --target native`；
3. harness 打印**授权 URL** → 浏览器打开并完成登录授权；
4. 浏览器跳转到 redirect_uri（未监听会显示打不开——正常），复制地址栏**完整 URL**；
5. 粘贴到 `l2/callback.txt` 并保存；
6. harness 捕获 → `complete_auth` → 打印 **L2 记录**（provider/uid/uid_kind/email/
   extra 声明）→ 存入平台验收清单。

## 平台注册清单（轻量路径）

| 平台 | 注册位置 | 要点 |
|---|---|---|
| google | console.cloud.google.com → OAuth 客户端（Web） | redirect 填 `http://localhost:9876/callback`；测试用户加自己 |
| microsoft | entra.microsoft.com → 应用注册（Web） | redirect 填 localhost；tenant 建议 organizations |
| github | github.com/settings/developers → OAuth App | 即时生效，测试用户 = 自己 |
| discord | discord.com/developers → OAuth2 | redirect 填 localhost |
| x | developer.x.com → App → User authentication | 开启 OAuth 2.0，redirect 填 localhost |
| dingtalk | open.dingtalk.com → 企业内部应用（扫码登录） | 个人可建；测试组织用于授权账号 |
| feishu | open.feishu.cn → 企业自建应用 + 测试企业 | 免审核，redirect 填 localhost |
| alipay | open.alipay.com → 控制台 → **沙箱** | 沙箱 appid/网关 + 沙箱版钱包登录授权 |
| wechat | mp.weixin.qq.com → **公众号测试号** | 网页授权回调域名填 `127.0.0.1`（替代路径，非 qrconnect 主形态） |
| qq | connect.qq.com（需 **ICP 备案域名**） | 无备案则推迟 |
| apple | 不在本 harness | form_post 回调 + 付费开发者资质，推迟 |

## 注意

- `l2/config.json` / `l2/callback.txt` / `l2/records/` 已 gitignore——凭据绝不入库；
- 微信测试号的授权需在**微信内**打开授权 URL（PC 浏览器显示二维码，扫码亦可）；
- alipay 用**沙箱版钱包**或浏览器打开沙箱授权页；
- 记录格式 = 本 harness 打印的「L2 记录」块，逐平台粘贴进验收清单。
