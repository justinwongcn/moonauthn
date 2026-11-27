# moonauth

moonauth 是一个不依赖 Web 框架的 MoonBit 认证库。它提供 11 个第三方登录适配器，也支持 Passkey（WebAuthn）和 TOTP。

库用 `ExternalIdentity` 表示第三方身份。应用负责创建账号、绑定身份和管理登录会话。

## 安装

```bash
moon add justinwongcn/moonauthn@0.1.1
```

库支持 `native` 和 `js`，本仓库默认使用 `native`。生成随机数用的 `getrandom` 不支持 `wasm-gc`，因此库也不支持该目标。

## 接入 Google 登录

先在 Google Cloud 中创建 Web 应用的 OAuth 客户端，登记回调地址。完整设置见 [Google 接入文档](docs/platforms/google.md)。

在应用的 `moon.pkg` 中导入 Google 适配器和共用类型：

```moonbit
import {
  "justinwongcn/moonauthn/core" @core,
  "justinwongcn/moonauthn/provider/google" @google,
}
```

发起登录时，在异步处理函数中构造配置并调用 `begin_auth`。客户端密钥从应用的服务端配置读取。

```moonbit
let config = @google.GoogleConfig::new(client_id, redirect_uri)
  .with_client_secret(client_secret)
let start = @google.begin_auth(config, {
  state: None,
  code_verifier: None,
  nonce: None,
})
```

这三个字段留空时，库会生成相应的值。将完整的 `AuthStart` 与发起登录的会话关联，在服务端短期保存，再把浏览器重定向到 `start.url`。

收到回调后，把 `?` 后的原始查询串交给解析器，不要用解码后的值重拼。应用根据当前会话和回调中的 `state` 原子取出并删除对应的 `AuthStart`。没有匹配的记录就拒绝回调。

```moonbit
let callback = @core.CallbackParams::from_query_string(raw_query)
let state = callback.required_non_empty("state")
// 应用根据当前会话和 state 取出并删除 start。
let identity = @google.complete_auth(config, callback, start)
```

在异步回调处理函数中沿用发起登录时的配置。库先校验 `state`，再用授权码换取并验证 Google 的 ID token。返回的 `identity.uid` 是 Google 的 `sub`，应用可用它查询 Google 的身份绑定记录。

## 第三方平台

各平台适配器互不依赖，应用按需导入 `provider/…` 子包。

- [Google](docs/platforms/google.md)、[Apple](docs/platforms/apple.md)、[Microsoft Entra ID](docs/platforms/microsoft.md)
- [微信（含小程序登录）](docs/platforms/wechat.md)、[QQ](docs/platforms/qq.md)、[支付宝](docs/platforms/alipay.md)
- [GitHub](docs/platforms/github.md)、[Discord](docs/platforms/discord.md)、[X（Twitter）](docs/platforms/x.md)
- [钉钉](docs/platforms/dingtalk.md)、[飞书 / Lark](docs/platforms/feishu.md)

接入 Lark 时，使用 Lark 应用凭据，并调用 `with_lark()` 切换端点。钉钉只内置国内站端点，国际站端点需要自行确认，再用 `with_endpoints` 配置。

## 其他子包

| 子包 | 用途 |
| --- | --- |
| `core` | 共用类型、错误和接口，例如 `ExternalIdentity`、`AuthError`、`HttpClient` |
| `oauth` | OAuth 2.0 授权码流程和 PKCE |
| `oidc` | 通过 JWKS 获取公钥，验证 OIDC ID token |
| [`passkey`](docs/passkey.md) | 生成注册和登录选项、校验浏览器返回的凭据；浏览器调用和凭据保存由应用完成 |
| [`totp`](docs/totp.md) | 生成 TOTP 密钥和恢复码、校验验证码；应用保存密钥和恢复码哈希，并负责校验和核销恢复码 |
| `rand` | `RandomSource` 的默认实现 |
| `store-memory` | `ChallengeStore` 的内存实现 |
| `contract` | 可复用的契约测试和固定测试向量 |

随机数、时钟、HTTP 请求和挑战值存储均可由应用提供实现。如何替换默认的 ID token 验证器，见 [SDK 适配说明](docs/switch-to-official-sdk.md)。

## 运行示例

在本仓库根目录运行。首次检出后，可先运行 `bash ci/bootstrap.sh` 准备依赖。

```bash
moon run examples/minimal-google/src --target native
moon run examples/bare-async/src --target native
moon run examples/moonback/src --target native
moon run examples/switch-sdk/src --target native
```

| 示例 | 演示内容 |
| --- | --- |
| [`minimal-google`](examples/minimal-google) | 只导入 `provider/google`，打印配置，不发起授权请求 |
| [`bare-async`](examples/bare-async) | 模拟 Google 回调，用测试向量演示 Passkey 和 TOTP |
| [`moonback`](examples/moonback) | 用本机回环请求测试登录和回调路由，第三方响应是模拟的 |
| [`switch-sdk`](examples/switch-sdk) | 用固定结果演示如何替换 `IdTokenVerifier`；不验签，也未接入官方 SDK |

示例不需要平台凭证，也不访问第三方登录服务。四个示例都是独立模块，通过 `moon.work` 使用本地库源码。

## 开发检查

```bash
bash ci/check.sh
```

[检查脚本](ci/check.sh)会准备依赖，构建并测试 `native` 和 `js`，同时检查平台包隔离、公开接口类型和文档引用。测试只运行本库的用例，不包含随库引入的第三方测试。

如果你的项目曾参考 v1 的认证服务方案，可查阅[迁移说明](docs/migration-from-v1-service.md)。

## 许可证

[Apache-2.0](LICENSE)。随库引入的 `moonbitlang-x` 源码及其许可见[来源说明](third_party/moonbitlang-x/VENDORED.md)。
