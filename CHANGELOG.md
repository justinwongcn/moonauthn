# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **oidc：id_token 验签增加算法白名单**（RFC 8725 §3.1）。`IdTokenExpectations` 新增
  `algorithms : Array[String]` 字段：非空时严格比对 token 头声明的 `alg`（不命中即
  `UnsupportedAlg`），空数组 = 接受实现支持的 RS/ES 族（仍绑死 JWKS 公钥）。
  Google / Apple 默认实现恒填 `["RS256"]`。
- **oidc：缺 `exp` 的 id_token 一律拒绝**（OIDC Core 将 `exp` 列为 REQUIRED 且客户端
  MUST 校验；此前缺失 `exp` 会被静默放行）。
- **oidc：JWKS 缓存健壮性**。① 200 + 不可解析体（如网关故障页）不再写入缓存
  （此前会坏整整一个 TTL 且报误导性的「no key matches」）；② kid 未命中的强制重取
  增加 60 秒节流（`forced_refetch_min_seconds`，可配置）——未认证路径上伪造随机
  `kid` 不再把每次验签放大为对 `jwks_uri` 的出站请求；③ 空 `issuers` / `audiences`
  一律 `InvalidInput`（fail-closed，不存在合法的「跳过校验」）。
- **oauth：PKCE `code_verifier` 生成护栏**：编码后长度必须落在 RFC 7636 §4.1 的
  43~128 字符（`byte_len ∈ 32..=96`），越界即 `InvalidInput`。
- **oauth：ES256/RS256 密钥解析校验曲线 / 算法**：PKCS#8 的 AlgorithmIdentifier
  必须为 `id-ecPublicKey` + `prime256v1`（RSA 路径为 `rsaEncryption`）；SEC1 标量
  宽度超出 32 字节一律 `KeyError`——此前 P-384 等异族密钥会被**静默截断**成一把
  「有效」的 P-256 键并错签。
- **totp：恢复码哈希支持 pepper**（`StandardTotpPrimitive::with_recovery_hash_pepper`）：
  设 pepper 后为 `hex(HMAC-SHA256(pepper, code))`，确定性不变（按哈希查找仍成立）。
  此前无盐的 `sha256(code)` 在哈希库泄露后可被 GPU 一次穷举批量撞出全库用户
  （全空间约 30^8 ≈ 6.6e11）。未设 pepper 时保持旧行为（生产必须设 pepper）。
- **wechat / qq / alipay：授权 URL 与 query 的动态值全部百分号编码**——调用方自带
  `state`（`SuppliedSecrets`）含 `&` / `#` 时此前会截断甚至注入 query；
  `access_token` / `openid` / `appid` / `secret` 同理。

### Fixed

- **oauth：token 响应携带 `error` 字段时优先归一为 `ProviderError`**（RFC 6749 §5.2）。
  L1 实测（2026-10-12，零凭据探测）确认 GitHub 对「有效 client_id + 无效授权码」返回
  **HTTP 200 + 错误体**（`{"error":"bad_verification_code",...}`）——此前会降级为
  信息量更低的 `ParseError`。JSON/form 两形态均覆盖。
- 🔴 **feishu：token 响应按真实 v2 形态解析**（信封优先）。真实
  `POST /authen/v2/oauth/token` 成功响应是 `{code,msg,data:{access_token,...}}`
  信封壳（与官方 Go/Node SDK 模型一致）；此前按顶层平铺解析，默认配置对真实网关
  必失败。现「信封优先、平铺兼容」，夹具与文档同步修正；非 2xx 错误体兼容
  OAuth2 标准与平台信封两形态。另记：官方已宣布 token 端点将迁 v3。
- **wechat：默认授权端点改为 `connect/qrconnect`**（开放平台网站应用扫码，与默认
  scope `snsapi_login` 及平台文档的申请路径配套）。此前默认端点 `connect/oauth2/authorize`
  （公众号）配 `snsapi_login`（开放平台专用）是无效组合，真实网关必报 10016；
  公众号 H5 场景请 `with_endpoints` + `with_scope("snsapi_userinfo")` 一并切换。
- **wechat / qq / alipay / dingtalk / feishu：信封错误码口径统一**——能解出数值且
  非零才报错（`0` 视为成功）；微信不再把 `errcode: 0` 误判为失败；钉钉 / 飞书兼容
  数值与字符串两形态。
- **alipay：`error_response` 保留 `sub_code` / `sub_msg`**——它们是支付宝唯一有用的
  排障线索（如 `isv.invalid-signature`），此前被丢弃。
- **dingtalk / feishu：空字符串 `unionId` / `union_id` 视为缺失**（降级 openId 且
  `Degraded`，同微信 `non_empty_opt` 先例）——此前会产出 `uid=""` 且标 `Stable`。
- **core：`HttpClient` 非 2xx 归一责任移至调用方**（seam 契约已写明）。默认
  `AsyncHttpClient` 不再在传输层抛 `HttpStatus`，非 2xx 响应原样返回——此前该分支
  使全部消费方（oauth / 10 个 provider）的归一逻辑成为死代码，且自定义实现下行为
  不一致；新增端到端用例锁定。
- **contract：`assert_all_pass` 失败改为 `raise AuthError`**（可捕获），不再 `abort`
  杀进程——与「所有失败路径都可被调用方 catch」的库级记账一致。
- **dingtalk / feishu：`with_scopes` 拷贝传入数组**（与 `new()` 一致，调用方后续
  改数组不穿透进配置）。

### Added

- **contract：`ChallengeStore` 参数化契约 `run_store`**——下游最可能替换的 seam
  （内存 → Redis）现在有可复跑的断言集（一次性 / peek 不消费 / TTL 边界 / 覆盖写 /
  键隔离）；`MemoryChallengeStore` 已接入。
- **contract：`run_id_token` 新增 JWKS 轮转契约 `run_id_token_rotation`** 与
  leeway 边界用例（leeway 恰好覆盖过期则接受、差 1 秒仍拒绝）。
- **qa_verify：discord 互补向量**（`global_name` 优先、非 `a_` 前缀头像取 `.png`）；
  修复了一对逐字节重复的测试。
- **examples：三个示例改为生产形状的 OAuth 流程**——`/login` 由服务端铸造并暂存
  `state`（一次性消费，重放拒绝），不再「回调时凭空重建 + 硬编码 state」；
  `bare-async` 补充 stored 流程的取用半程演示（`ChallengeMismatch` / `ChallengeNotFound`）。
- **CI 第 7 步「文档与实物一致性」机械检查**：新增 `ci/doc_check.sh`（由 `ci/check.sh` 统一调用）。
  文档中的文件路径（权威来源 `ls`/`find`）、库内包路径（`justinwongcn/moonauth/...` 对目录）、
  库内标识符（`@pkg.Ident` / `Type::name` 对 `.mbti`）必须与实物一致；「伪包名」与「不存在的文件名」
  两类历史事故已通过注入坏例验证可被捕获。检查范围为随包发布的 `README.md` / `CHANGELOG.md` / `docs/**/*.md`。
- **四个新平台 provider**：`provider/github`、`provider/discord`（标准 OAuth2 + PKCE，骑 `@oauth` seam）、
  `provider/dingtalk`、`provider/feishu`（非标准协议自拼：钉钉 token 端点 JSON 体 + 驼峰字段 +
  `x-acs-dingtalk-access-token` 鉴权头；飞书 v2 JSON 体 + `{code,msg,data}` 信封壳）。
  飞书国际版为**端点预设**：`FeishuConfig::with_lark()`（`*.larksuite.com`，已按官方文档核实）；
  **钉钉国际站端点未能从官方文档核实，库不内置预设**（诚实优先，不实现未经核实的功能；
  国际站应用用 `with_endpoints` 配置，见平台文档）。
- **钉钉 / 飞书 UID 语义**：`unionId` / `union_id` 优先（`Stable`），仅 `openId` / `open_id` 时
  `Degraded`（微信 unionid 同款先例）。
- `core/provider_descriptor` 登记四行（supports_pkce 全 true、supports_id_token 全 false）；
  `qa_verify/provider_ext_test.mbt`（库外视角对抗验证：授权 URL 含国际版预设、`state` 防线、
  归一化、随机只经 seam）。
- 四份平台文档：`docs/platforms/{github,discord,dingtalk,feishu}.md`（钉钉 / 飞书含
  「国内版与国际版」对照节与凭据隔离警告）。

### Fixed

- 新增 provider 的归一化函数一律收**原始 JSON 文本**（`qq_identity` 先例），
  `Json` 类型不出现在任何 `pub` 签名（SDK-03）。

## [0.1.0] - 2026-10-10

首个公开版本：**框架无关、零状态的第三方登录 / Passkey / 2FA 工具库**。

### Added

- **核心**
  - `core`：值类型（`ExternalIdentity` / `AuthStart` / `CallbackParams` / `TokenSet` / `IdTokenClaims` …）、
    `AuthError`（`suberror`）、能力 **seam**（`pub(open) trait`：`HttpClient` / `OAuthAuthCode` /
    `IdTokenVerifier` / `WebAuthnVerifier` / `TotpPrimitive` / `SecretSigner` / `Clock` / `RandomSource` /
    `ChallengeStore`）、UTF-8 字节**字典序**工具（`lexicographic_compare` / `sort_lexicographic` / `sorted_keys`）。
  - `rand`：`RandomSource` 默认实现 `GetrandomSource`（库内**唯一**接触 `getrandom` 的地方）。
- **协议实现**
  - `oauth`：OAuth 2.0 授权码 + PKCE 默认实现（`StandardOAuthAuthCode`）、`base64url` / `s256` 工具。
  - `oidc`：`id_token` 验签（`JwksIdTokenVerifier`，RS256 / JWKS）。
  - `passkey`：WebAuthn 验签（`StandardWebAuthnVerifier`）+ `PasskeyService`（challenge 一次性 + TTL）。
  - `totp`：TOTP（`StandardTotpPrimitive`）+ `TotpService` + 恢复码。
  - `store-memory`：`MemoryChallengeStore`（`ChallengeStore` 内存实现）。
- **六个 provider 子包**（彼此**隔离**，LIB-20）
  - `provider/google`、`provider/apple`、`provider/x`（标准 OAuth2/OIDC + PKCE），
    `provider/wechat`、`provider/qq`、`provider/alipay`（非标准协议：严格顺序 URL / JSONP / 网关 RSA2）。
- **契约测试骨架**
  - `contract`：参数化契约（`run_oauth` / `run_id_token` / `run_webauthn` / `run_totp` / `run_google`）
    + 固定测试向量，**下游可复用**（SDK-04）。
- **示例**（均为独立模块，经 `moon.work` 本地解析库，**不进**库依赖图）
  - `examples/minimal-google`（LIB-20 隔离断言）、`examples/bare-async`（Google + passkey + TOTP）、
    `examples/moonback`、`examples/mars`（框架只做路由）、`examples/switch-sdk`（官方 SDK 切换示范）。
- **文档 / 工程化**
  - `README.md`（定位 / 安装 / 5 分钟快速开始 / target 矩阵 / 「不建号·不存映射·不发会话」声明）。
  - `docs/platforms/{google,apple,wechat,qq,alipay,x}.md`（申请步骤 / 配置项 / 踩坑点）。
  - `docs/switch-to-official-sdk.md`、`docs/migration-from-v1-service.md`。
  - `ci/check.sh`（本地一键 CI）+ `.github/workflows/ci.yml`（薄壳，调用同一脚本）。

### 支持范围

| Target | 支持 |
|---|---|
| `native` | ✅ |
| `js` | ✅ |
| `wasm-gc` | ❌（`getrandom` 仅支持 `[js, native]`；原因见 README） |

### 设计要点（不可回退的决定）

- 所有 I/O 相关 seam 为 `async fn`；纯计算 seam 为同步 `fn`。
- 所有 seam 为 **`pub(open) trait`**（普通 `pub trait` 跨包不可实现）。
- 第三方错误类型**绝不**出现在任何 `pub` 签名；边界处一律转 `AuthError`。
- 随机性一律经 `RandomSource`、时间一律经 `Clock`（第三方便捷函数若直读系统随机/时间，须绕开）。
- 需**字典序**的字符串排序**一律**走 `core/lexical.mbt`（默认 `String::compare` 是长度优先，不是字典序）。

---

## 版本策略（SemVer）

本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/)：

- **MAJOR**：不兼容的公开 API 变更（含 `pub(open) trait` 的方法签名变化、`AuthError` 变体的增删/改名、
  值类型字段变化）。——对应仓库内 **SDK-03** 约定。
- **MINOR**：向后兼容地**新增**能力（新子包、新 provider、新 seam 方法带默认、新便捷函数）。
- **PATCH**：向后兼容的问题修复（协议细节修正、文档、内部实现）。

> 说明：由于库的「可替换性」依赖 `pub(open) trait` 的签名稳定，**任何 trait 方法签名变化都按 MAJOR 处理**。
> 子包按「子包 + 测试向量」为最小可合并单元推进（可先发 `0.x`）。

---

## 发布清单（Release Checklist）

> ⚠️ **本清单仅供准备与核对，请勿在自动化流程中直接执行 `moon publish`**（需要账号与授权）。

- [ ] 工作树干净，无未提交改动。
- [ ] 版本号已更新：`moon.mod` 的 `version` 与本 `CHANGELOG.md` 顶部一致。
- [ ] 本 `CHANGELOG.md` 已写上本次变更（Added / Changed / Fixed / Removed）。
- [ ] **本地 CI 全绿**：`./ci/check.sh`（native+js 编译、native+js 全量测试、LIB-20、SDK-03）。
- [ ] 泄露自检：`provider/*/pkg.generated.mbti` 无第三方类型；`provider/*` 只 import `core`。
- [ ] 示例可跑：`moon run examples/minimal-google/src`、`examples/bare-async/src`、
      `examples/moonback/src`、`examples/mars/src`、`examples/switch-sdk/src` 均正常输出。
- [ ] `README.md` 的 target 矩阵与「不建号 / 不存映射 / 不发会话」声明为最新。
- [ ] 六份平台文档的踩坑点与实现一致。
- [ ] 依赖版本已核对（`moon.mod` 的 5 个依赖）。
- [ ] （可选）`moon info` 后确认公开接口 diff 与预期一致，无意外破坏性变更。
- [ ] 打 tag：`git tag vX.Y.Z && git push --tags`。
- [ ] 发布：`moon publish`（**需人工执行并确认账号**，不在本仓库自动化范围内）。

[0.1.0]: https://github.com/justinwongcn/moonauth/releases/tag/v0.1.0
