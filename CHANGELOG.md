# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
