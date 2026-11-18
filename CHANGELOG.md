# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **core / 11 provider：空授权码 fail-closed**（黑客审计 E1，JEV 确认 0.992；契约
  §3.2.5「授权码存在且**长度合理**」）。新增 `CallbackParams::required_non_empty`：
  全部 backend 的 `code` / `auth_code` / `id_token` 提取统一改用（`state` 空串经
  `StateMismatch` 天然拦截，未改提取）——空字符串
  此前会通过「存在性检查」并发起注定失败的出站 token 请求，现归一为 `missing_param`。
  支付宝 `auth_code`/`code` 双形态保留非空回退语义。
- **qq / wechat / discord / oidc：空标识符拒绝**（黑客审计 E2，JEV 确认 0.979；契约
  §2.2「subject 必须存在且非空」）。空 `openid` / 空 `id` / 空 `sub` 此前会归一为
  `uid=""` 的身份（落进调用方映射表可与其它空串身份碰撞，qq 甚至标 `Stable`）；
  现一律 `ParseError` 拒绝（dingtalk/feishu 已有同款防线，本批补齐 qq/wechat/
  discord/oidc sub）。
- **oidc：多受众 id_token 的 `azp` 校验**（合规审计 F13，JEV 确认 0.992；OIDC Core
  §3.1.3.7 / 实现契约 §4.2）。`aud` 为**多值数组**时，`azp` 必须存在且等于期望受众
  之一，否则 `AudienceMismatch`——实测（microsoft 流程）：`aud=[期望,他方]` 且
  `azp=他方` 的 token 此前**通过全部校验并归一身份**。单值 `aud` 不强制 `azp`
  （Google/Entra 单资源形态，向后兼容）。
  **OCR 代码审查复核后强化**（alibaba open-code-review 对 775999c 的审查发现两处残余，
  均已修复）：① `azp` 存在时改为**无条件**校验——必须同时属于 token 自身的 `aud`
  声明值与期望受众（原实现仅对照配置集合，两集合不可互换；单值 `aud` + 外部 `azp`
  的形态此前完全放行）；② 门控取 **raw `aud` 形态**（数组含非字符串元素一律
  `ParseError`），不再经归一化视图（归一会静默丢弃非字符串元素，使 `["client-1",42]`
  绕过 azp 门控）。新增 `oidc/oidc_wbtest.mbt` 白盒单测 ×7（provider 无关地钉死
  check_azp 双条款契约）+ microsoft 集成用例 ×3（F-a 攻击回归/缺 azp/单值 aud +
  外部 azp）。
- **totp：验证窗口改「仅回看」，不再接受未来时间步**（黑客审计第 2 轮，JEV 确认 0.993）。
  `verify` 此前为 `±window` 对称——T=29 校验 step1 的码被接受（RFC 6238 附录 B 向量实测）。
  接受未来步把在线爆破窗口从 2 步扩大到 3 步、并接受预先生成的未来码，与实现契约
  §6.6.4（「校验当前时间步和至多一个前一时间步」）及 RFC 6238 §5.2（比较过去时间戳、
  网络延迟至多一个时间步）冲突。现仅回看（当前 + 前 `window` 步）。
- **qq：`client_id` 绑定校验**（黑客审计第 1 轮，JEV 确认 0.986）。`qq_parse_openid` 现在
  校验 `me` 响应携带的 `client_id`：与配置 appid 不一致（或非字符串）→
  `ProviderError("client_id_mismatch", ...)`——防他应用 openid 混入本应用身份绑定的混淆
  攻击（与调研契约对支付宝「回调 app_id 与本地一致」同构）。响应缺失 `client_id` 时
  无法校验、放行（QQ 部分响应形态历史上有缺省，已文档化）。
- **passkey：credentialId 长度上限**（黑客审计第 1 轮，JEV 确认 0.985）。注册校验结果
  的 `credential_id` 超过 **1023 字节**（WebAuthn Level 3 上限）一律 `InvalidInput` 拒绝
  ——此前无上限，攻击者可提交超大凭据交由调用方无限存储。上游 `@webauthn` 不设限，
  防线在本层收口。
- **oauth：PKCE `code_verifier` 全路径护栏**（黑客审计第 1 轮，JEV 确认 0.871）。
  `s256_challenge` 成为唯一咽喉点：长度 43~128 字符 + 字符集限 RFC 3986 unreserved
  （RFC 7636 §4.1），不合规即 `InvalidInput`——**调用方自带**的 verifier 此前完全
  不校验，错误延迟到 token 交换才由 provider 端暴露。新增
  `@oauth.validate_code_verifier`；`s256_challenge` / `verify_s256` 签名增加 `raise`。
- **core / 四 provider：回调错误参数归一**（RFC 6749 §4.1.2.1）。`CallbackParams::provider_error()`
  统一读取回调 `error` / `error_description` / `error_uri`；google / apple / github / feishu 的
  `complete_auth` 在 **state 校验通过后、读取授权码之前** 接入——用户拒绝授权
  （Google/GitHub/飞书 query、Apple form_post）现在归一为 `ProviderError`（可定位的平台
  语义），不再误报为 `missing_param`（此前与真实丢参不可区分）。Google 同时把
  「先校验 state 再处理 code」的顺序与官方回调契约对齐。
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

- **examples/bare-async：回调示例改「直传原始 query」**（黑客审计第 2 轮，JEV 确认 0.975）。
  `google_complete_from` 此前把**解码后的** `code` / `state` 重新拼接为 query 再交库解析
  ——平台下发 `code=a%26b`（解码值 `a&b`）时重拼会被二次解析碎裂。现改为 handler 直传
  原始 query（`req.query_string()` 形状），并从回调参数中取回 `state`（与
  `docs/migration-from-v1-service.md` 的对照示例一致）。
- **core：移除 `AsyncHttpClient.timeout_ms` 假超时字段**（黑客审计第 1 轮，JEV 确认 0.958）。
  该字段可设置但**从未被实现**（上游 `@http.request` 无超时参数，`moonbitlang/async` 无公开
  spawn/select/cancel 原语可竞速）——调用方设置后毫无作用，且平台端点 TCP 黑洞时请求
  无限挂起。现移除字段并在 `core/http_async.mbt` 文档化已知限制：**超时职责归调用方的
  `HttpClient` 实现**（seam 可整体替换，SDK-01），同文档另记响应体无大小上限的上游限制。
  `AsyncHttpClient::new()` 不再接受 `timeout_ms?` 参数。
- **oauth：`expires_in` 异常大值归一为 `None` 而非静默截断**（JEV 扫描第 1 轮确认）。
  `parse_int_opt` 此前对 Int64 累加无溢出检查、且 `Int64→Int32` 静默截断——平台返回
  20 位数字或 ≥2^31 的 `expires_in` 时会产出看似合法的错误值；现超出可表示范围一律
  归一为 `None`（「未知」），由调用方按未知时效保守处理。正常值不受影响。
- **oauth：token 响应携带 `error` 字段时优先归一为 `ProviderError`**（RFC 6749 §5.2）。
  L1 实测（2026-10-12，零凭据探测）确认 GitHub 对「有效 client_id + 无效授权码」返回
  **HTTP 200 + 错误体**（`{"error":"bad_verification_code",...}`）——此前会降级为
  信息量更低的 `ParseError`。JSON/form 两形态均覆盖。
- 🔴 **alipay：身份键改 `open_id` 优先、`user_id` 兜底**（2026-11-17 按官方口径修正，
  见下方 Added）。此前 `alipay_identity` 只取 `user_id` 且平台文档称其为「稳定用户标识」；
  官方已宣布「新商户建议使用 `open_id` 替代，`user_id` 字段未来计划逐步回收（二选一）」
  ——在回收路径上的标识上建绑定映射会随官方迁移失效。`alipay_identity` 签名改为
  `(userinfo, fallback_open_id, fallback_user_id)`；`uid_kind` 保持 `Stable`。
- **github：邮箱选择补回退档**——`/user/emails` 无 `primary` 项时取首个 `verified=true`
  （此前无 primary 直接返回 `None`；GitHub 私密邮箱场景列表常无 primary）。
  规则：`primary && verified` 优先 → 首个 `verified` → 只有未验证邮箱时不采用。
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

- **microsoft：新增 Microsoft Entra ID provider**（依据 2026-11-13 已核验调研文档
  `docs/providers/microsoft.md`，经 worktree 实现）。v2.0 授权码 + OIDC：`MicrosoftConfig`
  显式 tenant 策略（`common`/`organizations`/`consumers`/tenant-id，默认 `common`），
  端点 / JWKS 按 tenant 展开；PKCE S256 与 `nonce` 恒发；scope 默认
  `openid profile email`（refresh 由调用方追加 `offline_access`）。🔴 **per-tenant
  issuer 派生**：换 token 后从未验签 claims 取 `tid`（仅用于选 issuer / 租户策略，
  不参与身份语义）→ `allowed_tenant_ids` 白名单（非空时不命中即
  `ProviderError("tenant_not_allowed")`）→ 按 `issuer_template`
  （默认 `https://login.microsoftonline.com/{tid}/v2.0`）派生精确 issuer 交
  `oidc` 验签（RS256 + per-tenant JWKS）——绝不做前缀/包含匹配。回调错误参数
  （`error`/`error_description`，AADSTS 细节在 description）→ `provider_error`；
  归一化：`uid = sub`（pairwise，Stable）、`email_verified` 缺省 false、
  `display_name = name ?? preferred_username`、`extra` 含 `tid`/`oid`。
  平台文档 `docs/platforms/microsoft.md`；descriptor / check.sh / doc_check /
  qa_verify / README 同步；`provider_ids()` 计数断言更新为 11。
- **CI：依赖兼容引导层 `ci/bootstrap.sh` + `ci/migrate_try.py`**（check.sh 第 0 步，幂等）。
  moon 0.1.20261104（官方 latest）移除 `try?` 语法并更改 manifest 格式要求，而
  `mizchi/experimental_crypto@0.0.2`（最新且唯一版本）与 `moonbitlang/regexp@0.3.5` 均未跟进
  ——本层对 `.mooncakes` 缓存做确定性迁移：旧格式 manifest → `moon.mod`（官方 `moon fmt` 路径）、
  `try? EXPR` → `try Ok(EXPR) catch { e => Err(e) }`（官方诊断 [3002] 给出的语义保持替换，词边界
  检测 + 注释跳过 + 跨行括号配对）。全新缓存多轮自愈，**从零复现已验证**（删除 `.mooncakes` /
  `_build` 后完整 check.sh 7/7 绿）。上游发修复版后 bump 依赖并删除对应迁移项。
- **wechat：小程序登录 `code2Session`**（2026-11-17 官方文档核实）。`wechat_code2_session(config, js_code)`
  → `WeChatCode2Session { identity, session_key }`：身份与网站链路**同一归一口径**
  （`provider = "wechat"`，`unionid` 优先 `Stable` → `openid` 兜底 `Degraded`，同一开放平台
  账号下的网站 + 小程序可用 `unionid` 关联）；`session_key` 走**专用字段**返回且不进
  `extra`（敏感密钥防误落日志），错误先查 `errcode`（`40029`/`40226`/`45011`/`-1` →
  `ProviderError`）。小程序链路无浏览器回调、无 state、无 refresh，不经 `WeChatProvider`
  trait；端点可经 `with_code2_session_endpoint` 覆盖。
- **core：`CallbackParams::provider_error()`**——回调错误参数（`error` / `error_description` /
  `error_uri`）的统一读取口（详见 Security 节）。
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
