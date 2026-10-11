//! moonauth / passkey —— 高层门面：`PasskeyService`。
//!
//! 门面把「配置 + 注入的 seam（`WebAuthnVerifier` / `ChallengeStore` / `RandomSource` /
//! `Clock`）」组装成调用方直接可用的 passkey 仪式。
//!
//! ## 两种收尾模式
//! - **托管式（`*_stored`）**：门面经 `ChallengeStore` 管理挑战的**一次性 + TTL**
//!   （`begin_*` 写入、`finish_*_stored` 取用）。适合多实例部署（共享 Redis 等）。
//! - **无状态式（`finish_*`）**：调用方自管挑战，门面只做「策略 + 密码学校验」。
//!
//! ## 🔴 存储故障 ≠ 挑战不存在（核心契约）
//! `ChallengeStore.take` 以 `raise AuthError` 表达**基础设施故障**，以 `None` 表达
//! **「不存在 / 已用 / 过期」**（成功语义）。门面**原样透传**存储抛出的错误：若把
//! `take` 的异常吞成 `None`，就会把「Redis 连接失败」误判为「挑战不存在」，在 passkey
//! 场景中等同于把基础设施故障误报成**重放 / 凭据失效**——属安全语义事故。
//! 因此本门面**不**对 `ChallengeStore` 的调用做任何 `catch`。该不变量由
//! `passkey_test.mbt` 的「必然失败的存储 → `AuthError`（`network`）而非
//! `ChallengeNotFound`」用例锁定。
//!
//! ## 全 async
//! `ChallengeStore` 是 async seam（下游可替换为 Redis / 数据库），故门面**所有**方法
//! 声明为 `async fn`（即使无状态式不触碰存储，也保持接口一致，调用方无需区分）。
//! 需要纯同步校验的调用方可直接用同步 seam `StandardWebAuthnVerifier`
//! （`passkey/verifier.mbt`）。

///|
/// passkey 门面。持有注入的 seam 与部署配置，本身无状态。
pub struct PasskeyService {
  config : PasskeyConfig
  verifier : &@core.WebAuthnVerifier
  store : &@core.ChallengeStore
  random : &@core.RandomSource
  clock : &@core.Clock
}

///|
/// 以配置构造。默认装配：
/// - `WebAuthnVerifier` = `StandardWebAuthnVerifier`（UV 策略取自 `config`）；
/// - `ChallengeStore`   = `@store_memory.MemoryChallengeStore`（注入同一个 `SystemClock`）；
/// - `RandomSource`     = `@rand.GetrandomSource`；
/// - `Clock`            = `@core.SystemClock`。
///
/// 以上均可用 `with_*` 覆盖（测试注入固定随机源 / 固定时钟 / 失败存储）。
pub fn PasskeyService::new(config : PasskeyConfig) -> PasskeyService {
  let verifier : &@core.WebAuthnVerifier = StandardWebAuthnVerifier::new().with_user_verification(
    config.require_user_verification,
  )
  let clock : &@core.Clock = @core.SystemClock::new()
  let store : &@core.ChallengeStore = @store_memory.MemoryChallengeStore::new(clock)
  let random : &@core.RandomSource = @rand.GetrandomSource::new()
  { config, verifier, store, random, clock }
}

///|
/// 只读访问当前配置。
pub fn PasskeyService::config(self : PasskeyService) -> PasskeyConfig {
  self.config
}

///|
/// 覆盖验证器实现，返回**新**门面。
pub fn PasskeyService::with_verifier(
  self : PasskeyService,
  verifier : &@core.WebAuthnVerifier,
) -> PasskeyService {
  {
    config: self.config,
    verifier,
    store: self.store,
    random: self.random,
    clock: self.clock,
  }
}

///|
/// 覆盖挑战存储，返回**新**门面。
///
/// 注：`with_clock` 不会重建 `store` 内部引用的时钟——若需存储也使用新时钟，
/// 请显式 `with_store(<store built with that clock>)`。
pub fn PasskeyService::with_store(
  self : PasskeyService,
  store : &@core.ChallengeStore,
) -> PasskeyService {
  {
    config: self.config,
    verifier: self.verifier,
    store,
    random: self.random,
    clock: self.clock,
  }
}

///|
/// 覆盖随机源，返回**新**门面。
pub fn PasskeyService::with_random(
  self : PasskeyService,
  random : &@core.RandomSource,
) -> PasskeyService {
  {
    config: self.config,
    verifier: self.verifier,
    store: self.store,
    random,
    clock: self.clock,
  }
}

///|
/// 覆盖时钟，返回**新**门面（仅影响门面的时间读取，见 `with_store` 注）。
pub fn PasskeyService::with_clock(
  self : PasskeyService,
  clock : &@core.Clock,
) -> PasskeyService {
  {
    config: self.config,
    verifier: self.verifier,
    store: self.store,
    random: self.random,
    clock,
  }
}

// ════════ 开始（begin） ════════

///|
/// 开始注册：生成挑战并经 `ChallengeStore` 存储（TTL = 配置值）。
pub async fn PasskeyService::begin_registration(
  self : PasskeyService,
) -> PasskeyChallenge raise @core.AuthError {
  self.begin_ceremony("reg")
}

///|
/// 开始认证：生成挑战并经 `ChallengeStore` 存储（TTL = 配置值）。
pub async fn PasskeyService::begin_authentication(
  self : PasskeyService,
) -> PasskeyChallenge raise @core.AuthError {
  self.begin_ceremony("auth")
}

///|
/// 开始一次仪式的公共实现（私有）：生成挑战 + 一次性键，写入存储。
async fn PasskeyService::begin_ceremony(
  self : PasskeyService,
  purpose : String,
) -> PasskeyChallenge raise @core.AuthError {
  let challenge = self.new_challenge()
  let key = self.new_challenge_key(purpose)
  let ttl = self.config.challenge_ttl_seconds
  let expires_at = self.clock.now_unix() + ttl.to_int64()
  self.store.put(key, challenge, ttl)
  { challenge, key, expires_at }
}

// ════════ 浏览器 options 构建（LIB-05 ①，**加法**） ════════

///|
/// 由一次**注册挑战** + 用户信息构建浏览器创建选项
/// （`PublicKeyCredentialCreationOptions`）。
///
/// 纯组装（无 I/O，故为 **sync**）：`challenge` 原样取自传入的 `PasskeyChallenge`；`rp`
/// 取自 `config`（`rp_id` / `rp_name`）；`pubKeyCredParams` 固定为 `[ES256]`。
///
/// ## 典型链路（库提供什么 / 调用方还要做什么）
/// 1. `let ch = svc.begin_registration()` —— **库**：CSPRNG 挑战 + 存入 `ChallengeStore`；
/// 2. `let opts = svc.registration_options(ch, user)` —— **库**：产出本 options；
/// 3. **调用方**：把 `opts` 序列化为浏览器 JSON（字段名见各类型 doc 的 camelCase 映射），
///    前端再把 `challenge`（base64url）转成 `ArrayBuffer` 后调 `navigator.credentials.create()`；
/// 4. **调用方**：把浏览器返回的 `clientDataJSON` / `attestationObject` 装进
///    `@core.RegistrationInput`（`expected_challenge = ch.challenge`）；
/// 5. `svc.finish_registration(_stored)(...)` —— **库**：密码学校验。
pub fn PasskeyService::registration_options(
  self : PasskeyService,
  challenge : PasskeyChallenge,
  user : UserInfo,
  timeout? : Int = 60000,
  attestation? : String = "none",
  authenticator_selection? : AuthenticatorSelection? = None,
  exclude_credentials? : Array[CredentialDescriptor] = [],
) -> RegistrationOptions {
  {
    challenge: challenge.challenge,
    rp: { id: self.config.rp_id, name: self.config.rp_name },
    user,
    pub_key_cred_params: [PublicKeyCredParam::es256()],
    timeout: Some(timeout),
    attestation: Some(attestation),
    authenticator_selection,
    exclude_credentials: if exclude_credentials.length() > 0 {
      Some(exclude_credentials)
    } else {
      None
    },
  }
}

///|
/// 由一次**认证挑战**（+ 可选允许凭据）构建浏览器请求选项
/// （`PublicKeyCredentialRequestOptions`）。
///
/// `user_verification` 缺省时按 `config.require_user_verification` 推导为
/// `"required"` / `"preferred"`。
pub fn PasskeyService::authentication_options(
  self : PasskeyService,
  challenge : PasskeyChallenge,
  allow_credentials? : Array[CredentialDescriptor] = [],
  user_verification? : String? = None,
  timeout? : Int = 60000,
) -> AuthenticationOptions {
  let uv = match user_verification {
    Some(v) => Some(v)
    None =>
      if self.config.require_user_verification {
        Some("required")
      } else {
        Some("preferred")
      }
  }
  {
    challenge: challenge.challenge,
    rp_id: self.config.rp_id,
    allow_credentials: if allow_credentials.length() > 0 {
      Some(allow_credentials)
    } else {
      None
    },
    user_verification: uv,
    timeout: Some(timeout),
  }
}

// ════════ 收尾：注册 ════════

///|
/// 收尾注册（**无状态式**）：调用方自带挑战，门面只做策略 + 密码学校验。
///
/// 注：本方法不触碰 async 存储，其 `async` 是**接口一致性**的选择（门面整体 async，
/// 调用方无需区分托管 / 无状态；需要纯同步者请直接用 `StandardWebAuthnVerifier`）。
#warnings("-unused_async")
pub async fn PasskeyService::finish_registration(
  self : PasskeyService,
  input : @core.RegistrationInput,
) -> @core.VerifiedRegistration raise @core.AuthError {
  @core.WebAuthnVerifier::verify_registration(self.verifier, input)
}

///|
/// 收尾注册（**托管式**）：从 `ChallengeStore` 取出挑战（一次性），
/// 校验 `input.expected_challenge` 与之一致后交给验证器。
///
/// 🔴 存储故障经 `AuthError` 向上抛出（**不**吞成 `None`）；`take` 返回 `None` 才是
/// 真正的「不存在 / 已用 / 过期」→ `ChallengeNotFound`。
pub async fn PasskeyService::finish_registration_stored(
  self : PasskeyService,
  key : String,
  input : @core.RegistrationInput,
) -> @core.VerifiedRegistration raise @core.AuthError {
  let stored_challenge = match self.store.take(key) {
    Some(value) => value
    None => raise @core.ChallengeNotFound
  }
  if input.expected_challenge != stored_challenge {
    raise @core.ChallengeMismatch
  }
  self.finish_registration(input)
}

// ════════ 收尾：认证 ════════

///|
/// 收尾认证（**无状态式**）。
///
/// 注：同 `finish_registration`——`async` 为接口一致性（见该处说明）。
#warnings("-unused_async")
pub async fn PasskeyService::finish_authentication(
  self : PasskeyService,
  input : @core.AssertionInput,
) -> @core.VerifiedAssertion raise @core.AuthError {
  @core.WebAuthnVerifier::verify_assertion(self.verifier, input)
}

///|
/// 收尾认证（**托管式**）：从 `ChallengeStore` 取出挑战（一次性），
/// 校验 `input.expected_challenge` 与之一致后交给验证器。
///
/// 🔴 同 `finish_registration_stored`：存储故障 → `AuthError`，不吞成 `None`。
pub async fn PasskeyService::finish_authentication_stored(
  self : PasskeyService,
  key : String,
  input : @core.AssertionInput,
) -> @core.VerifiedAssertion raise @core.AuthError {
  let stored_challenge = match self.store.take(key) {
    Some(value) => value
    None => raise @core.ChallengeNotFound
  }
  if input.expected_challenge != stored_challenge {
    raise @core.ChallengeMismatch
  }
  self.finish_authentication(input)
}

// ════════ 挑战 / 键生成 ════════

///|
/// 生成 32 字节 CSPRNG 挑战并编码为 base64url（无填充，43 字符）。
///
/// 32 字节（256 bit）远超 WebAuthn 建议的 ≥16 字节；base64url 是浏览器侧
/// `PublicKeyCredential*.challenge` 的既定编码，也是 `clientDataJSON.challenge` 的原样值。
fn PasskeyService::new_challenge(self : PasskeyService) -> String raise @core.AuthError {
  let raw = @core.RandomSource::bytes(self.random, 32)
  if raw.length() != 32 {
    raise @core.InvalidInput("moonauth: random source returned a short challenge")
  }
  base64url(raw)
}

///|
/// 生成一次性存储键（`pk:<purpose>:<hex(24B)>`）。`purpose` 区分注册 / 认证。
fn PasskeyService::new_challenge_key(
  self : PasskeyService,
  purpose : String,
) -> String raise @core.AuthError {
  let raw = @core.RandomSource::bytes(self.random, 24)
  if raw.length() != 24 {
    raise @core.InvalidInput("moonauth: random source returned a short key")
  }
  "pk:" + purpose + ":" + hex_encode(raw)
}

// ════════ 私有编码工具 ════════

///|
/// RFC 4648 §5 base64url 编码（无填充）。
///
/// 说明：这是包内私有工具（`oauth` 包有同名实现）。**有意不依赖 `oauth`**——passkey
/// 不应为一段 40 行编码而依赖整个 OAuth 功能包；也不改已冻结的 `core`。
fn base64url(data : Bytes) -> String {
  let alphabet = @utf8.encode(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
  )
  let out : Array[Byte] = []
  let n = data.length()
  let mut i = 0
  while i < n {
    let has1 = i + 1 < n
    let has2 = i + 2 < n
    let b0 = data[i].to_int()
    let b1 = if has1 { data[i + 1].to_int() } else { 0 }
    let b2 = if has2 { data[i + 2].to_int() } else { 0 }
    out.push(alphabet[b0 >> 2])
    out.push(alphabet[((b0 & 0x03) << 4) | (b1 >> 4)])
    if has1 {
      out.push(alphabet[((b1 & 0x0F) << 2) | (b2 >> 6)])
    }
    if has2 {
      out.push(alphabet[b2 & 0x3F])
    }
    i = i + 3
  }
  @utf8.decode_lossy(Bytes::from_array(out))
}
