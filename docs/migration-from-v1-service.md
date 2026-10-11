# 从 v1「认证服务」迁移到 v2「框架无关工具库」

> 本文面向**曾按 v1 设计**（统一身份认证**服务**）落过代码或做过方案的开发者，说明概念如何平移。

## 1. 一句话差异

| | v1（已作废） | **v2（当前）** |
|---|---|---|
| 形态 | 自带 HTTP 服务 + 会话 + 用户表 + 绑定管理页 | **框架无关、零状态的开源工具库** |
| 提供什么 | 一整套「登录服务」 | 六个平台的协议与密码学细节（第三方登录 / passkey / 2FA） |
| 谁建账号 | 服务 | **你**（库不建号） |
| 谁存映射 | 服务的用户表 | **你**（库不存映射） |
| 谁发会话 | 服务签发 token | **你**（库不发会话） |
| HTTP 框架 | 内置 `mizchi/mars` | **不含任何 HTTP 服务端代码**（示例里才有框架） |
| 依赖 | 9 个（含 mars / moon-token …） | **5 个**（只留协议/密码学必需件） |

**结论**：v1 里约 60% 是「服务」代码（账号、会话、页面、风控），v2 **不再提供**；v2 只保留其中约 40% 的
「协议 + 密码学」内核，并把它做成可嵌入任何后端的库。

## 2. 概念平移表

| v1 概念 | v2 对应 | 说明 |
|---|---|---|
| `POST /auth/:provider/callback` 控制器 | `@<provider>.complete_auth(config, callback, start)` | 控制器由**你的**框架写；回调解析后交给库 |
| 服务内置的用户表 | 无 | **你**把 `ExternalIdentity` 落进**你的**库 |
| 会话签发（moon-token） | 无 | **你**自己发 session / JWT / cookie |
| 身份绑定管理页 | 无 | 页面是业务；库只给 `uid` / `uid_kind` |
| `Provider` 特化（mars 的 `oauth2_google`） | `provider/google` 等**独立子包** | 六个子包**相互隔离**（LIB-20），只依赖你用到的那条 |
| 服务内的 passkey / TOTP | `passkey` / `totp` 子包 | 纯密码学原语，与「登录服务」解耦 |
| 内置 `mizchi/mars` | **删除** | 库零 Web 框架；接入示范见 `examples/moonback` / `examples/mars` |

## 3. 迁移步骤（典型）

1. **删服务、留协议**：把 v1 里「协议 + 密码学」的代码换成对应的 `provider/*` / `passkey` / `totp` 子包调用。
2. **接管状态**：
   - `ExternalIdentity` → 写进**你的**用户表（`uid ↔ 你的用户` 的映射由你维护）；
   - 会话 → 用**你的**方案（JWT / Redis session / …）；
   - `AuthStart`（`state` / `code_verifier` / `nonce`）→ 存在**你的**会话或缓存里（库不替你存）。
3. **给框架瘦身**：HTTP 层只保留「路由 + 解析回调 + 调库 + 写响应」，不掺协议逻辑（见示例）。
4. **注入外围能力**：把 HTTP / 时钟 / 随机 / 存储经 seam 注入（测试时用 mock，生产用真实实现）。
5. **跑契约**：用 `contract/` 的参数化契约对你的装配跑一遍（SDK-04）。

## 4. 一个「回调控制器」的前后对照

**v1 风格（服务内置、什么都有）**：
```text
POST /auth/google/callback
  → 服务内部：验 state → 换 token → 验 id_token → 建号/绑定 → 发会话 → 302 到首页
```

**v2 风格（你写薄控制器，库管协议）**：
```moonbit
// 你的框架路由：
ctx.get("/auth/google/callback", (req, res) => {
  let callback = @core.CallbackParams::from_query_string(req.query_string())
  let identity = try {
    @google.complete_auth(config, callback, session.get("google_start"))
  } catch {
    e => { res.send_text("auth-error " + @core.auth_error_code(e)); return }
  }
  // 以下全是「业务」，由你决定：建号 / 绑定 / 发会话
  let user_id = my_users.upsert_by_uid(identity.uid, identity.email, identity.email_verified)
  let session_token = my_sessions.issue(user_id)
  res.set_cookie("session", session_token)
  res.redirect("/")
})
```

库只出现在中间那三行（`CallbackParams` → `complete_auth` → `identity`）；其余都是**你的**业务。

## 5. 不复现 v1 的能力（明确排除）

- 用户注册 / 账号生命周期 / 绑定解绑与末位凭据守卫；
- 会话签发、多设备、refresh 轮转、踢下线、RBAC；
- 登录页 / 绑定页 / 管理页 UI；
- 服务端 HTTP 框架与路由（仅在 `examples/` 演示）。

> 若你确实需要这些能力，请在**你的应用**里实现，或组合其它库；`moonauth` 刻意不提供，以保持
> 「框架无关 + 零状态」的定位。
