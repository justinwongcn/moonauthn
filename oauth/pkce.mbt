//! moonauth / oauth —— PKCE（RFC 7636）与 base64 助手。
//!
//! 本文件只使用 MoonBit 标准类型与 `@otp`（SHA-256）——**没有**任何第三方类型出现在
//! 公开签名上。
//!
//! 🔴 **为什么自写 base64**：生态里的 `moonbitstack/moonbase/base64` 虽然存在，但
//! `moonbase` 只是 `mooncrypt` / `mooncred` 的**传递依赖**，未被 `moonauth` 的
//! `moon.mod` 直接声明——实测 `moon build` 会报
//! `its containing module is not imported ... thus cannot be imported by its package`
//! （见 T02 阶段 `_probe` 验证）。因此按 ARCH §2.2 / T02.1 的预案**自写 base64url**
//! （约 40 行），既避免新增直接依赖，也保持依赖清单不变。
//!
//! 同时提供**标准 base64**（`+/`、带 `=` 填充）的编解码，供 `signer.mbt` 解析 PEM
//! 密钥体使用（PEM 用标准 base64，不是 url 变体）。

///|
/// RFC 4648 §5 base64url 字母表（url-safe，无填充）。
let base64url_alphabet : String = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

///|
/// RFC 4648 §4 标准 base64 字母表（`+` / `/`，带填充）。
let base64_std_alphabet : String = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

///|
/// base64url 编码（无填充）。输出恒为 ASCII，故用 `decode_lossy` 还原为 `String`。
pub fn base64url_encode(data : Bytes) -> String {
  encode_with(@utf8.encode(base64url_alphabet), data)
}

///|
/// 标准 base64 编码（RFC 4648 §4，**带 `=` 填充**，输出长度恒为 4 的倍数）。
///
/// 与 `base64url_encode`（**无填充**）相对：标准 base64 是带填充的，只有 JOSE 的
/// base64url 才约定去填充。真实消费者是 PEM 路径——严格 PEM 解析器要求 body 段是
/// **标准带填充** base64（见 `signer.mbt` 的 `pem_body_to_der`；`provider/alipay`
/// 的 `sign` 字段亦要求标准 base64）。故此处**必须**补 `=`。
pub fn base64_std_encode(data : Bytes) -> String {
  let encoded = encode_with(@utf8.encode(base64_std_alphabet), data)
  // 按输入长度补 `=` 至 4 的倍数：n%3==1 → 补 2 个；n%3==2 → 补 1 个；n%3==0 → 不补。
  match data.length() % 3 {
    0 => encoded
    1 => encoded + "=="
    _ => encoded + "="
  }
}

///|
/// 按给定字母表编码（无填充；调用方按需补 `=`）。
fn encode_with(alphabet : Bytes, data : Bytes) -> String {
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

///|
/// base64url 解码（容忍缺失 / 多余的 `=` 填充）。
pub fn base64url_decode(text : String) -> Bytes raise @core.AuthError {
  decode_with(text, true)
}

///|
/// 标准 base64 解码（容忍缺失的 `=` 填充）。
pub fn base64_std_decode(text : String) -> Bytes raise @core.AuthError {
  decode_with(text, false)
}

///|
/// 通用 base64 解码。`url` 决定字母表变体。
///
/// 实现要点：以 6-bit 累加器滚动拼字节。空白字符（空格 / 制表 / `\r` / `\n`）被忽略
/// （便于直接解码 PEM 体，其换行、缩进属格式而非数据）；遇 `=` 即停止读取
/// （填充不携带信息）；出现字母表外字符时抛 `ParseError`，绝不做静默丢弃。
fn decode_with(text : String, url : Bool) -> Bytes raise @core.AuthError {
  let src = @utf8.encode(text)
  let out : Array[Byte] = []
  let mut acc = 0
  let mut bits = 0
  let mut i = 0
  let n = src.length()
  while i < n {
    let c = src[i].to_int()
    if c == 0x3D {
      // '=' —— 填充，忽略其后内容
      i = n
    } else if c == 0x20 || c == 0x09 || c == 0x0A || c == 0x0D {
      // 空白 —— 跳过
      i = i + 1
    } else {
      let v = if url {
        base64url_value(c)
      } else {
        base64_std_value(c)
      }
      if v < 0 {
        raise @core.ParseError("moonauth: invalid base64 character")
      }
      acc = (acc << 6) | v
      bits = bits + 6
      if bits >= 8 {
        bits = bits - 8
        out.push(((acc >> bits) & 0xFF).to_byte())
      }
      i = i + 1
    }
  }
  Bytes::from_array(out)
}

///|
/// base64url 字符 → 6-bit 值；非法返回 -1。
fn base64url_value(c : Int) -> Int {
  if c >= 65 && c <= 90 {
    c - 65
  } else if c >= 97 && c <= 122 {
    c - 97 + 26
  } else if c >= 48 && c <= 57 {
    c - 48 + 52
  } else if c == 45 {
    62
  } else if c == 95 {
    63
  } else {
    -1
  }
}

///|
/// 标准 base64 字符 → 6-bit 值；非法返回 -1。
fn base64_std_value(c : Int) -> Int {
  if c >= 65 && c <= 90 {
    c - 65
  } else if c >= 97 && c <= 122 {
    c - 97 + 26
  } else if c >= 48 && c <= 57 {
    c - 48 + 52
  } else if c == 43 {
    62
  } else if c == 47 {
    63
  } else {
    -1
  }
}

///|
/// PKCE `S256` 挑战：`base64url(sha256(code_verifier))`（RFC 7636 §4.2）。
///
/// SHA-256 取自 `1726914517-spec/moon_otp`（其 `sha256` 是纯函数，无第三方类型逃逸）。
pub fn s256_challenge(code_verifier : String) -> String {
  base64url_encode(@otp.sha256(@utf8.encode(code_verifier)[:]))
}

///|
/// 恒定时间无必要的常量比较：校验 `code_verifier` 与期望的 `S256` 挑战是否匹配。
///
/// 这里用普通相等即可——`code_verifier` 是调用方自己生成的秘密，比对不涉及
/// 「按字节泄露秘密」的时序攻击面（与 MAC 比较不同）。
pub fn verify_s256(code_verifier : String, expected_challenge : String) -> Bool {
  s256_challenge(code_verifier) == expected_challenge
}

///|
/// 生成 `code_verifier`（RFC 7636 §4.1）：`byte_len` 字节 CSPRNG 经 base64url 编码。
///
/// 🔴 随机源**只**经注入的 `RandomSource` seam 获取（LIB-01 / 共享知识 §10.4），
/// 绝不直接引用 `getrandom`。默认 32 字节 → 43 字符，落在 RFC 允许的 43~128 区间内。
pub fn generate_code_verifier(
  random : &@core.RandomSource,
  byte_len? : Int = 32,
) -> String raise @core.AuthError {
  base64url_encode(@core.RandomSource::bytes(random, byte_len))
}
