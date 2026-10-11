//! moonauth / oauth —— 默认 `SecretSigner` 实现：`MooncryptSecretSigner`。
//!
//! 承担两处签名需求：
//! - **Apple client secret**：ES256（P-256 + SHA-256），`mooncrypt/sign/ecdsa`；
//! - **支付宝网关**：RS256（RSA PKCS#1 v1.5 + SHA-256），`mooncrypt/rsa`。
//!
//! ## 密钥形态
//! `SigningKey` 只有两种载体（`core/values.mbt` 冻结）：`Pem(String)` / `Der(Bytes)`。
//! 本模块把二者统一解析为「可直接用于 mooncrypt 的裸密钥材料」：
//!
//! | 算法 | 接受的编码 |
//! |---|---|
//! | ES256 | 裸 32 字节标量；SEC1 `ECPrivateKey` DER；PKCS#8 `PrivateKeyInfo` DER；以上两者的 PEM |
//! | RS256 | PKCS#1 `RSAPrivateKey` DER；PKCS#8 `PrivateKeyInfo` DER；以上两者的 PEM |
//!
//! 🔴 **为什么不依赖第三方 ASN.1 / PEM 解析器**：`moonbitstack/moonbase/*` 是传递依赖、
//! 不可直接 import（见 `pkce.mbt` 顶部说明）；`mooncrypt/asn1` 虽在直接依赖 `mooncrypt` 内，
//! 但只做「最小 DER 走查」所需的代码量很小（~70 行），自写可避免把 `asn1` 拉进依赖面，
//! 也让错误归一完全由本模块掌控（第三方类型不逃逸）。
//!
//! 边界处一律 `catch` 并转 `AuthError`：密钥解析失败 → `KeyError`。

///|
/// 默认 `SecretSigner` 实现（ES256 / RS256）。
pub struct MooncryptSecretSigner {}

///|
/// 构造默认签名器（无状态）。
pub fn MooncryptSecretSigner::new() -> MooncryptSecretSigner {
  MooncryptSecretSigner::{}
}

///|
/// 实现 seam：按 `alg` 选择曲线 / RSA，签名 `message`，返回原始签名字节。
///
/// - ES256 返回 **`r ∥ s`（64 字节）**——正是 JOSE ES256 的线格式，无需 DER 转换；
/// - RS256 返回 PKCS#1 v1.5 的定长签名。
pub impl @core.SecretSigner for MooncryptSecretSigner with fn sign(self, alg, key, msg) {
  let _ = self
  let der = signing_key_to_der(key)
  match alg {
    ES256 => {
      let scalar = ec_private_scalar(der)
      let sk = @ecdsa.PrivateKey::new(scalar[:], curve=@ecdsa.Curve::P256) catch {
        _ => raise @core.KeyError("moonauth: invalid P-256 private key")
      }
      sk.sign(msg[:])
    }
    RS256 => {
      let (n, e, d) = rsa_private_parts(der)
      let sk = @rsa.PrivateKey::new(
        n[:],
        e[:],
        d[:],
        digest=@rsa.Digest::Sha256,
        scheme=@rsa.Scheme::Pkcs1,
      ) catch {
        _ => raise @core.KeyError("moonauth: invalid RSA private key")
      }
      sk.sign(msg[:])
    }
  }
}

///|
/// 显式把 seam 方法提升为常规方法，避免隐式提升的弃用告警。
pub extend MooncryptSecretSigner with @core.SecretSigner::{sign}

// ════════ 密钥载体 → DER ════════

///|
/// 把 `SigningKey` 归一为 DER 字节（PEM 先去铠甲并 base64 解码）。
fn signing_key_to_der(key : @core.SigningKey) -> Bytes raise @core.AuthError {
  match key {
    Der(bytes) => bytes
    Pem(text) => pem_body_to_der(text)
  }
}

///|
/// 从 PEM 文本提取 DER：跳过 `-----BEGIN/END ...-----` 行，其余行拼接后按标准 base64
/// 解码（解码器忽略空白，故 CRLF 亦可）。
///
/// 🔴 **密钥加载失败一律归一为 `KeyError`**（而非底层的 `ParseError`）：对调用方而言，
/// 「PEM 体不是合法 base64」与「DER 结构不合法」同属「这把密钥用不了」，
/// 归一后调用方可单点捕获，无需区分编码层细节。
fn pem_body_to_der(text : String) -> Bytes raise @core.AuthError {
  let mut joined = ""
  for line in text.split("\n") {
    let l = line.to_owned()
    if !l.has_prefix("-----") {
      joined = joined + l
    }
  }
  base64_std_decode(joined) catch {
    _ => raise @core.KeyError("moonauth: PEM body is not valid base64")
  }
}

// ════════ 最小 DER 走查 ════════

///|
/// 一个 BER/DER TLV 的头：`tag` 与其内容的 `[start, start+len)` 区间。
priv struct Tlv {
  tag : Int
  start : Int
  len : Int
}

///|
/// 读取 `buf[pos]` 处的 TLV，返回该 TLV 与「下一个兄弟」的起始位置。
///
/// 只支持短 / 长两种长度形式（长度字节数 ≤ 4），对畸形输入一律 `KeyError`，
/// 不做任何越界读取。
fn der_next(buf : Bytes, pos : Int) -> (Tlv, Int) raise @core.AuthError {
  let n = buf.length()
  if pos + 2 > n {
    raise @core.KeyError("moonauth: truncated DER")
  }
  let tag = buf[pos].to_int()
  let mut p = pos + 1
  let first = buf[p].to_int()
  p = p + 1
  let len = if (first & 0x80) == 0 {
    first
  } else {
    let cnt = first & 0x7F
    if cnt == 0 || cnt > 4 {
      raise @core.KeyError("moonauth: unsupported DER length form")
    }
    let mut v = 0
    let mut k = 0
    while k < cnt {
      if p >= n {
        raise @core.KeyError("moonauth: truncated DER length")
      }
      v = (v << 8) | buf[p].to_int()
      p = p + 1
      k = k + 1
    }
    v
  }
  if p + len > n {
    raise @core.KeyError("moonauth: DER length overruns buffer")
  }
  ({ tag, start: p, len }, p + len)
}

///|
/// 列出某个 SEQUENCE 的**直接**子 TLV（按出现顺序）。
fn der_children(buf : Bytes, parent : Tlv) -> Array[Tlv] raise @core.AuthError {
  let out : Array[Tlv] = []
  let end = parent.start + parent.len
  let mut pos = parent.start
  while pos < end {
    let (child, next) = der_next(buf, pos)
    out.push(child)
    pos = next
  }
  out
}

///|
/// OCTET STRING 的内容（不做任何归一）。
fn octet_content(buf : Bytes, tlv : Tlv) -> Bytes {
  buf[tlv.start : tlv.start + tlv.len].to_owned()
}

///|
/// INTEGER 的内容，剥掉前导 `0x00`（DER 用它表示正整数最高位为 1 的情形）。
fn int_content(buf : Bytes, tlv : Tlv) -> Bytes {
  let raw = octet_content(buf, tlv)
  let mut s = 0
  while s + 1 < raw.length() && raw[s] == b'\x00' {
    s = s + 1
  }
  raw[s:].to_owned()
}

// ════════ EC / RSA 私有材料提取 ════════

///|
/// ECDSA P-256 私钥标量（32 字节，定长）。
///
/// 接受：裸 32 字节；SEC1 `ECPrivateKey`；PKCS#8 `PrivateKeyInfo`（内含 SEC1）。
/// 宽度不足左侧补零、超出取低 32 字节，使后续 `PrivateKey::new` 只面对定长标量。
fn ec_private_scalar(der : Bytes) -> Bytes raise @core.AuthError {
  if der.length() == 32 {
    return der
  }
  let (outer, _) = der_next(der, 0)
  if outer.tag != 0x30 {
    raise @core.KeyError("moonauth: EC key is not a DER SEQUENCE")
  }
  let items = der_children(der, outer)
  // PKCS#8：version INTEGER, AlgorithmIdentifier SEQUENCE, privateKey OCTET STRING
  if items.length() >= 3 && items[1].tag == 0x30 && items[2].tag == 0x04 {
    return ec_private_scalar(octet_content(der, items[2]))
  }
  // SEC1：version INTEGER, privateKey OCTET STRING
  if items.length() >= 2 && items[1].tag == 0x04 {
    return normalize_scalar(octet_content(der, items[1]))
  }
  raise @core.KeyError("moonauth: unrecognized EC private key encoding")
}

///|
/// RSA 私钥的三元组 `(n, e, d)`。
///
/// 接受：PKCS#1 `RSAPrivateKey`；PKCS#8 `PrivateKeyInfo`（内含 PKCS#1）。
/// 只取前三个 INTEGER——mooncrypt 的 `PrivateKey::new` 恰好只需要这三个数，
/// 且 PKCS#1 的后续 CRT 参数（p/q/dp/dq/qinv）为本库所不需。
fn rsa_private_parts(der : Bytes) -> (Bytes, Bytes, Bytes) raise @core.AuthError {
  let (outer, _) = der_next(der, 0)
  if outer.tag != 0x30 {
    raise @core.KeyError("moonauth: RSA key is not a DER SEQUENCE")
  }
  let items = der_children(der, outer)
  // PKCS#8：version, AlgorithmIdentifier SEQUENCE, privateKey OCTET STRING
  if items.length() >= 3 && items[1].tag == 0x30 && items[2].tag == 0x04 {
    return rsa_private_parts(octet_content(der, items[2]))
  }
  // PKCS#1：version, n, e, d, ...
  if items.length() >= 4 && items[1].tag == 0x02 && items[2].tag == 0x02 {
    return (
      int_content(der, items[1]),
      int_content(der, items[2]),
      int_content(der, items[3]),
    )
  }
  raise @core.KeyError("moonauth: unrecognized RSA private key encoding")
}

///|
/// 把可能带前导零 / 宽度异常的标量归一为定长 32 字节。
fn normalize_scalar(raw : Bytes) -> Bytes {
  let mut s = 0
  while s + 1 < raw.length() && raw[s] == b'\x00' {
    s = s + 1
  }
  let stripped = raw[s:]
  let width = stripped.length()
  if width == 32 {
    return stripped.to_owned()
  }
  let out : Array[Byte] = []
  if width > 32 {
    for i in 0..<32 {
      out.push(stripped[width - 32 + i])
    }
  } else {
    for _ in 0..<(32 - width) {
      out.push(b'\x00')
    }
    for b in stripped {
      out.push(b)
    }
  }
  Bytes::from_array(out)
}
