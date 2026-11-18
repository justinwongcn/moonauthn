//! 健壮性回归（模糊探针）：确定性伪随机垃圾 query → CallbackParams 不 panic。

///|
/// 确定性伪随机（xorshift64），种子固定 → 可复跑。
struct FuzzRng {
  mut state : UInt64
}

///|
fn FuzzRng::next(self : FuzzRng) -> UInt64 {
  let x = self.state
  let x2 = x ^ (x << 13)
  let x3 = x2 ^ (x2 >> 7)
  let x4 = x3 ^ (x3 << 17)
  self.state = x4
  x4
}

///|
let fuzz_tokens : Array[String] = [
  "%", "&", "=", ";", "?", "#", "\n", "\r", "\t", " ", "{", "}", "[", "]",
  "(", ")", "<", ">", "\\", "\"", "'", "0", "a", "中", "%2B", "%FF", "%C3%28",
]

///|
fn FuzzRng::garbage(self : FuzzRng) -> String {
  let len = ((self.next() & 255UL).to_int())
  let parts : Array[String] = []
  for _i in 0..<len {
    let idx = ((self.next() & 1023UL).to_int() % fuzz_tokens.length())
    parts.push(fuzz_tokens[idx])
  }
  parts.join("")
}

///|
test "FUZZ: CallbackParams query parsing never panics on garbage" {
  let rng = FuzzRng::{ state: 0x2545F491UL }
  for i in 0..<10 {
    let g = rng.garbage()
    println("ITER \{i}: \{g}")
    let cb = @core.CallbackParams::from_query_string(g)
    let _ = cb.get("code")
    let _ = cb.get("state")
    let _ = cb.provider_error()
  }
}

///|
/// P1（黑客审计第 1 轮观察 → 回归）：percent_decode 的对抗形态——截断转义与非
/// 法 hex 原样保留、NUL 字节不丢弃、分号不是分隔符、值内 `=` 保留、裸键为空值。
test "P1: percent_decode adversarial shapes" {
  @debug.assert_eq(@core.CallbackParams::from_query_string("a=%4").get("a"), Some("%4"))
  @debug.assert_eq(@core.CallbackParams::from_query_string("a=%GG").get("a"), Some("%GG"))
  let nul = @core.CallbackParams::from_query_string("a=x%00y").get("a")
  match nul {
    Some(s) => @debug.assert_eq(s.length(), 3)
    None => abort("P1: %00 was dropped")
  }
  @debug.assert_eq(
    @core.CallbackParams::from_query_string("a=b;c=d").get("a"),
    Some("b;c=d"),
  )
  @debug.assert_eq(@core.CallbackParams::from_query_string("a=b=c").get("a"), Some("b=c"))
  @debug.assert_eq(@core.CallbackParams::from_query_string("flag").get("flag"), Some(""))
}
