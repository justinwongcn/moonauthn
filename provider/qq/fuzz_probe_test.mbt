//! 健壮性回归（模糊探针）：qq token / JSONP 解析不得 panic。

///|
struct QqFuzzRng {
  mut state : UInt64
}

///|
fn QqFuzzRng::next(self : QqFuzzRng) -> UInt64 {
  let x = self.state
  let x2 = x ^ (x << 13)
  let x3 = x2 ^ (x2 >> 7)
  let x4 = x3 ^ (x3 << 17)
  self.state = x4
  x4
}

///|
let qq_fuzz_tokens : Array[String] = [
  "%", "&", "=", ";", "?", "#", "\n", "\r", "\t", " ", "{", "}", "(", ")",
  "\\", "\"", "'", "c", "a", "l", "b", "a", "c", "k", "0", "9", "中", "openid",
  "access_token", "error", "%2B", "%FF",
]

///|
fn QqFuzzRng::garbage(self : QqFuzzRng) -> String {
  let len = ((self.next() & 255UL).to_int())
  let parts : Array[String] = []
  for _i in 0..<len {
    let idx = ((self.next() & 1023UL).to_int() % qq_fuzz_tokens.length())
    parts.push(qq_fuzz_tokens[idx])
  }
  parts.join("")
}

///|
test "FUZZ: qq token/jsonp parsing never panics on garbage" {
  let rng = QqFuzzRng::{ state: 0xDEADBEEFUL }
  for _i in 0..<1000 {
    let g = rng.garbage()
    let c = try {
      let _ = @qq.qq_parse_token(g)
      "ok"
    } catch {
      e => @core.auth_error_code(e)
    }
    assert_true(c != "panic")
    let c2 = try {
      let _ = @qq.qq_parse_openid(g, "appid")
      "ok"
    } catch {
      e => @core.auth_error_code(e)
    }
    assert_true(c2 != "panic")
  }
}
