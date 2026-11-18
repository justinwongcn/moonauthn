//! 健壮性回归（模糊探针）：wechat token 解析不得 panic。

///|
struct WechatFuzzRng {
  mut state : UInt64
}

///|
fn WechatFuzzRng::next(self : WechatFuzzRng) -> UInt64 {
  let x = self.state
  let x2 = x ^ (x << 13)
  let x3 = x2 ^ (x2 >> 7)
  let x4 = x3 ^ (x3 << 17)
  self.state = x4
  x4
}

///|
let wechat_fuzz_tokens : Array[String] = [
  "%", "&", "=", ";", "?", "#", "\n", "\r", "\t", " ", "{", "}", "[", "]",
  "\\", "\"", "'", "e", "r", "c", "o", "d", "e", "0", "0", "9", "x", "中",
  "\"errcode\"", "\"errmsg\"", "0.9",
]

///|
fn WechatFuzzRng::garbage(self : WechatFuzzRng) -> String {
  let len = ((self.next() & 255UL).to_int())
  let parts : Array[String] = []
  for _i in 0..<len {
    let idx = ((self.next() & 1023UL).to_int() % wechat_fuzz_tokens.length())
    parts.push(wechat_fuzz_tokens[idx])
  }
  parts.join("")
}

///|
test "FUZZ: wechat token parsing never panics on garbage" {
  let rng = WechatFuzzRng::{ state: 0xBADC0DEUL }
  for _i in 0..<1000 {
    let g = rng.garbage()
    let c = try {
      let _ = @wechat.wechat_parse_token(g)
      "ok"
    } catch {
      e => @core.auth_error_code(e)
    }
    assert_true(c != "panic")
  }
}
