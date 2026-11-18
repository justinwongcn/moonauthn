//! 健壮性回归（模糊探针，2026-11-19 安全审计加入）：垃圾 id_token 走完整
//! complete_auth（换 token → 未验签 tid → 验签）——不得 panic，全部归一错误码。

///|
struct MsftFuzzRng {
  mut state : UInt64
}

///|
fn MsftFuzzRng::next(self : MsftFuzzRng) -> UInt64 {
  let x = self.state
  let x2 = x ^ (x << 13)
  let x3 = x2 ^ (x2 >> 7)
  let x4 = x3 ^ (x3 << 17)
  self.state = x4
  x4
}

///|
fn MsftFuzzRng::garbage_token(self : MsftFuzzRng) -> String {
  let alphabet = [
    ".", "-", "_", "e", "y", "J", "0", "9", "{", "}", "\"", ":", "iss", "tid",
    "alg", "RS256", "HS256", "none", ".", "%2E", "中",
  ]
  let len = (self.next() % 300UL).to_int()
  let parts : Array[String] = []
  for _i in 0..<len {
    let idx = (self.next() & 1023UL).to_int() % alphabet.length()
    parts.push(alphabet[idx])
  }
  parts.join("")
}

///|
async test "microsoft fuzz: garbage id_tokens through complete_auth never panic" {
  let rng = MsftFuzzRng::{ state: 0xFEEDFACEUL }
  for _i in 0..<300 {
    let client : &@core.HttpClient = @contract.MockHttpClient::new([
      { status: 200,
        headers: Map([("Content-Type", "application/json")]),
        body: "{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"id_token\":\"" + rng.garbage_token() + "\"}",
      },
      { status: 200,
        headers: Map([("Content-Type", "application/json")]),
        body: "{\"keys\":[]}",
      },
    ])
    let config = @microsoft.MicrosoftConfig::new("client-1", "https://app.example/cb")
    .with_client_secret("s")
    .with_endpoints("mock://authorize", "mock://token", "mock://jwks")
    .with_http(client)
    let secrets : @core.SuppliedSecrets = {
      state: Some("st"),
      code_verifier: None,
      nonce: Some("n"),
    }
    let start = @microsoft.begin_auth(config, secrets)
    let callback = @core.CallbackParams::from_query_string("code=c&state=st")
    let out = try {
      let _ = @microsoft.complete_auth(config, callback, start)
      "ok"
    } catch {
      e => @core.auth_error_code(e)
    }
    assert_true(out != "panic")
  }
}
