name = "justinwongcn/moonauthn"
version = "0.1.1"
readme = "README.md"
repository = "https://github.com/justinwongcn/moonauthn"
license = "Apache-2.0"
description = "Framework-agnostic, zero-state authentication toolkit for MoonBit: third-party login (11 providers), Passkey/WebAuthn, and TOTP with all non-determinism injected through seams."
keywords = [ "auth", "authentication", "oauth", "oidc", "passkey", "webauthn", "totp", "fido2", "sso" ]

supported_targets = [ "native", "js" ]

preferred_target = "native"

import {
  "moonbitstack/mooncred@0.6.1",
  "moonbitstack/mooncrypt@0.3.1",
  "justinwongcn/experimental_crypto@0.0.3",
  "1726914517-spec/moon_otp@0.3.1",
  "moonbitlang/async@0.22.4",
}
