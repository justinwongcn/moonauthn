The MoonBit core library "moonbitlang/x" is vendored here at version 0.5.8.

Source: https://github.com/moonbitlang/x (published on mooncakes.io as moonbitlang/x 0.5.8)
License: Apache License 2.0 (OSI-approved), copyright MoonBit lang / moonbitlang contributors.

Vendored for local workspace resolution: the registry manifest of the version pinned
by mizchi/experimental_crypto@0.0.2 (moonbitlang/x@0.4.43) uses the legacy
`moon.mod.json` format, which newer MoonBit toolchains refuse to install. The vendored
copy is migrated to the current `moon.mod` format and registered as a `moon.work`
workspace member, so the module name `moonbitlang/x` resolves locally.

Upstream Apache-2.0 license text: https://www.apache.org/licenses/LICENSE-2.0
