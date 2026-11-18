#!/usr/bin/env bash
#
# moonauth 本地 CI —— 一条脚本把「该绿的都跑一遍」。
#
# 这个脚本是**唯一**的 CI 事实来源：`.github/workflows/ci.yml` 只负责 `checkout` 后调用它，
# 从而保证「本机跑」与「CI 跑」行为一致。
#
# 断言：
#   0) 依赖引导（ci/bootstrap.sh）：在最新工具链下对 .mooncakes 缓存做幂等兼容性迁移
#      （旧格式 manifest + `try?` 语法，见脚本头注释）——全新缓存的多轮自愈也在这里
#   1) native 与 js 双 target 编译 —— 任一失败即红
#   2) native 与 js 双 target 全量测试 —— 任一失败即红（含 contract 参数化契约）
#   3) examples/minimal-google 的 LIB-20 隔离：只 import provider/google，且能独立跑通
#   4) 六个 provider 的 .mbti 中**无第三方类型泄漏**（SDK-03）
#   5) 文档与实物一致性：路径 / 库内包路径 / 标识符（判据 HANDOVER §9.21，逻辑在 ci/doc_check.sh）
#
# 用法：./ci/check.sh   （在 moonauth/ 根目录或任意位置运行均可）

set -euo pipefail

# —— 定位到模块根（脚本所在目录的上一级）——
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

PROVIDERS=(google apple wechat qq alipay x github discord dingtalk feishu microsoft)

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
step()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
fail()  { red "CI FAILED: $*"; exit 1; }

step "0/7  依赖引导（最新工具链兼容性，幂等）"
bash "${SCRIPT_DIR}/bootstrap.sh"
green "deps bootstrap OK"

step "1/7  build native"
moon build --target native
green "native build OK"

step "2/7  build js"
moon build --target js
green "js build OK"

step "3/7  test native"
moon test --target native
green "native test OK"

step "4/7  test js"
moon test --target js
green "js test OK"

step "5/7  LIB-20 isolation: examples/minimal-google imports ONLY provider/google"
MM_PKG="examples/minimal-google/src/moon.pkg"
[[ -f "${MM_PKG}" ]] || fail "missing ${MM_PKG}"
MOONAUTH_IMPORTS="$(grep -oE '"justinwongcn/moonauth[^"]*"' "${MM_PKG}" | sort -u | tr -d '"' || true)"
EXPECTED="justinwongcn/moonauth/provider/google"
if [[ "${MOONAUTH_IMPORTS}" != "${EXPECTED}" ]]; then
  red "minimal-google must import exactly [${EXPECTED}], got:"
  printf '%s\n' "${MOONAUTH_IMPORTS}"
  fail "LIB-20 isolation violated"
fi
# 独立跑通（打印 provider = google）
OUT="$(moon run examples/minimal-google/src --target native 2>/dev/null || true)"
echo "${OUT}" | grep -q "provider = google" || fail "minimal-google did not run as expected:\n${OUT}"
green "LIB-20 isolation OK (minimal-google runs, imports only provider/google)"

step "6/7  第三方类型泄漏 grep（SDK-03）"
# 先刷新 .mbti，再断言：十个 provider 的公开签名里不得出现任何第三方类型。
moon info >/dev/null 2>&1 || true
LEAKS=""
for p in "${PROVIDERS[@]}"; do
  f="provider/${p}/pkg.generated.mbti"
  [[ -f "${f}" ]] || fail "missing generated interface: ${f}"
  if grep -nE '(^|[^A-Za-z])(Json|@json|@jwt|@mooncrypt|@ecdsa|@rsa|@otp|@utf8|moonbitstack|mizchi)([^A-Za-z]|$)' "${f}" >/dev/null 2>&1; then
    LEAKS="${LEAKS}\n  ${f}"
  fi
done
if [[ -n "${LEAKS}" ]]; then
  red "third-party types leaked into provider .mbti:${LEAKS}"
  fail "SDK-03 violated"
fi
green "no third-party type leakage in provider .mbti"

step "7/7  文档与实物一致性（路径 / 包路径 / 标识符）"
bash "${SCRIPT_DIR}/doc_check.sh"

printf '\n'
green "=============================================="
green " CI PASSED: build(native+js) / test(native+js) / LIB-20 / SDK-03 / docs"
green "=============================================="
