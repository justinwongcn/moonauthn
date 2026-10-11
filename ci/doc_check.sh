#!/usr/bin/env bash
#
# moonauth —— 文档与实物一致性检查（判据：HANDOVER §9.21 / ARCH §10.15）。
#
# 项目历史上「文档写了实物不存在的东西」中过 6 次（伪包名 ×4 + 不存在的文件名
# + 若干文件路径）。本脚本把判据落成机械检查，作为 CI 的一步：
#
#   1) 文档里出现的**文件路径**（`.mbt` / `.md` / `moon.mod` …）必须真实存在——
#      权威来源是 `ls`/`find`，绝不接受「由签名反推的文件名」；
#   2) 文档里出现的**库内包路径**（`justinwongcn/moonauth/...`）必须对应真实目录；
#   3) 文档里出现的**库内标识符**必须能在 `.mbti`（权威来源）里找到：
#        - `@pkg.Ident`：当 `pkg` 判定为本库包别名时，`Ident` 必须已知；
#        - `@pkg.Ident`：当 `pkg` **不是**本库包、而 `Ident` 是本库已知标识符时，
#          判为「伪包名」（历史上 ×4 的那类：`@moonauth_core.AuthStart` 等）；
#        - `Type::name`：当 `Type` 判定为本库类型时，`name` 必须已知。
#
# 检查范围 = 随包发布的文档：`README.md` / `CHANGELOG.md` / `docs/**/*.md`。
# `plan/`（工作区内部）与 `HANDOVER.md` 不属发布面，不在本检查内。
#
# 已知的第三方写法（`@env.` / `@otp.` / `@jwt.` / `@example.com` 等）经白名单排除；
# 即便如此，新增命中仍须按 HANDOVER §9.20 读语境人工复核，不得盲信本脚本。

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"     # moonauth 模块根
PARENT_DIR="$(cd "${ROOT_DIR}/.." && pwd)"     # 工作区根（容纳 plan/ 等）
cd "${ROOT_DIR}"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }

VIOLATIONS=0
report() { red "  ✗ $1"; VIOLATIONS=$((VIOLATIONS + 1)); }

# ── 刷新 .mbti（权威来源），失败不阻塞——沿用 check.sh 第 6 步的宽容策略 ──
moon info >/dev/null 2>&1 || true

# ── 已知标识符全集：全部 pkg.generated.mbti 的 pub 面 ──
# 剔除 `package "..."` / `import { ... }` 头部：包名本身（如 `rand`）不是标识符，
# 否则 `@env.rand` 一类第三方便捷函数引用会误报。
KNOWN="$(find . \( -path './.mooncakes' -o -path './_build' \) -prune -o \
    -name 'pkg.generated.mbti' -print 2>/dev/null \
  | xargs cat 2>/dev/null \
  | sed -n '/^\/\/ Values/,$p' \
  | grep -oE '[A-Za-z_][A-Za-z0-9_]*' | sort -u || true)"

have() { grep -qx -- "$1" <<<"${KNOWN}"; }

# 本库包别名（moon.pkg 引用短名；`store-memory` 目录 → 别名 `store_memory`）。
# 可跨行书写：匹配按「空格包围」进行，先把换行归一为空格。
OUR_PKGS=" core oauth oidc passkey totp rand store_memory store-memory
  contract qa_verify seam_probe http_e2e google apple x wechat qq alipay
  github discord dingtalk feishu "
OUR_PKGS="${OUR_PKGS//$'\n'/ }"
in_our_pkgs() { [[ "${OUR_PKGS}" == *" $1 "* ]]; }

# 文档合法提及、但不属本库 `.mbti` 的例外（内建 / 第三方）。
#  - String::compare：HANDOVER §9.6 记档的坑名（长度优先 vs 字典序），String 是内建类型。
ID_ALLOW=" String::compare "
id_allowed() { [[ "${ID_ALLOW}" == *" $1 "* ]]; }

# 第三方包别名白名单（默认实现真实引用的第三方包；这些前缀不做伪包名判定）。
THIRD_PKGS=" jwt json jwk spec ecdsa rsa otp env mooncred mooncrypt moonbase http "
in_third_pkgs() { [[ "${THIRD_PKGS}" == *" $1 "* ]]; }

# 顶级域名后缀——排除 `@example.com` 一类邮箱/origin 误配。
TLDS=" com org net cn io dev app "
is_tld() { [[ "${TLDS}" == *" $1 "* ]]; }

# ── 花括号展开：docs/platforms/{google,apple,...}.md → 逐个真实路径 ──
expand_braces() {
  local tok="$1"
  if [[ "${tok}" == *\{*,*\}* ]]; then
    local pre="${tok%%\{*}"
    local rest="${tok#*\{}"
    local inner="${rest%%\}*}"
    local post
    if [[ "${rest}" == *\}* ]]; then post="${rest#*\}}"; else post=""; fi
    local part
    local IFS=','
    for part in ${inner}; do printf '%s\n' "${pre}${part}${post}"; done
  else
    printf '%s\n' "${tok}"
  fi
}

# ── 文件路径存在性：模块根 → 工作区根 → 文档所在目录 → 裸文件名全仓 find → glob ──
check_path() {
  local p="$1" where="$2" fdir="$3"
  p="${p#./}"
  p="${p//[[:space:]]/}"
  [[ -z "${p}" ]] && return 0
  # 注意模式必须写作 *"*"*：写成 *[* 会因方括号未闭合而退化为字面 `[`
  if [[ "${p}" == *"*"* ]]; then
    # 通配写法（如 provider/*/pkg.generated.mbti）：能展开即通过
    if compgen -G "${p}" >/dev/null 2>&1; then return 0; fi
  else
    if [[ -e "${ROOT_DIR}/${p}" || -e "${PARENT_DIR}/${p}" || -e "${fdir}/${p}" ]]; then return 0; fi
    if [[ "${p}" != */* ]]; then
      # 裸文件名：允许落在任意包目录（如 `memory_wbtest.mbt`、`pkg.generated.mbti`）
      if find . \( -path './.mooncakes' -o -path './_build' \) -prune -o \
           -name "${p}" -print -quit 2>/dev/null | grep -q .; then
        return 0
      fi
    fi
  fi
  report "${where}: 文档引用的路径不存在: ${p}"
}

# ── 逐行扫描 ──
DOCS="$(ls README.md CHANGELOG.md 2>/dev/null; find docs -name '*.md' 2>/dev/null | sort)"
[[ -n "${DOCS// /}" ]] || { red "doc_check: no docs found"; exit 1; }

ln=0
while IFS= read -r f; do
  [[ -f "${f}" ]] || continue
  fdir="$(dirname "${f}")"
  while IFS= read -r line; do
    ln=$((ln + 1))
    # 先剥 URL，防止 https://... 里的片段被当成本仓路径/包名
    clean="$(sed -E 's#https?://[^ )`>|]+##g' <<<"${line}")"
    where="${f}:${ln}"

    # (1) 文件路径
    while IFS= read -r tok; do
      [[ -z "${tok}" ]] && continue
      while IFS= read -r p; do
        [[ -z "${p}" ]] && continue
        check_path "${p}" "${where}" "${fdir}"
      done < <(expand_braces "${tok}")
    done < <(grep -oE '[A-Za-z_.][A-Za-z0-9_./,{}*-]*\.(mbt|mbti|sh|ya?ml|mod|pkg|json|toml|work|md)($|[^A-Za-z0-9_])' <<<"${clean}" | sed -E 's/[^A-Za-z0-9_.{}*/]*$//' || true)

    # (2) 库内包路径
    while IFS= read -r m; do
      [[ -z "${m}" ]] && continue
      rel="${m#justinwongcn/moonauth}"
      d="${rel#/}"
      if [[ -z "${d}" ]]; then
        # 裸模块名或 `justinwongcn/moonauth/`（泛指）：以库根 moon.mod 为实物
        [[ -f moon.mod ]] || report "${where}: 库根不存在 moon.mod（引用: ${m}）"
      else
        [[ -d "${d}" ]] || report "${where}: 库内包路径不存在: ${m}"
      fi
    done < <(grep -oE 'justinwongcn/moonauth[a-zA-Z0-9/_-]*' <<<"${clean}" || true)

    # (3a) Type::name —— Type 判定为本库类型时，name 必须已知
    while IFS= read -r m; do
      [[ -z "${m}" ]] && continue
      id_allowed "${m}" && continue
      t="${m%%::*}"; n="${m##*::}"
      if have "${t}"; then
        have "${n}" || report "${where}: 标识符在 .mbti 中不存在: ${m}"
      fi
    done < <(grep -oE '[A-Za-z_][A-Za-z0-9_]*::[A-Za-z_][A-Za-z0-9_]*' <<<"${clean}" || true)

    # (3b) @pkg.Ident
    while IFS= read -r m; do
      [[ -z "${m}" ]] && continue
      pkg="${m#@}"; pkg="${pkg%%.*}"
      ident="${m##*.}"
      is_tld "${ident}" && continue
      if in_our_pkgs "${pkg}"; then
        have "${ident}" || report "${where}: 本库包 ${pkg} 下无此标识符: ${m}"
      elif ! in_third_pkgs "${pkg}"; then
        # 伪包名形态：用不存在的别名引用本库已知标识符（历史 ×4 事故的形状）
        have "${ident}" && report "${where}: 未知包别名引用本库标识符: ${m}"
      fi
    done < <(grep -oE '@[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*' <<<"${clean}" || true)
  done < "${f}"
  ln=0
done <<<"${DOCS}"

if (( VIOLATIONS > 0 )); then
  red "doc_check FAILED: ${VIOLATIONS} 处文档与实物不一致（每处须读语境复核，判据 HANDOVER §9.20/§9.21）"
  exit 1
fi
green "docs match reality: paths / package paths / identifiers（README + CHANGELOG + docs/**）"
