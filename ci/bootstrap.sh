#!/usr/bin/env bash
#
# moonauth 依赖引导（check.sh 第 0 步）—— 在**最新工具链**下修复 .mooncakes
# 第三方依赖的兼容性。**幂等**：缓存已迁移过时是零开销的 no-op。
#
# 🔴 背景（2026-11-17）：
#   - moon 0.1.20261104（当前官方 latest）移除了 `try?` 语法（诊断 [3002]），并在
#     `.mbti` 把默认 `Int` 渲染为 `Int32`。第三方依赖 `justinwongcn/experimental_crypto@0.0.3`
#     （registry 最新且唯一版本，无升级路径）仍使用 `try?`，其 `webauthn` 包在 moonauth
#     的编译闭包内（passkey / qa_verify 依赖）。
#   - `moonbitlang/regexp@0.3.5`（`mizchi/x@0.6.1` 的依赖，历史路径：经已移除的
#     examples/mars 进入工作区依赖图）还是旧 `moon.mod.json` manifest 格式，会让依赖**解析**直接失败。
#   本脚本对 **缓存**（`.mooncakes/`，gitignore、可随时删除重建）做确定性迁移：
#     1) 旧格式 manifest → `moon.mod`（官方 `moon fmt` 迁移路径）；
#     2) `try? EXPR` → `try Ok(EXPR) catch { e => Err(e) }`（官方诊断 [3002] 给出的
#        **语义保持**替换）。单行与「`try? 调用(` 跨行」两种形态都覆盖；跳过注释行；
#        检测带词边界（`retry?` / `T?` / JS 字符串里的 `?.` 不误报）。
#   全新缓存需要多轮（先触发 moon 拉取依赖，再迁移，再验证），见下方循环。
#   🔴 上游发布修复版本后：bump 依赖版本并删除本脚本中对应的迁移项。
#
# 用法：由 `ci/check.sh` 第 0 步统一调用；也可单独执行。

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${SCRIPT_DIR}/.."
cd "${ROOT_DIR}"

blue() { printf '\033[36m%s\033[0m\n' "$*"; }
red()  { printf '\033[31m%s\033[0m\n' "$*"; }

# ── 1) 旧格式 manifest 迁移（moon.mod.json → moon.mod）──────────────────────
migrate_manifests() {
  for d in .mooncakes/*/*/; do
    if [[ -f "${d}moon.mod.json" && ! -f "${d}moon.mod" ]]; then
      blue "bootstrap: migrate manifest ${d}"
      # 在包目录内单独跑 fmt：把该包当作独立模块迁移（官方迁移路径）。
      (cd "${d}" && moon fmt >/dev/null 2>&1) || true
    fi
  done
}

# ── 2) `try?` 语法迁移（幂等：无候选时真正零开销跳过）───────────────────────
# 覆盖 .mooncakes 全部**非测试** .mbt（排除 `_build` 产物目录）。测试文件
# （*_test.mbt / *_wbtest.mbt）不进入本仓库的构建/测试闭包，暂不迁移。
# 先用预筛找出仍可能含旧语法 `try?` 的候选：剥离 `//` 注释行后，要求
# `try?` 前不是字母数字下划线（排除 `retry?` / `DirectoryEntry?` 等误报）。
# 候选为空 = 缓存已迁移，直接跳过——这样无 Python 的机器（如 Windows 上
# python/python3 均为商店占位符）在已迁移缓存上可跑通；候选非空时才要求
# 可运行的解释器。预筛仅做粗筛，真实迁移仍由 migrate_try.py 的精确
# 词边界/注释/字符串感知逻辑执行。
migrate_try_question() {
  local candidates=""
  local f
  while IFS= read -r f; do
    if grep -vE '^[[:space:]]*//' "$f" | grep -qE '(^|[^A-Za-z0-9_])try\?'; then
      candidates="${candidates}${f}"$'\n'
    fi
  done < <(find .mooncakes -name '*.mbt' -not -path '*/_build/*' \
             -not -name '*_test.mbt' -not -name '*_wbtest.mbt' -print 2>/dev/null)
  if [[ -z "${candidates}" ]]; then
    return 0
  fi
  # 解释器：python3 优先、python 回退；须实际可运行（`command -v` 会命中
  # Windows Store 占位符，故用 `--version` 做真实探测）。
  local py=""
  if command -v python3 >/dev/null 2>&1 && python3 --version >/dev/null 2>&1; then
    py="$(command -v python3)"
  elif command -v python >/dev/null 2>&1 && python --version >/dev/null 2>&1; then
    py="$(command -v python)"
  fi
  if [[ -z "${py}" ]]; then
    red "bootstrap: 存在待迁移 try? 文件，但 python3/python 不可用"
    exit 1
  fi
  while IFS= read -r f; do
    # 迁移器恒退出 0；有真实改动时才输出提示（幂等验证依据：第二遍应无提示）。
    out="$("${py}" ci/migrate_try.py "$f")" || {
      red "bootstrap: migrate_try failed on ${f}"; exit 1;
    }
    if [[ -n "${out}" ]]; then
      blue "bootstrap: migrate try? ${f}"
    fi
  done <<<"${candidates}"
}

# ── 引导循环 ────────────────────────────────────────────────────────────────
# 全新缓存（如 CI 首次 checkout）时依赖尚未下载：先跑一次 `moon check` 触发
# 拉取与安装（失败不阻塞），再迁移，再验证；最多 4 轮（当前已知 2 类兼容问题）。
# fresh runner 可能只有陈旧的 registry 索引；先刷新再触发依赖解析。
blue "bootstrap: refresh registry index"
moon update

migrate_manifests
migrate_try_question

for _round in 1 2 3 4; do
  if moon check --target native >/dev/null 2>&1; then
    blue "bootstrap: moon check passed (round ${_round})"
    break
  fi
  blue "bootstrap: moon check failed (round ${_round}) — migrating cache and retrying"
  migrate_manifests
  migrate_try_question
done

# 注意：即使引导后 moon check 仍失败也不在此退出——后续 check.sh 的正式步骤会
# 给出权威报错输出（bootstrap 只负责兼容性迁移，不掩盖真实错误）。
blue "bootstrap: done"
