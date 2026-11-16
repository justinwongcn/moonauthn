#!/usr/bin/env python3
"""把 MoonBit 旧语法 `try? EXPR` 迁移为官方诊断 [3002] 给出的语义保持替换
`try Ok(EXPR) catch { e => Err(e) }`。

设计约束（moonauth ci/bootstrap.sh 调用，针对 .mooncakes 第三方依赖缓存）：
- 幂等：迁移完成后再次运行不再改动文件（退出码 0 且不输出）。
- 有真实改动时：写回文件并打印一行提示，退出码 0。
- 检测带词边界：`retry?` / `Option<T>?` 形的标签后缀与类型后缀、JS 字符串里的
  `?.` 都不是 `try?` 运算符，不误报。
- 跳过 `//` / `///` 注释行（文档里提到 `try?` 不改写）。
- 覆盖两种形态：
  1) 单行：`(try? EXPR).unwrap_or(..)` / `let _ = try? EXPR` / `= try? EXPR`；
  2) 跨行：`... = try? 调用名(` 换行续参 —— 按括号配对在调用收口处补
     `) catch { e => Err(e) }`（括号计数不含字符串字面量内的括号——这些调用
     的参数是变量名，无此形态）。

退出码：0 = 正常（无论是否改动）；其他 = 异常。
"""
import re
import sys

# 真实 `try?` 运算符：前面不能是标识符字符（排除 `retry?` / `max_retry?`）。
TRY_RE = re.compile(r'(?:^|[^_a-zA-Z0-9])try\?')
# 跨行形态行尾：`try? 调用名(`——调用名可带 `@` 包前缀（如 `@aead.seal_detached`）。
MULTILINE_RE = re.compile(r'try\?\s*([@\w.:/]+)\($')


def has_real_try(lines):
    for line in lines:
        s = line.lstrip()
        if s.startswith('//'):
            continue
        if TRY_RE.search(line):
            return True
    return False


def migrate_single_line(line):
    """单行形态；返回 (新行, 是否改动)。"""
    if line.lstrip().startswith('//'):
        return line, False
    changed = False
    # (try? EXPR).unwrap_or( —— EXPR 与 `(try?` 同在一行（依赖内最常见的验证包装）
    if '(try?' in line and ').unwrap_or(' in line:
        new = re.sub(r'\(try\? (.+)\)\.unwrap_or\(',
                     r'(try Ok(\1) catch { e => Err(e) }).unwrap_or(', line)
        if new != line:
            line, changed = new, True
    # 行尾补 `(` 的多行调用不在此处理；完整单行表达式。
    # 🔴 行尾只吞空格/制表符（`[ \t]*$`）——用 `\s*$` 会把换行符也吞掉，
    #    导致迁移后的行与下一行**粘连**（真实事故：naclbox.mbt 的 `match` 行）。
    if not line.rstrip('\n').rstrip().endswith('(') and TRY_RE.search(line):
        new = re.sub(r'= ?try\? (.+?)[ \t]*$',
                     r'= try Ok(\1) catch { e => Err(e) }', line)
        if new != line:
            line, changed = new, True
    return line, changed


def migrate(lines):
    out = []
    changed_total = False
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        s = line.lstrip()
        if s.startswith('//'):
            out.append(line)
            i += 1
            continue
        # 跨行形态：`... try? 调用名(`（行尾恰为调用名的开括号）
        m = MULTILINE_RE.search(line)
        if m:
            # 保留原行尾（换行符在 m.start()+len('try?') 之后的余文里）——
            # 🔴 直接拼新行不带回车会把下一行粘上来。
            out.append(line[:m.start()] + 'try Ok(' + line[m.start() + 4:])
            depth = 1  # 已进入 `调用名(` 的括号
            j = i + 1
            done = False
            while j < n and not done:
                l2 = lines[j]
                buf = []
                for k, ch in enumerate(l2):
                    buf.append(ch)
                    if ch == '(':
                        depth += 1
                    elif ch == ')':
                        depth -= 1
                        if depth == 0:
                            # 该 `)` 收口调用；再补一层收 `try Ok(` 的括号，
                            # 并保留该行 `)` 之后的余文（通常是换行符）。
                            buf.append(') catch { e => Err(e) }')
                            buf.append(l2[k + 1:])
                            done = True
                            break
                out.append(''.join(buf))
                j += 1
            changed_total = True
            i = j
            continue
        new, changed = migrate_single_line(line)
        out.append(new)
        changed_total = changed_total or changed
        i += 1
    return out, changed_total


def main():
    if len(sys.argv) != 2:
        print('usage: migrate_try.py <file>', file=sys.stderr)
        return 2
    path = sys.argv[1]
    with open(path, encoding='utf-8') as f:
        lines = f.readlines()
    if not has_real_try(lines):
        return 0
    out, changed = migrate(lines)
    if changed:
        with open(path, 'w', encoding='utf-8') as f:
            f.writelines(out)
        print('migrated try? in ' + path)
    return 0


if __name__ == '__main__':
    sys.exit(main())
