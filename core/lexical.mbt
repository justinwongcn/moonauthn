//! moonauth / core —— 字典序字符串比较与排序（跨平台可重放）。
//!
//! 🔴 **为什么需要这个文件：MoonBit 的 `String::compare` 不是字典序。**
//!
//! 当前工具链的 `String` 默认 `Compare` 是「**先比长度、再比内容**」，与「字典序」
//! 直觉不一致（在 `core/lexical_wbtest.mbt` 有断言锁定，防止未来工具链变更时悄然失配）：
//!
//! | 表达式 | 实测结果 | 说明 |
//! |---|---|---|
//! | `"b".compare("aa")` | `-1` | 长度优先 → `"b" < "aa"` |
//! | `"aa".compare("b")` | `1` | 同上 |
//! | `"zeta".compare("alpha")` | `-1` | 长度优先 → `"zeta"(4) < "alpha"(5)` |
//! | `"a".compare("b")` | `-1` | 仅**同长度**时才退化为内容比较 |
//!
//! 于是 `["zeta","alpha"].sort()` 得到 `["zeta","alpha"]`——**不是**字典序的
//! `["alpha","zeta"]`。
//!
//! **为什么这对本库是致命的**：支付宝 RSA2 等签名串要求参数 `key` 按 **ASCII 升序**
//! 拼接。用默认 `sort()` 会得到完全不同的顺序，导致签名恒错，而服务端只回
//! `isv.invalid-signature`，**不会提示是排序问题**——足以耗掉整天。
//!
//! 故本模块提供确定的、按 UTF-8 字节比较的字典序原语，供**全库**复用
//! （`oauth` 的 `extra` 参数排序、`provider/*` 自 T03 起的签名串排序等）。
//!
//! 🔴 **为什么它住在 `core` 而不是某个功能包**：这是一条**跨领域**的文本工具，不是
//! 任何单一协议语义的一部分。其真正的外部消费者（`provider/alipay` 的 ASCII 升序）
//! 若必须依赖 `oauth` 功能包才能取到它，就是依赖倒置——`core` 才是全库共享地基
//! （`error_map.mbt` 等纯工具已在此），任何包都能直接取用，无需为一个字符串工具
//! 依赖某个功能包。
//!
//! 注：`Array[Int].sort()` **不受此影响**（整数比较正常升序），此陷阱**仅限字符串
//! 的默认比较**。

///|
/// 字符串字典序比较（按 UTF-8 字节逐位）；返回 `<0` / `0` / `>0`。
///
/// 语义 = 「按字节的 ASCII 升序」：先比到首个不同字节，较小者在前；
/// 一方是另一方前缀时，较短者在前。对纯 ASCII 输入即 ASCII 升序
/// （正是支付宝签名串所用）。
pub fn lexicographic_compare(a : String, b : String) -> Int {
  let x = @utf8.encode(a)
  let y = @utf8.encode(b)
  let nx = x.length()
  let ny = y.length()
  let n = if nx < ny {
    nx
  } else {
    ny
  }
  let mut i = 0
  while i < n {
    let cx = x[i].to_int()
    let cy = y[i].to_int()
    if cx != cy {
      if cx < cy {
        return -1
      } else {
        return 1
      }
    }
    i = i + 1
  }
  if nx == ny {
    0
  } else if nx < ny {
    -1
  } else {
    1
  }
}

///|
/// 返回一个**新的**、字典序升序的字符串数组（不改原数组，且**不依赖**默认
/// `String::compare`／`Array::sort()`）。
///
/// 供拼签名串 / query 前对 `key` 排序使用。
pub fn sort_lexicographic(xs : Array[String]) -> Array[String] {
  let out = xs.copy()
  out.sort_by(fn(a, b) { lexicographic_compare(a, b) })
  out
}

///|
/// 取 `Map` 的键并返回**字典序升序**数组——拼签名串 / query 的通用构件。
///
/// 排序确定（跨平台可重放），顺序为 ASCII/UTF-8 字节升序。
pub fn sorted_keys(m : Map[String, String]) -> Array[String] {
  let keys : Array[String] = []
  for k, _ in m {
    keys.push(k)
  }
  sort_lexicographic(keys)
}
