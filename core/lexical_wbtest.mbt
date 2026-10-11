//! moonauth / core —— 白盒测试：字典序原语（`lexical.mbt`）。
//!
//! 🔴 **工具行为必须在它自己的包里锁死**（而不是靠下游包 `oauth`/`provider` 间接锁定）。
//! 这些断言同时是「工具链行为快照」：若未来 MoonBit 把 `String::compare` 改成字典序，
//! 第一条断言会失败——那正是需要复核 `lexical.mbt` 前提的信号（届时其实现仍正确）。

///|
/// 🔴 **锁定工具链事实**：默认 `String::compare` 先比长度、再比内容，**不是字典序**；
/// 并证明本库 `lexicographic_compare` 与之不同（这正是 `lexical.mbt` 存在的理由）。
test "lexical: default String::compare is length-first, NOT lexicographic" {
  // 工具链事实（先比长度、再比内容）：
  assert_true("b".compare("aa") < 0) // "b" < "aa" ← 长度优先
  assert_true("aa".compare("b") > 0)
  assert_true("zeta".compare("alpha") < 0) // 4 < 5 ← 长度优先
  assert_true("a".compare("b") < 0) // 仅同长度才退化为内容比较
  // 字典序原语给出**相反且正确**的结果：
  assert_true(lexicographic_compare("b", "aa") > 0) // "b" > "aa"
  assert_true(lexicographic_compare("zeta", "alpha") > 0)
  assert_true(lexicographic_compare("alpha", "zeta") < 0)
  assert_true(lexicographic_compare("a", "b") < 0)
  assert_eq(lexicographic_compare("abc", "abc"), 0)
  // 一方是前缀时，较短者在前
  assert_true(lexicographic_compare("abc", "abcd") < 0)
}

///|
/// `sort_lexicographic` 得到真正的字典序；默认 `Array[String].sort()` 不会。
test "lexical: sort_lexicographic differs from default Array[String].sort" {
  // 默认序（长度优先，快照）：beta(4)/zeta(4) 先按内容 → alpha(5) 最后
  let default_sorted : Array[String] = ["zeta", "alpha", "beta"]
  default_sorted.sort()
  @debug.assert_eq(default_sorted, ["beta", "zeta", "alpha"])
  // 字典序：alpha < beta < zeta
  @debug.assert_eq(
    sort_lexicographic(["zeta", "alpha", "beta"]),
    ["alpha", "beta", "zeta"],
  )
  // 支付宝风格：参数 key 的 ASCII 升序（RSA2 签名串要求）
  @debug.assert_eq(
    sort_lexicographic([
      "sign_type", "app_id", "method", "charset", "timestamp", "version",
      "biz_content", "format",
    ]),
    [
      "app_id", "biz_content", "charset", "format", "method", "sign_type",
      "timestamp", "version",
    ],
  )
  // sorted_keys(Map) 亦按字典序
  @debug.assert_eq(
    sorted_keys(Map([("zeta", "1"), ("alpha", "2")])),
    ["alpha", "zeta"],
  )
  // 不改原数组
  let original : Array[String] = ["zeta", "alpha"]
  let _ = sort_lexicographic(original)
  @debug.assert_eq(original, ["zeta", "alpha"])
}

///|
/// ✅ **明确结论**：`Array[Int].sort()` **正常**（升序）——长度优先陷阱**仅限
/// 字符串的默认比较**。（字符串键排序务必用本模块，整数键不受影响。）
test "lexical: Array[Int].sort is normal ascending (trap is string-only)" {
  let ints : Array[Int] = [5, 1, 3, 2, 4]
  ints.sort()
  @debug.assert_eq(ints, [1, 2, 3, 4, 5])
  let signed : Array[Int] = [0, -3, 7, -1, 2]
  signed.sort()
  @debug.assert_eq(signed, [-3, -1, 0, 2, 7])
}
