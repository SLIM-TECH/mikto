// тесты строковых хелперов
#include "test_fw.hpp"

#include "mikto/util.hpp"

using namespace mikto;

MIKTO_TEST(trim_basic) {
  CHECK_EQ(trim("  hello  "), std::string("hello"));
  CHECK_EQ(trim("\t x\n"), std::string("x"));
  CHECK_EQ(trim(""), std::string(""));
  CHECK_EQ(trim("   "), std::string(""));
}

MIKTO_TEST(split_basic) {
  auto parts = split("a,b,c", ',');
  CHECK_EQ(parts.size(), size_t(3));
  CHECK_EQ(parts[0], std::string("a"));
  CHECK_EQ(parts[2], std::string("c"));
  auto one = split("solo", ',');
  CHECK_EQ(one.size(), size_t(1));
  auto trailing = split("a,", ',');
  CHECK_EQ(trailing.size(), size_t(2));
  CHECK_EQ(trailing[1], std::string(""));
}

MIKTO_TEST(starts_ends) {
  CHECK(starts_with("https://x", "https://"));
  CHECK(!starts_with("http://x", "https://"));
  CHECK(ends_with("main.js", ".js"));
  CHECK(!ends_with("main.jsx", ".js"));
}

MIKTO_TEST(iequals_contains) {
  CHECK(iequals("Content-Type", "content-type"));
  CHECK(!iequals("abc", "abd"));
  CHECK(contains_ci("Strict-Transport-Security: max-age=100", "MAX-AGE"));
  CHECK(!contains_ci("abc", "zzz"));
}

MIKTO_TEST(html_escape) {
  CHECK_EQ(html_escape("<a href=\"x\">&'</a>"),
           std::string("&lt;a href=&quot;x&quot;&gt;&amp;&#39;&lt;/a&gt;"));
}

MIKTO_TEST(truncate_ellipsis) {
  CHECK_EQ(truncate_ellipsis("short", 10), std::string("short"));
  std::string t = truncate_ellipsis("abcdefghij", 8);
  CHECK_EQ(t.size(), size_t(8));
  CHECK(ends_with(t, "..."));
}
