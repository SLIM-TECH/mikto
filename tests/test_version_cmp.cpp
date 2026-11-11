// тесты сравнения версий
#include "test_fw.hpp"

#include "mikto/version.hpp"

using namespace mikto;

MIKTO_TEST(version_numeric_order) {
  CHECK(compare_versions("1.0", "2.0") < 0);
  CHECK(compare_versions("2.0", "1.9.9") > 0);
  CHECK(compare_versions("1.25.3", "1.25.3") == 0);
  CHECK(compare_versions("1.25.3", "1.25.10") < 0);
  CHECK(compare_versions("8.0.11", "8.0.9") > 0);
  CHECK(compare_versions("9", "10") < 0);
}

MIKTO_TEST(version_suffixes) {
  // "p1" выше голой версии
  CHECK(compare_versions("9.6p1", "9.6") > 0);
  CHECK(compare_versions("9.6p1", "9.6p2") < 0);
  CHECK(compare_versions("3.0.3", "3.0") > 0);
  CHECK(compare_versions("1.0", "1.0.0") == 0);
}

MIKTO_TEST(version_multi_digit) {
  CHECK(compare_versions("1.9", "1.25") < 0);
  CHECK(compare_versions("2.4.57", "2.4.6") > 0);
}
