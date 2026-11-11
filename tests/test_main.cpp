// входная точка тестов
#include "test_fw.hpp"

int main() {
  for (const auto& t : testfw::registry()) {
    int before = testfw::failures();
    t.fn();
    std::printf("%s %s\n", testfw::failures() == before ? "ok  " : "FAIL",
                t.name.c_str());
  }
  std::printf("\n%d checks, %d failures\n", testfw::checks(),
              testfw::failures());
  return testfw::failures() ? 1 : 0;
}
