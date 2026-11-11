#pragma once
// миниатюрный тестовый фреймворк
#include <cstdio>
#include <string>
#include <vector>

namespace testfw {

struct Test {
  std::string name;
  void (*fn)();
};

inline std::vector<Test>& registry() {
  static std::vector<Test> r;
  return r;
}

inline int& failures() {
  static int f = 0;
  return f;
}

inline int& checks() {
  static int c = 0;
  return c;
}

struct Registrar {
  Registrar(const char* name, void (*fn)()) { registry().push_back({name, fn}); }
};

}  // namespace testfw

#define MIKTO_TEST(name)                                  \
  static void test_body_##name();                         \
  static testfw::Registrar reg_##name(#name, &test_body_##name); \
  static void test_body_##name()

#define CHECK(cond)                                                       \
  do {                                                                    \
    ++testfw::checks();                                                   \
    if (!(cond)) {                                                        \
      ++testfw::failures();                                               \
      std::printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);       \
    }                                                                     \
  } while (0)

#define CHECK_EQ(a, b)                                                    \
  do {                                                                    \
    ++testfw::checks();                                                   \
    auto va_ = (a);                                                       \
    auto vb_ = (b);                                                       \
    if (!(va_ == vb_)) {                                                  \
      ++testfw::failures();                                               \
      std::printf("  FAIL %s:%d: %s == %s\n", __FILE__, __LINE__, #a, #b);\
    }                                                                     \
  } while (0)
