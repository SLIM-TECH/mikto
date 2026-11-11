// тесты парсинга целей
#include "test_fw.hpp"

#include <cstdio>
#include <fstream>

#include "mikto/target.hpp"

using namespace mikto;

MIKTO_TEST(target_plain_ip) {
  Target t;
  std::string err;
  CHECK(parse_target("203.0.113.10", t, err));
  CHECK_EQ(t.host, std::string("203.0.113.10"));
  CHECK(t.is_ip);
  CHECK_EQ(t.port, 0);
  CHECK(t.scheme.empty());
}

MIKTO_TEST(target_url_with_port) {
  Target t;
  std::string err;
  CHECK(parse_target("https://target.example:8443/", t, err));
  CHECK_EQ(t.scheme, std::string("https"));
  CHECK_EQ(t.host, std::string("target.example"));
  CHECK_EQ(t.port, 8443);
  CHECK(!t.is_ip);
}

MIKTO_TEST(target_hostname_lowercased) {
  Target t;
  std::string err;
  CHECK(parse_target("TARGET.Example", t, err));
  CHECK_EQ(t.host, std::string("target.example"));
}

MIKTO_TEST(target_ipv6) {
  Target t;
  std::string err;
  CHECK(parse_target("[::1]:443", t, err));
  CHECK_EQ(t.host, std::string("::1"));
  CHECK_EQ(t.port, 443);
  CHECK(t.is_ip);
  CHECK(parse_target("2001:db8::1", t, err));
  CHECK_EQ(t.host, std::string("2001:db8::1"));
}

MIKTO_TEST(target_rejects_junk) {
  Target t;
  std::string err;
  CHECK(!parse_target("", t, err));
  CHECK(!parse_target("ftp://host", t, err));
  CHECK(!parse_target("host:99999", t, err));
  CHECK(!parse_target("bad host name!", t, err));
  CHECK(!parse_target("host:-1", t, err));
}

MIKTO_TEST(target_list_from_file) {
  const char* path = "/tmp/mikto_test_targets.txt";
  {
    std::ofstream f(path);
    f << "# comment line\n"
      << "https://one.example\n"
      << "\n"
      << "203.0.113.10\n"
      << "two.example:8080\n";
  }
  std::vector<Target> out;
  std::string err;
  CHECK(parse_target_list({path}, out, err));
  CHECK_EQ(out.size(), size_t(3));
  CHECK_EQ(out[0].host, std::string("one.example"));
  CHECK_EQ(out[1].host, std::string("203.0.113.10"));
  CHECK_EQ(out[2].port, 8080);
  std::remove(path);
}

MIKTO_TEST(target_list_dedup) {
  std::vector<Target> out;
  std::string err;
  CHECK(parse_target_list({"https://dup.example", "dup.example"}, out, err));
  CHECK_EQ(out.size(), size_t(2));  // разные схемы: оба остаются
  CHECK(parse_target_list({"dup.example", "dup.example"}, out, err));
  CHECK_EQ(out.size(), size_t(1));  // дубликат схлопывается
}
