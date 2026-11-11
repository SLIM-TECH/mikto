// тесты провайдеров
#include "test_fw.hpp"

#include "mikto/providers.hpp"

using namespace mikto;

MIKTO_TEST(provider_tracker_closes_on_successes_only) {
  ProviderTracker t(3, 0);  // трип после 3 фейлов подряд, без капа
  CHECK(t.allow("p.test"));
  t.record_success("p.test");
  CHECK(t.allow("p.test"));
  t.record_failure("p.test");
  t.record_failure("p.test");
  CHECK(t.allow("p.test"));
  t.record_failure("p.test");
  auto snap = t.snapshot();
  CHECK(snap.at("p.test").circuit_open);
  CHECK_EQ(snap.at("p.test").circuit_trips, 1);
  CHECK(!t.allow("p.test"));
}

MIKTO_TEST(provider_tracker_success_reopens_circuit) {
  ProviderTracker t(2, 0);
  t.record_failure("p.test");
  t.record_failure("p.test");
  // 10-й заблокированный вызов даёт half-open пробу
  CHECK(!t.allow("p.test"));
  for (int i = 0; i < 8; ++i) CHECK(!t.allow("p.test"));
  CHECK(t.allow("p.test"));
  t.record_success("p.test");
  CHECK(t.allow("p.test"));
  auto snap = t.snapshot();
  CHECK(!snap.at("p.test").circuit_open);
}

MIKTO_TEST(provider_tracker_request_cap) {
  ProviderTracker t(5, 3);  // кап 3 запроса
  CHECK(t.allow("q.test"));
  CHECK(t.allow("q.test"));
  CHECK(t.allow("q.test"));
  CHECK(!t.allow("q.test"));  // кап достигнут
  auto snap = t.snapshot();
  CHECK(snap.at("q.test").capped);
  CHECK_EQ(snap.at("q.test").blocked, 1);
  CHECK_EQ(snap.at("q.test").allowed, 3);
}

MIKTO_TEST(provider_tracker_counts_blocks_honestly) {
  ProviderTracker t(1, 0);
  t.record_failure("r.test");
  int blocked_seen = t.blocked_count("r.test");
  CHECK(!t.allow("r.test"));
  CHECK_EQ(t.blocked_count("r.test"), blocked_seen + 1);
}

MIKTO_TEST(provider_url_host_extracts_hosts) {
  CHECK_EQ(provider_url_host("https://crt.sh/?q=x"), std::string("crt.sh"));
  CHECK_EQ(provider_url_host("http://ip-api.com/json/1.2.3.4"),
           std::string("ip-api.com"));
  CHECK_EQ(provider_url_host("https://API.Example.com:8443/path"),
           std::string("api.example.com"));
  CHECK_EQ(provider_url_host("https://user:pass@secret.example/x"),
           std::string("secret.example"));
  CHECK(provider_url_host("not-a-url").empty());
  CHECK(provider_url_host("ftp://weird").empty());
}

MIKTO_TEST(provider_classification_disambiguates_shared_hosts) {
  // raw.githubusercontent.com отдает и cvelistV5, и OpenPhish
  std::string host;
  const ProviderInfo* p1 = classify_provider(
      "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/x.json",
      {"target.example"}, host);
  CHECK(p1 && std::string(p1->name) == "CVE Project cvelistV5");
  const ProviderInfo* p2 = classify_provider(
      "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/"
      "main/feed.txt",
      {"target.example"}, host);
  CHECK(p2 && std::string(p2->name) == "OpenPhish");
  // цель скана не провайдер
  const ProviderInfo* p3 = classify_provider("https://target.example/x",
                                             {"target.example"}, host);
  CHECK(p3 == nullptr);
  // неизвестный хост -> host-only
  const ProviderInfo* p4 =
      classify_provider("https://crt.sh/?q=x", {"target.example"}, host);
  CHECK(p4 && std::string(p4->name) == "crt.sh");
}

MIKTO_TEST(provider_catalog_is_honest) {
  const auto& cat = provider_catalog();
  CHECK(cat.size() >= 12);
  bool crt = false, nvd = false, shodan_idb = false;
  for (const auto& p : cat) {
    CHECK(p.name && p.host && p.category && p.endpoint);
    if (std::string(p.name) == "crt.sh") crt = true;
    if (std::string(p.name) == "NVD") nvd = true;
    if (std::string(p.name) == "Shodan InternetDB") shodan_idb = true;
  }
  CHECK(crt);
  CHECK(nvd);
  CHECK(shodan_idb);
}

MIKTO_TEST(providers_help_text_lists_env_vars) {
  std::string text = providers_help_text();
  CHECK(text.find("SHODAN_API_KEY") != std::string::npos);
  CHECK(text.find("NVD_API_KEY") != std::string::npos);
  CHECK(text.find("CENSYS_API_ID") != std::string::npos);
  CHECK(text.find("crt.sh") != std::string::npos);
}
