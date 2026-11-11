// тесты cve db
#include "test_fw.hpp"

#include "mikto/cve_db.hpp"

using namespace mikto;

MIKTO_TEST(nvd_parse_basic) {
  std::string body = R"({
    "resultsPerPage": 1,
    "vulnerabilities": [
      {
        "cve": {
          "id": "CVE-2023-44487",
          "published": "2023-10-10T14:15:09.327",
          "descriptions": [
            {"lang": "en", "value": "The HTTP/2 protocol allows a denial of service (server resource consumption)."},
            {"lang": "es", "value": "translated text ignored"}
          ],
          "metrics": {
            "cvssMetricV31": [
              {"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}
            ]
          }
        }
      }
    ]
  })";
  std::vector<CveEntry> out;
  parse_nvd_response(body, "nginx", "nginx", "1.25.3", out);
  CHECK_EQ(out.size(), size_t(1));
  CHECK_EQ(out[0].id, std::string("CVE-2023-44487"));
  CHECK(out[0].cvss == 7.5);
  CHECK_EQ(out[0].severity, std::string("HIGH"));
  CHECK(out[0].description.find("denial of service") != std::string::npos);
  CHECK(out[0].description.find("ignored") == std::string::npos);
  CHECK_EQ(out[0].match_kind, std::string(""));
  CHECK(!out[0].version_verified);
}

MIKTO_TEST(nvd_parse_garbage_safe) {
  std::vector<CveEntry> out;
  parse_nvd_response("not json at all", "nginx", "nginx", "1.0", out);
  CHECK(out.empty());
  parse_nvd_response("{}", "nginx", "nginx", "1.0", out);
  CHECK(out.empty());
  parse_nvd_response("", "nginx", "nginx", "1.0", out);
  CHECK(out.empty());
}

MIKTO_TEST(cpe_mapping) {
  auto a = cpe_for_product("nginx", "1.25.3");
  CHECK(a.has_value());
  CHECK_EQ(a->first, std::string("nginx"));
  CHECK_EQ(a->second, std::string("nginx"));

  auto b = cpe_for_product("OpenSSH", "9.6p1");
  CHECK(b.has_value());
  CHECK_EQ(b->first, std::string("openbsd"));
  CHECK_EQ(b->second, std::string("openssh"));

  auto c = cpe_for_product("MySQL", "8.0.36");
  CHECK(c.has_value());
  CHECK_EQ(c->first, std::string("oracle"));
  CHECK_EQ(c->second, std::string("mysql"));

  auto d = cpe_for_product("MySQL", "5.7.40");
  CHECK(d.has_value());
  CHECK_EQ(d->first, std::string("mysql"));

  auto e = cpe_for_product("totally-unknown-server", "1.0");
  CHECK(!e.has_value());
}

namespace {

// минимальный nvd-ответ с одним cpeMatch
std::string nvd_with_match(const std::string& id, const std::string& criteria,
                           const std::string& extra_fields = "") {
  std::string body =
      "{\"vulnerabilities\":[{\"cve\":{\"id\":\"" + id + "\","
      "\"configurations\":[{\"nodes\":[{\"cpeMatch\":[{\"vulnerable\":true,"
      "\"criteria\":\"" + criteria + "\"" + extra_fields +
      "}]}]}]}}]}";
  return body;
}

}  // namespace

MIKTO_TEST(nvd_match_exact_verified) {
  auto body = nvd_with_match(
      "CVE-2024-0001",
      "cpe:2.3:a:nginx:nginx:1.25.3:*:*:*:*:*:*:*");
  std::vector<CveEntry> out;
  parse_nvd_response(body, "nginx", "nginx", "1.25.3", out);
  CHECK_EQ(out.size(), size_t(1));
  CHECK_EQ(out[0].match_kind, std::string("exact"));
  CHECK(out[0].version_verified);
  CHECK(!out[0].match_rule.empty());
  CHECK(out[0].match_rule.find("1.25.3") != std::string::npos);
}

MIKTO_TEST(nvd_match_exact_version_differs) {
  auto body = nvd_with_match(
      "CVE-2024-0002",
      "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*");
  std::vector<CveEntry> out;
  parse_nvd_response(body, "nginx", "nginx", "1.25.3", out);
  CHECK_EQ(out.size(), size_t(1));
  CHECK_EQ(out[0].match_kind, std::string("exact"));
  CHECK(!out[0].version_verified);
}

MIKTO_TEST(nvd_match_range_inside) {
  auto body = nvd_with_match(
      "CVE-2024-0003",
      "cpe:2.3:a:apache:httpd:2.4.0:*:*:*:*:*:*:*",
      R"(,"versionStartIncluding":"2.4.0","versionEndExcluding":"2.4.50")");
  std::vector<CveEntry> out;
  parse_nvd_response(body, "apache", "httpd", "2.4.41", out);
  CHECK_EQ(out.size(), size_t(1));
  CHECK_EQ(out[0].match_kind, std::string("range"));
  CHECK(out[0].version_verified);
  CHECK(out[0].match_rule.find("2.4.50") != std::string::npos);
}

MIKTO_TEST(nvd_match_range_outside) {
  auto body = nvd_with_match(
      "CVE-2024-0004",
      "cpe:2.3:a:apache:httpd:2.4.0:*:*:*:*:*:*:*",
      R"(,"versionStartIncluding":"2.4.0","versionEndExcluding":"2.4.50")");
  std::vector<CveEntry> out;
  parse_nvd_response(body, "apache", "httpd", "2.4.62", out);
  CHECK_EQ(out.size(), size_t(1));
  CHECK_EQ(out[0].match_kind, std::string("range"));
  CHECK(!out[0].version_verified);
}

MIKTO_TEST(nvd_match_vendor_wide_wildcard) {
  auto body = nvd_with_match(
      "CVE-2024-0005",
      "cpe:2.3:a:jquery:jquery:*:*:*:*:*:*:*:*");
  std::vector<CveEntry> out;
  parse_nvd_response(body, "jquery", "jquery", "3.7.1", out);
  CHECK_EQ(out.size(), size_t(1));
  CHECK_EQ(out[0].match_kind, std::string("any"));
  CHECK(!out[0].version_verified);  // vendor-wide не verified
  CHECK(out[0].match_rule.find("wildcard") != std::string::npos);
}

MIKTO_TEST(nvd_match_cpe22_legacy_format) {
  auto body = nvd_with_match("CVE-2024-0006", "cpe:/a:nginx:nginx:1.25.3");
  std::vector<CveEntry> out;
  parse_nvd_response(body, "nginx", "nginx", "1.25.3", out);
  CHECK_EQ(out.size(), size_t(1));
  CHECK_EQ(out[0].match_kind, std::string("exact"));
  CHECK(out[0].version_verified);
}

MIKTO_TEST(nvd_match_other_product_ignored) {
  auto body = nvd_with_match(
      "CVE-2024-0007",
      "cpe:2.3:a:apache:tomcat:9.0.0:*:*:*:*:*:*:*");
  std::vector<CveEntry> out;
  parse_nvd_response(body, "nginx", "nginx", "1.25.3", out);
  CHECK_EQ(out.size(), size_t(1));
  CHECK_EQ(out[0].match_kind, std::string(""));
  CHECK(!out[0].version_verified);
}

MIKTO_TEST(nvd_match_cpe_escaped_chars) {
  // в json joomla\\! парсится в cpe joomla\!
  auto body = nvd_with_match(
      "CVE-2024-0008",
      "cpe:2.3:a:joomla:joomla\\\\!:4.0.0:*:*:*:*:*:*:*");
  std::vector<CveEntry> out;
  parse_nvd_response(body, "joomla", "joomla!", "4.0.0", out);
  CHECK_EQ(out.size(), size_t(1));
  CHECK_EQ(out[0].match_kind, std::string("exact"));
  CHECK(out[0].version_verified);
}
