// тесты diff
#include "test_fw.hpp"

#include <nlohmann/json.hpp>

#include "mikto/scan_diff.hpp"

using namespace mikto;

namespace {

using json = nlohmann::json;

json report(const std::string& started, json extra_hosts = json::array(),
            json extra_findings = json::array()) {
  return {{"scan", {{"started_at", started}}},
          {"hosts", extra_hosts},
          {"findings", extra_findings}};
}

json host(const std::string& name, json patch = json::object()) {
  json h = {{"host", name}};
  for (auto it = patch.begin(); it != patch.end(); ++it) h[it.key()] = it.value();
  return h;
}

}  // namespace

MIKTO_TEST(diff_identical_reports) {
  json a = report("2026-01-01T00:00:00Z",
                  json::array({host("example.com", json{{"ips", {"1.2.3.4"}}})}));
  json b = report("2026-01-02T00:00:00Z",
                  json::array({host("example.com", json{{"ips", {"1.2.3.4"}}})}));
  ScanDiffResult d = diff_reports(a, b);
  CHECK(d.identical());
  CHECK_EQ(d.changes.size(), size_t(0));
}

MIKTO_TEST(diff_new_and_removed_subdomains) {
  json a = report("2026-01-01",
                  json::array({host("example.com", json{{"subdomains", {"a.example.com"}}})}));
  json b = report("2026-01-02",
                  json::array({host("example.com", json{{"subdomains", {"a.example.com", "b.example.com"}}})}));
  ScanDiffResult d = diff_reports(a, b);
  bool added = false;
  for (const auto& c : d.changes)
    if (c.kind == "subdomain" && c.action == "added" &&
        c.detail == "b.example.com")
      added = true;
  CHECK(added);
  for (const auto& c : d.changes)
    if (c.kind == "subdomain" && c.action == "added") {
      CHECK(c.first_seen.empty());
      CHECK_EQ(c.last_seen, std::string("2026-01-02"));
    }
}

MIKTO_TEST(diff_opened_and_closed_ports) {
  json a = report("2026-01-01", json::array({host("example.com", json{
      {"ports", {{{"port", 443}, {"service", "https"}, {"product", "nginx"}, {"version", "1.25.0"}}}}})}));
  json b = report("2026-01-02", json::array({host("example.com", json{
      {"ports", {{{"port", 443}, {"service", "https"}, {"product", "nginx"}, {"version", "1.25.0"}},
                 {{"port", 8080}, {"service", "http-proxy"}}}}})}));
  ScanDiffResult d = diff_reports(a, b);
  bool opened = false;
  for (const auto& c : d.changes)
    if (c.kind == "port" && c.action == "added") {
      CHECK_EQ(c.severity, std::string("medium"));
      CHECK(c.detail.find("8080") != std::string::npos);
      opened = true;
    }
  CHECK(opened);

  json c = report("2026-01-03", json::array({host("example.com", json{{"ports", json::array()}})}));
  ScanDiffResult d2 = diff_reports(b, c);
  bool closed = false;
  for (const auto& ch : d2.changes)
    if (ch.kind == "port" && ch.action == "removed" &&
        ch.detail.find("443") != std::string::npos)
      closed = true;
  CHECK(closed);
}

MIKTO_TEST(diff_tech_version_change) {
  json a = report("2026-01-01", json::array({host("example.com", json{
      {"tech", {{{"name", "nginx"}, {"version", "1.25.0"}}}}})}));
  json b = report("2026-01-02", json::array({host("example.com", json{
      {"tech", {{{"name", "nginx"}, {"version", "1.25.3"}}}}})}));
  ScanDiffResult d = diff_reports(a, b);
  bool changed = false;
  for (const auto& c : d.changes)
    if (c.kind == "tech" && c.action == "changed" &&
        c.detail.find("1.25.0 -> 1.25.3") != std::string::npos) {
      CHECK_EQ(c.severity, std::string("medium"));
      changed = true;
    }
  CHECK(changed);
}

MIKTO_TEST(diff_findings_added_and_resolved) {
  json f1 = json::array({{{"severity", "high"}, {"module", "headers"},
                          {"host", "example.com"}, {"title", "HSTS missing"}}});
  json f2 = json::array({{{"severity", "critical"}, {"module", "secrets"},
                          {"host", "example.com"},
                          {"title", "API key in page"}}});
  ScanDiffResult d = diff_reports(report("d1", json::array(), f1),
                                  report("d2", json::array(), f2));
  bool added = false, resolved = false;
  for (const auto& c : d.changes) {
    if (c.action == "added" && c.severity == "critical" &&
        c.detail.find("API key") != std::string::npos)
      added = true;
    if (c.action == "removed" && c.detail.find("HSTS") != std::string::npos)
      resolved = true;
  }
  CHECK(added);
  CHECK(resolved);
}

MIKTO_TEST(diff_dns_changes) {
  json a = report("2026-01-01", json::array({host("example.com", json{
      {"dns_records", {{{"type", "MX"}, {"name", "example.com"}, {"value", "10 mail.example.com."}}}}})}));
  json b = report("2026-01-02", json::array({host("example.com", json{
      {"dns_records", {{{"type", "MX"}, {"name", "example.com"}, {"value", "20 backup.example.net."}}}}})}));
  ScanDiffResult d = diff_reports(a, b);
  bool changed = false;
  for (const auto& c : d.changes)
    if (c.kind == "dns" && c.action == "changed") changed = true;
  CHECK(changed);
}

MIKTO_TEST(diff_certificate_change) {
  json a = report("2026-01-01", json::array({host("example.com", json{
      {"tls", {{"subject", "CN=example.com"}, {"issuer", "CN=Let's Encrypt"},
                {"not_after", "2026-03-01"}}}})}));
  json b = report("2026-01-02", json::array({host("example.com", json{
      {"tls", {{"subject", "CN=example.com"}, {"issuer", "CN=Let's Encrypt"},
                {"not_after", "2026-06-01"}}}})}));
  ScanDiffResult d = diff_reports(a, b);
  bool changed = false;
  for (const auto& c : d.changes)
    if (c.kind == "certificate" && c.action == "changed" &&
        c.detail.find("2026-03-01 -> 2026-06-01") != std::string::npos)
      changed = true;
  CHECK(changed);
}

MIKTO_TEST(diff_severity_sorting_critical_first) {
  json f1 = json::array({{{"severity", "info"}, {"module", "tech"},
                          {"host", "example.com"}, {"title", "minor"}}});
  json f2 = json::array({{{"severity", "critical"}, {"module", "secrets"},
                          {"host", "example.com"}, {"title", "leak"}}});
  ScanDiffResult d = diff_reports(report("a", json::array(), f1),
                                  report("b", json::array(), f2));
  CHECK(!d.changes.empty());
  CHECK_EQ(d.changes[0].severity, std::string("critical"));
}

MIKTO_TEST(diff_json_and_console_output_shapes) {
  json a = report("2026-01-01");
  json b = report("2026-01-02", json::array({host("x.com")}));
  ScanDiffResult d = diff_reports(a, b);
  json j = diff_to_json(d);
  CHECK(j.contains("changes"));
  CHECK(j.contains("summary"));
  CHECK(j["identical"].is_boolean());
  std::string text = diff_console_text(d, false);
  CHECK(text.find("mikto diff") != std::string::npos);
  ScanDiffResult e = diff_reports(a, a);
  std::string t2 = diff_console_text(e, false);
  CHECK(t2.find("no differences") != std::string::npos);
}
