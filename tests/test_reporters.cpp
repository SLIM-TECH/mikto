// тесты репортеров: csv, sarif, html
#include "test_fw.hpp"

#include <fstream>
#include <nlohmann/json.hpp>

#include "mikto/config.hpp"
#include "mikto/intel_graph.hpp"
#include "mikto/reporter.hpp"
#include "mikto/scan_result.hpp"
#include "mikto/util.hpp"

using namespace mikto;

namespace {

using json = nlohmann::json;

void sample_result(ScanResult& r) {
  r.started_at = "2026-01-01T00:00:00Z";
  r.finished_at = "2026-01-01T00:01:00Z";

  HostResult& h = r.ensure_host("example.com", false);
  h.ips.push_back("203.0.113.10");
  PortInfo p;
  p.port = 443;
  p.open = true;
  p.service = "https";
  h.ports.push_back(p);

  WebResult& w = r.ensure_web("https://example.com/");
  w.fetched = true;
  w.status = 200;
  w.server = "nginx";
  w.headers = {{"Content-Type", "text/html; charset=utf-8"},
               {"X-Frame-Options", "DENY"}};

  Finding high;
  high.severity = Severity::High;
  high.module = "headers";
  high.host = "example.com";
  high.port = 443;
  high.service = "https";
  high.location = "https://example.com/";
  high.title = "Strict-Transport-Security missing";
  high.detail = "No HSTS header on the main page";
  high.recommendation = "Add the header";
  high.evidence = "no header found";
  high.references.push_back("https://nvd.nist.gov/vuln/detail/CVE-2024-1234");
  r.add_finding(high);

  Finding med;
  med.severity = Severity::Medium;
  med.module = "secrets";
  med.host = "example.com";
  med.location = "https://example.com/app.js";
  med.title = "Possible API key pattern";
  med.detail = "pattern matched, redacted";
  r.add_finding(med);
}

bool read_file(const std::string& path, std::string& out) {
  std::ifstream f(path);
  if (!f) return false;
  out.assign((std::istreambuf_iterator<char>(f)),
             std::istreambuf_iterator<char>());
  return true;
}

}  // namespace

MIKTO_TEST(csv_escape_rfc4180) {
  CHECK_EQ(csv_escape("plain"), std::string("plain"));
  CHECK_EQ(csv_escape("a,b"), std::string("\"a,b\""));
  CHECK_EQ(csv_escape("say \"hi\""), std::string("\"say \"\"hi\"\"\""));
  CHECK_EQ(csv_escape("line\nbreak"), std::string("\"line\nbreak\""));
  CHECK_EQ(csv_escape(""), std::string(""));
}

MIKTO_TEST(csv_reporter_writes_escaped_rows) {
  ScanResult r;
  sample_result(r);
  Finding weird;
  weird.severity = Severity::Low;
  weird.module = "exposed";
  weird.host = "example.com";
  weird.title = "Comma, \"quote\" and newline\nhere";
  r.add_finding(weird);

  Config cfg;
  std::string err;
  auto rep = make_csv_reporter("/tmp/mikto_test.csv");
  CHECK(rep->write(r, cfg, err));
  std::string out;
  CHECK(read_file("/tmp/mikto_test.csv", out));
  CHECK(out.find("severity,module,host,port,service,location,title,detail,"
                 "recommendation,evidence,references") == 0);
  CHECK(out.find("\"Comma, \"\"quote\"\" and newline\nhere\"") !=
        std::string::npos);
  CHECK(out.find("headers") != std::string::npos);
  CHECK(out.find("203.0.113.10") == std::string::npos);  // ip не строка
  // каждая находка ровно один раз, перенос внутри кавычек это часть поля
  size_t rows = 0;
  for (const char* mod : {"headers", "secrets", "exposed"}) {
    size_t pos = out.find(std::string(",") + mod + ",");
    CHECK(pos != std::string::npos);
    if (pos != std::string::npos) ++rows;
  }
  CHECK_EQ(rows, size_t(3));
}

MIKTO_TEST(sarif_reporter_valid_shape) {
  ScanResult r;
  sample_result(r);
  Config cfg;
  std::string err;
  auto rep = make_sarif_reporter("/tmp/mikto_test.sarif");
  CHECK(rep->write(r, cfg, err));
  std::string out;
  CHECK(read_file("/tmp/mikto_test.sarif", out));
  json j;
  try {
    j = json::parse(out);
  } catch (...) {
    CHECK(false);
    return;
  }
  CHECK_EQ(j["version"].get<std::string>(), std::string("2.1.0"));
  CHECK(j.contains("$schema"));
  auto& run = j["runs"][0];
  auto& driver = run["tool"]["driver"];
  CHECK_EQ(driver["name"].get<std::string>(), std::string("mikto"));
  CHECK(driver.contains("rules"));
  CHECK(run["results"].size() == 2);
  // severity mapping
  bool saw_error = false, saw_warning = false;
  for (const auto& res : run["results"]) {
    if (res["level"] == "error") saw_error = true;
    if (res["level"] == "warning") saw_warning = true;
    CHECK(res.contains("ruleId"));
    CHECK(res.contains("message"));
    CHECK(res.contains("locations"));
  }
  CHECK(saw_error);    // high -> error
  CHECK(saw_warning);  // medium -> warning
  CHECK(driver["rules"].size() == 2);
}

MIKTO_TEST(html_reporter_selfcontained_with_intel_layer) {
  ScanResult r;
  sample_result(r);

  // провайдер виден в отчёте
  ProviderStat ps;
  ps.name = "NVD";
  ps.allowed = 3;
  ps.successes = 3;
  r.provider_stats["nvd.nist.gov"] = ps;

  r.intel.build(r);
  CHECK(!r.intel.nodes().empty());

  Config cfg;
  std::string err;
  auto rep = make_html_reporter("/tmp/mikto_test.html");
  CHECK(rep->write(r, cfg, err));
  std::string out;
  CHECK(read_file("/tmp/mikto_test.html", out));

  // самодостаточность: без внешних ресурсов
  CHECK(out.find("<!doctype html>") == 0);
  CHECK(out.find("<style>") != std::string::npos);
  CHECK(out.find("<script>") != std::string::npos);
  CHECK(out.find("https://cdn") == std::string::npos);
  CHECK(out.find("fonts.googleapis") == std::string::npos);
  CHECK(out.find("<link rel=\"stylesheet\"") == std::string::npos);

  for (const char* id :
       {"overview", "findings", "hosts", "web", "correlations", "traffic",
        "scaninfo"}) {
    CHECK(out.find(std::string("id=\"") + id + "\"") != std::string::npos);
  }
  CHECK(out.find("href=\"#correlations\"") != std::string::npos);

  CHECK(out.find("id=\"intel-nodes\"") != std::string::npos);
  CHECK(out.find("id=\"intel-edges\"") != std::string::npos);
  CHECK(out.find("id=\"intel-map\"") != std::string::npos);
  CHECK(out.find("stchip st-confirmed") != std::string::npos);
  CHECK(out.find("confbar") != std::string::npos);
  CHECK(out.find("example.com") != std::string::npos);
  CHECK(out.find("has_service") != std::string::npos);
  CHECK(out.find("External providers") != std::string::npos);
  CHECK(out.find("NVD") != std::string::npos);
  CHECK(out.find("Security headers matrix") != std::string::npos);
  CHECK(out.find("X-Frame-Options") != std::string::npos);
  CHECK(out.find("hok") != std::string::npos);
  CHECK(out.find("hmiss") != std::string::npos);
  CHECK(out.find("Findings by module") != std::string::npos);
  CHECK(out.find("class=\"modbar\" data-mod=\"headers\"") != std::string::npos);
  CHECK(out.find("riskbar") != std::string::npos);
}

MIKTO_TEST(html_reporter_escapes_hostile_values_everywhere) {
  ScanResult r;
  sample_result(r);
  // злые значения экранируются везде
  Finding evil;
  evil.severity = Severity::Critical;
  evil.module = "exposed";
  evil.host = "example.com";
  evil.title = "<script>alert(1)</script>";
  evil.detail = "<img src=x onerror=alert(2)>";
  evil.evidence = "\"onmouseover=\"alert(3)";
  evil.references.push_back("<a href=\"http://evil\">x</a>");
  r.add_finding(evil);

  HostResult& h = r.ensure_host("example.com", false);
  h.subdomains.push_back("<script>sub</script>");
  h.emails.push_back("<b>evil@x</b>");
  r.intel.build(r);

  Config cfg;
  std::string err;
  auto rep = make_html_reporter("/tmp/mikto_test_xss.html");
  CHECK(rep->write(r, cfg, err));
  std::string out;
  CHECK(read_file("/tmp/mikto_test_xss.html", out));

  CHECK(out.find("<script>alert(1)</script>") == std::string::npos);
  CHECK(out.find("<img src=x onerror") == std::string::npos);
  CHECK(out.find("<script>sub</script>") == std::string::npos);
  CHECK(out.find("<b>evil@x</b>") == std::string::npos);
  CHECK(out.find("<a href=\"http://evil\">x</a>") == std::string::npos);
  CHECK(out.find("&lt;script&gt;alert(1)&lt;/script&gt;") != std::string::npos);
}

MIKTO_TEST(html_reporter_states_caps_and_accounting) {
  ScanResult r;
  sample_result(r);
  r.intel.build(r);
  ProviderStat ps;
  ps.name = "NVD";
  ps.allowed = 2;
  ps.successes = 1;
  ps.failures = 1;
  r.provider_stats["nvd.nist.gov"] = ps;

  Config cfg;
  std::string err;
  auto rep = make_html_reporter("/tmp/mikto_test_acc.html");
  CHECK(rep->write(r, cfg, err));
  std::string out;
  CHECK(read_file("/tmp/mikto_test_acc.html", out));
  CHECK(out.find("entities&nbsp;·&nbsp;<b class=\"num\">") != std::string::npos);
  CHECK(out.find("relations&nbsp;·&nbsp;<b class=\"num\">") != std::string::npos);
  CHECK(out.find("Breaker trips") != std::string::npos);
  CHECK(out.find("End state") != std::string::npos);
}

MIKTO_TEST(html_reporter_infrastructure_section) {
  // два хоста: общий /24, соседи по ip, ns/mx
  ScanResult r;
  HostResult& a = r.ensure_host("acme.com", false);
  a.ips = {"203.0.113.10"};
  a.geo.ok = true;
  a.geo.country = "US";
  a.geo.asn = "AS64512";
  a.geo.org = "Acme Hosting, Inc.";
  DnsRecord ns;
  ns.type = "NS";
  ns.name = "acme.com";
  ns.value = "ns1.shared-dns.net.";
  ns.ttl = 3600;
  a.dns_records.push_back(ns);
  DnsRecord mx;
  mx.type = "MX";
  mx.name = "acme.com";
  mx.value = "10 mail.acme.com.";
  mx.ttl = 3600;
  a.dns_records.push_back(mx);

  HostResult& b = r.ensure_host("beta.com", false);
  b.ips = {"203.0.113.42", "203.0.114.7"};
  b.neighbors = {"shop-example.net", "blog-somebody.org"};

  r.intel.build(r);

  Config cfg;
  std::string err;
  auto rep = make_html_reporter("/tmp/mikto_test_infra.html");
  CHECK(rep->write(r, cfg, err));
  std::string out;
  CHECK(read_file("/tmp/mikto_test_infra.html", out));

  CHECK(out.find("id=\"infra\"") != std::string::npos);
  CHECK(out.find("href=\"#infra\"") != std::string::npos);
  CHECK(out.find("203.0.113.10") != std::string::npos);
  CHECK(out.find("203.0.113.42") != std::string::npos);
  CHECK(out.find("203.0.114.7") != std::string::npos);
  CHECK(out.find("AS64512") != std::string::npos);
  CHECK(out.find("Acme Hosting") != std::string::npos);
  CHECK(out.find("shop-example.net") != std::string::npos);
  CHECK(out.find("blog-somebody.org") != std::string::npos);
  CHECK(out.find("tag nb") != std::string::npos);
  CHECK(out.find("203.0.113.0/24") != std::string::npos);
  CHECK(out.find("ns1.shared-dns.net") != std::string::npos);
  CHECK(out.find("mail.acme.com") != std::string::npos);
  CHECK(out.find("Shared DNS infrastructure") != std::string::npos);
}

MIKTO_TEST(html_reporter_infrastructure_empty_state) {
  // пустой скан: empty state, отчёт структурно цел
  ScanResult r;
  Config cfg;
  std::string err;
  auto rep = make_html_reporter("/tmp/mikto_test_infra_empty.html");
  CHECK(rep->write(r, cfg, err));
  std::string out;
  CHECK(read_file("/tmp/mikto_test_infra_empty.html", out));
  CHECK(out.find("id=\"infra\"") != std::string::npos);
  CHECK(out.find("No infrastructure data was collected") != std::string::npos);
}

MIKTO_TEST(html_reporter_intel_map_cap_on_large_graphs) {
  // граф на 200+: кап карты 120, таблица полная
  ScanResult r;
  sample_result(r);
  HostResult& h = r.ensure_host("example.com", false);
  for (int i = 0; i < 200; ++i) {
    PortInfo p;
    p.port = static_cast<uint16_t>(10000 + i);
    p.open = true;
    p.service = "http";
    p.probe = "http";
    p.confidence = 3;
    h.ports.push_back(p);
  }
  r.intel.build(r);
  CHECK(r.intel.nodes().size() >= 200);

  Config cfg;
  std::string err;
  auto rep = make_html_reporter("/tmp/mikto_test_cap.html");
  CHECK(rep->write(r, cfg, err));
  std::string out;
  CHECK(read_file("/tmp/mikto_test_cap.html", out));

  size_t mapped = 0, node_rows = 0;
  // считаем только строки сущностей, рёбра начинаются с data-edge
  for (size_t pos = 0; (pos = out.find("<tr data-node=", pos)) != std::string::npos;
       pos += 1) {
    ++node_rows;
    size_t tag_end = out.find('>', pos);
    if (tag_end == std::string::npos) break;
    if (out.find("data-map=\"1\"", pos) < tag_end) ++mapped;
  }
  CHECK_EQ(mapped, size_t(120));                      // кап карты
  CHECK(node_rows >= 200);                            // таблица полная
  CHECK(out.find("of " + std::to_string(r.intel.nodes().size()) +
                 " entities (hubs first)") != std::string::npos);
}
