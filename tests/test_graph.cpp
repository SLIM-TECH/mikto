// тесты intel graph
#include "test_fw.hpp"

#include "mikto/intel_graph.hpp"
#include "mikto/scan_result.hpp"

using namespace mikto;

namespace {

// синтетический скан
void make_scan(ScanResult& r) {
  r.started_at = "2026-01-01T00:00:00Z";
  r.finished_at = "2026-01-01T00:01:00Z";

  Target t;
  t.original = "example.com";
  t.host = "example.com";
  r.targets.push_back(t);

  HostResult& h = r.ensure_host("example.com", false);
  h.ips.push_back("203.0.113.10");
  h.geo.ok = true;
  h.geo.asn = "AS64496";
  h.geo.org = "TestNet";
  DnsRecord mx;
  mx.type = "MX";
  mx.name = "example.com";
  mx.value = "10 mail.example.com.";
  h.dns_records.push_back(mx);
  DnsRecord ns;
  ns.type = "NS";
  ns.name = "example.com";
  ns.value = "ns1.example.com.";
  h.dns_records.push_back(ns);
  PortInfo p;
  p.port = 443;
  p.open = true;
  p.service = "https";
  p.product = "nginx";
  p.version = "1.25.3";
  p.confidence = 3;
  h.ports.push_back(p);
  TechHit tech;
  tech.name = "nginx";
  tech.version = "1.25.3";
  tech.source = "header:Server";
  h.tech.push_back(tech);
}

const GraphNode* find_node(const IntelGraph& g, const std::string& id) {
  for (const auto& n : g.nodes())
    if (n.id == id) return &n;
  return nullptr;
}

bool find_edge(const IntelGraph& g, const std::string& src,
               const std::string& dst, const std::string& relation) {
  for (const auto& e : g.edges())
    if (e.src == src && e.dst == dst && e.relation == relation) return true;
  return false;
}

}  // namespace

MIKTO_TEST(graph_entity_resolution_dedupes_by_type_and_value) {
  IntelGraph g;
  GraphNode& a = g.ensure(NodeType::Domain, "Example.com", "confirmed", 1.0,
                          "assets");
  GraphNode& b = g.ensure(NodeType::Domain, "example.com", "confirmed", 1.0,
                          "subdom");
  CHECK(&a == &b);  // дедуп по нормализованному значению
  CHECK_EQ(g.nodes().size(), size_t(1));
  bool has_assets = false, has_subdom = false;
  for (const auto& s : b.sources) {
    if (s == "assets") has_assets = true;
    if (s == "subdom") has_subdom = true;
  }
  CHECK(has_assets);
  CHECK(has_subdom);
}

MIKTO_TEST(graph_ensure_upgrades_status_only_stronger) {
  IntelGraph g;
  GraphNode& a = g.ensure(NodeType::Technology, "nginx", "probable", 0.75,
                          "tech");
  g.ensure(NodeType::Technology, "nginx", "possible", 0.4, "ports");
  CHECK_EQ(a.status, std::string("probable"));
  g.ensure(NodeType::Technology, "nginx", "confirmed", 1.0, "manual");
  CHECK_EQ(a.status, std::string("confirmed"));
}

MIKTO_TEST(graph_links_dedupe_and_upgrade) {
  IntelGraph g;
  g.link("domain:a", "ip:1", "resolves_to", "possible", 0.5, "hint", "n1");
  CHECK_EQ(g.edges().size(), size_t(1));
  g.link("domain:a", "ip:1", "resolves_to", "confirmed", 1.0, "dns answer",
         "assets");
  CHECK_EQ(g.edges().size(), size_t(1));
  CHECK_EQ(g.edges()[0].status, std::string("confirmed"));
  // evidence merged
  CHECK(g.edges()[0].evidence.find("hint") != std::string::npos &&
        g.edges()[0].evidence.find("dns answer") != std::string::npos);
}

MIKTO_TEST(graph_build_infra_relations) {
  ScanResult r;
  make_scan(r);
  IntelGraph g;
  g.build(r);
  CHECK(find_node(g, "domain:example.com"));
  CHECK(find_node(g, "ip:203.0.113.10"));
  CHECK(find_node(g, "asn:AS64496"));
  CHECK(find_node(g, "mail_exchanger:mail.example.com"));
  CHECK(find_node(g, "nameserver:ns1.example.com"));
  CHECK(find_node(g, "service:example.com:443"));
  CHECK(find_node(g, "technology:nginx 1.25.3"));

  CHECK(find_edge(g, "domain:example.com", "ip:203.0.113.10", "resolves_to"));
  CHECK(find_edge(g, "ip:203.0.113.10", "asn:AS64496", "belongs_to_asn"));
  CHECK(find_edge(g, "domain:example.com", "mail_exchanger:mail.example.com",
                  "mail_via"));
  CHECK(find_edge(g, "domain:example.com", "nameserver:ns1.example.com",
                  "delegated_to"));
  CHECK(find_edge(g, "domain:example.com", "service:example.com:443",
                  "has_service"));
  CHECK(find_edge(g, "domain:example.com", "technology:nginx 1.25.3", "runs"));
}

MIKTO_TEST(graph_confidence_is_honest) {
  ScanResult r;
  make_scan(r);
  IntelGraph g;
  g.build(r);
  const GraphNode* ip = find_node(g, "ip:203.0.113.10");
  CHECK(ip && ip->status == "confirmed");
  const GraphNode* tech = find_node(g, "technology:nginx 1.25.3");
  CHECK(tech && tech->status == "probable");
  CHECK(tech->confidence < 1.0);
  const GraphNode* asn = find_node(g, "asn:AS64496");
  CHECK(asn && asn->status == "probable");
}

MIKTO_TEST(graph_neighbors_stay_possible_and_unmerged) {
  ScanResult r;
  make_scan(r);
  HostResult& h = r.ensure_host("example.com", false);
  h.neighbors.push_back("Other-Site.example.org");
  IntelGraph g;
  g.build(r);
  const GraphNode* nb = find_node(g, "domain:other-site.example.org");
  CHECK(nb);
  CHECK(nb->status == "possible");  // ко-хостинг не подтверждение
  CHECK(find_edge(g, "domain:other-site.example.org", "ip:203.0.113.10",
                  "resolves_to"));
}

MIKTO_TEST(graph_cve_findings_are_unverified_matches) {
  ScanResult r;
  make_scan(r);
  Finding f;
  f.severity = Severity::High;
  f.module = "cve";
  f.host = "example.com";
  f.title = "Possible CVE match for nginx 1.25.3";
  f.detail = "matched by version range";
  f.references.push_back("https://nvd.nist.gov/vuln/detail/CVE-2024-1234");
  r.add_finding(f);
  IntelGraph g;
  g.build(r);
  CHECK(find_node(g, "cve:CVE-2024-1234"));
  CHECK(find_edge(g, "domain:example.com", "cve:CVE-2024-1234",
                  "potentially_affected"));
  const GraphNode* cve = find_node(g, "cve:CVE-2024-1234");
  CHECK(cve && cve->status == "possible");  // не confirmed
}

MIKTO_TEST(graph_counts_and_node_type_names) {
  ScanResult r;
  make_scan(r);
  IntelGraph g;
  g.build(r);
  auto nc = g.node_counts();
  CHECK(nc["domain"] >= 1);
  CHECK(nc["ip"] >= 1);
  CHECK_EQ(std::string(node_type_key(NodeType::MailExchanger)),
           std::string("mail_exchanger"));
  CHECK_EQ(std::string(node_type_name(NodeType::Cve)), std::string("CVE"));
}
