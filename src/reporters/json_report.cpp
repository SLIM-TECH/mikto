// json репортер
#include <cmath>
#include <fstream>

#include <nlohmann/json.hpp>

#include "mikto/config.hpp"
#include "mikto/intel_graph.hpp"
#include "mikto/providers.hpp"
#include "mikto/reporter.hpp"
#include "mikto/scan_result.hpp"
#include "mikto/util.hpp"
#include "mikto/version.hpp"

namespace mikto {

namespace {

using nlohmann::json;

json headers_to_json(const std::vector<std::pair<std::string, std::string>>& hs) {
  json out = json::object();
  json setcookies = json::array();
  for (const auto& kv : hs) {
    if (iequals(kv.first, "Set-Cookie")) {
      setcookies.push_back(kv.second);
      continue;
    }
    if (!out.contains(kv.first)) out[kv.first] = kv.second;
  }
  if (!setcookies.empty()) out["Set-Cookie"] = setcookies;
  return out;
}

class JsonReporter : public IReporter {
 public:
  explicit JsonReporter(std::string path) : path_(std::move(path)) {}

  bool write(const ScanResult& r, const Config& cfg, std::string& err) override {
    json j;
    j["tool"] = {{"name", "mikto"},
                 {"version", MIKTO_VERSION},
                 {"homepage", MIKTO_HOMEPAGE}};

    json timings = json::object();
    for (const auto& kv : r.module_timings)
      timings[kv.first] = std::round(kv.second * 100.0) / 100.0;

    j["scan"] = {{"started_at", r.started_at},
                 {"finished_at", r.finished_at},
                 {"duration_seconds", std::round(r.duration_s * 100.0) / 100.0},
                 {"safe_mode", r.safe_mode},
                 {"deep", r.deep},
                 {"modules_run", r.modules_run},
                 {"module_timings", timings}};

    json targets = json::array();
    for (const auto& t : cfg.targets) {
      json tj = json::object();
      tj["original"] = t.original;
      tj["scheme"] = t.scheme;
      tj["host"] = t.host;
      tj["port"] = t.port;
      targets.push_back(std::move(tj));
    }
    j["targets"] = targets;

    json hosts = json::array();
    for (const auto& h : r.hosts) {
      json hj = {{"host", h.host}, {"is_ip", h.is_ip}, {"ips", h.ips}};
      json ports = json::array();
      for (const auto& p : h.ports) {
        if (!p.open) continue;
        json pj = {{"port", p.port},
                   {"service", p.service},
                   {"product", p.product},
                   {"version", p.version},
                   {"banner", p.banner}};
        pj["confidence"] = p.confidence_label();
        if (!p.probe.empty()) pj["probe"] = p.probe;
        if (!p.extra_versions.empty()) {
          json extras = json::array();
          for (const auto& [ep, ev] : p.extra_versions)
            extras.push_back({{"product", ep}, {"version", ev}});
          pj["extra_versions"] = extras;
        }
        ports.push_back(std::move(pj));
      }
      hj["ports"] = ports;
      if (!h.scan_visibility.empty()) {
        hj["scan_visibility"] = h.scan_visibility;
        if (!h.visibility_notes.empty())
          hj["visibility_notes"] = h.visibility_notes;
      }
      if (h.tls && h.tls->ok) {
        const TlsInfo& ti = *h.tls;
        hj["tls"] = {{"protocol", ti.protocol},
                     {"cipher", ti.cipher},
                     {"subject", ti.subject},
                     {"issuer", ti.issuer},
                     {"self_signed", ti.self_signed},
                     {"not_after", ti.not_after},
                     {"days_until_expiry", ti.days_until_expiry},
                     {"san_dns", ti.san_dns}};
      }
      if (!h.os_guess.empty()) hj["os_guess"] = h.os_guess;
      if (!h.tech.empty()) {
        json tech = json::array();
        for (const auto& t : h.tech)
          tech.push_back({{"name", t.name},
                          {"version", t.version},
                          {"source", t.source}});
        hj["tech"] = tech;
      }
      if (!h.paths.empty()) {
        json paths = json::array();
        for (const auto& p : h.paths)
          paths.push_back({{"path", p.path},
                           {"status", p.status},
                           {"size", p.size},
                           {"source", p.source}});
        hj["paths"] = paths;
      }
      if (!h.subdomains.empty()) hj["subdomains"] = h.subdomains;
      if (h.wildcard_dns) hj["wildcard_dns"] = true;
      if (!h.emails.empty()) hj["emails"] = h.emails;
      if (!h.neighbors.empty()) hj["neighbors"] = h.neighbors;
      if (!h.infra_tags.empty()) hj["infra_tags"] = h.infra_tags;
      if (!h.shodan_cpes.empty()) hj["shodan_cpes"] = h.shodan_cpes;
      if (!h.dns_records.empty()) {
        json dns = json::array();
        for (const auto& d : h.dns_records)
          dns.push_back({{"type", d.type},
                         {"name", d.name},
                         {"value", d.value},
                         {"ttl", d.ttl}});
        hj["dns_records"] = dns;
      }
      if (h.dns_zone_transfer) hj["dns_zone_transfer"] = true;
      if (h.geo.ok) {
        hj["geo"] = {{"country", h.geo.country},
                     {"region", h.geo.region},
                     {"city", h.geo.city},
                     {"latitude", h.geo.lat},
                     {"longitude", h.geo.lon},
                     {"asn", h.geo.asn},
                     {"org", h.geo.org}};
      }
      if (h.whois.ok) {
        hj["whois"] = {{"registrar", h.whois.registrar},
                       {"created", h.whois.created},
                       {"updated", h.whois.updated},
                       {"expires", h.whois.expires},
                       {"emails", h.whois.emails},
                       {"nameservers", h.whois.nameservers}};
      }
      if (!h.reputation.empty()) hj["reputation"] = h.reputation;
      hosts.push_back(std::move(hj));
    }
    j["hosts"] = hosts;

    json web = json::array();
    for (const auto& w : r.web) {
      web.push_back({{"url", w.url},
                     {"status", w.status},
                     {"server", w.server},
                     {"fetched", w.fetched},
                     {"error", w.error},
                     {"headers", headers_to_json(w.headers)}});
    }
    j["web"] = web;

    json findings = json::array();
    for (const auto& f : r.findings) {
      findings.push_back({{"severity", severity_key(f.severity)},
                          {"module", f.module},
                          {"host", f.host},
                          {"port", f.port},
                          {"service", f.service},
                          {"location", f.location},
                          {"title", f.title},
                          {"detail", f.detail},
                          {"recommendation", f.recommendation},
                          {"evidence", f.evidence},
                          {"references", f.references}});
    }
    j["findings"] = findings;

    // trace: кап 1000, totals отдельно
    auto traffic = r.traffic_snapshot();
    size_t dropped = r.trace_dropped_count();
    size_t total_events = traffic.size() + dropped;
    json trace = json::array();
    for (const auto& e : traffic) {
      if (trace.size() >= 1000) break;
      trace.push_back({{"module", e.module},
                       {"kind", e.kind},
                       {"target", e.target},
                       {"request", e.request},
                       {"response", e.response},
                       {"status", e.status},
                       {"sent_bytes", e.sent},
                       {"recv_bytes", e.recv},
                       {"ms", std::round(e.ms * 10.0) / 10.0}});
    }
    j["traffic"] = trace;
    j["traffic_totals"] = {{"events_total", total_events},
                            {"events_in_memory", traffic.size()},
                            {"events_shown", trace.size()},
                            {"events_dropped_by_cap", dropped}};

    auto counts = r.counts();
    int total = 0;
    json cj = json::object();
    for (Severity s : {Severity::Info, Severity::Low, Severity::Medium,
                       Severity::High, Severity::Critical}) {
      cj[severity_key(s)] = counts[s];
      total += counts[s];
    }
    j["stats"] = {{"total", total},
                  {"counts", cj},
                  {"duplicates_suppressed", r.suppressed_duplicates_count()}};

    json provs = json::object();
    for (const auto& [phost, st] : r.provider_stats) {
      provs[phost] = {{"name", st.name},
                      {"requests", st.allowed},
                      {"blocked", st.blocked},
                      {"successes", st.successes},
                      {"failures", st.failures},
                      {"circuit_trips", st.circuit_trips},
                      {"circuit_open_at_end", st.circuit_open},
                      {"request_cap_reached", st.capped}};
    }
    j["providers"] = provs;

    // граф: кап 2000/4000
    {
      const auto& gnodes = r.intel.nodes();
      const auto& gedges = r.intel.edges();
      constexpr size_t kMaxNodes = 2000, kMaxEdges = 4000;
      json gj_nodes = json::array();
      for (size_t i = 0; i < gnodes.size() && i < kMaxNodes; ++i) {
        const GraphNode& n = gnodes[i];
        gj_nodes.push_back({{"id", n.id},
                            {"type", node_type_key(n.type)},
                            {"value", n.value},
                            {"status", n.status},
                            {"confidence", std::round(n.confidence * 100.0) / 100.0},
                            {"sources", n.sources}});
      }
      json gj_edges = json::array();
      for (size_t i = 0; i < gedges.size() && i < kMaxEdges; ++i) {
        const GraphEdge& e = gedges[i];
        gj_edges.push_back({{"src", e.src},
                            {"dst", e.dst},
                            {"relation", e.relation},
                            {"status", e.status},
                            {"confidence", std::round(e.confidence * 100.0) / 100.0},
                            {"evidence", truncate_ellipsis(e.evidence, 300)},
                            {"sources", e.sources}});
      }
      json type_counts = json::object();
      for (const auto& [tk, tc] : r.intel.node_counts()) type_counts[tk] = tc;
      j["intelligence_graph"] = {
          {"nodes", gj_nodes},
          {"edges", gj_edges},
          {"totals", {{"nodes", gnodes.size()},
                       {"edges", gedges.size()},
                       {"nodes_shown", gj_nodes.size()},
                       {"edges_shown", gj_edges.size()}}},
          {"node_counts", type_counts}};
    }

    std::ofstream f(path_, std::ios::trunc);
    if (!f) {
      err = "cannot open JSON report file: " + path_;
      return false;
    }
    f << j.dump(2) << "\n";
    if (!f) {
      err = "failed writing JSON report: " + path_;
      return false;
    }
    return true;
  }

 private:
  std::string path_;
};

}  // namespace

std::unique_ptr<IReporter> make_json_reporter(const std::string& path) {
  return std::make_unique<JsonReporter>(path);
}

}  // namespace mikto
