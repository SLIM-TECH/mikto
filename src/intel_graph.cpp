// граф: один проход по ScanResult, каждое ребро знает свой источник
#include "mikto/intel_graph.hpp"

#include <algorithm>
#include <cctype>

#include "mikto/target.hpp"
#include "mikto/scan_result.hpp"
#include "mikto/util.hpp"

namespace mikto {

const char* node_type_key(NodeType t) {
  switch (t) {
    case NodeType::Domain: return "domain";
    case NodeType::Ip: return "ip";
    case NodeType::Asn: return "asn";
    case NodeType::Provider: return "provider";
    case NodeType::Service: return "service";
    case NodeType::Technology: return "technology";
    case NodeType::Endpoint: return "endpoint";
    case NodeType::Email: return "email";
    case NodeType::Certificate: return "certificate";
    case NodeType::MailExchanger: return "mail_exchanger";
    case NodeType::Nameserver: return "nameserver";
    case NodeType::Cve: return "cve";
  }
  return "domain";
}

const char* node_type_name(NodeType t) {
  switch (t) {
    case NodeType::Domain: return "Domain";
    case NodeType::Ip: return "IP";
    case NodeType::Asn: return "ASN";
    case NodeType::Provider: return "Provider";
    case NodeType::Service: return "Service";
    case NodeType::Technology: return "Technology";
    case NodeType::Endpoint: return "Endpoint";
    case NodeType::Email: return "Email";
    case NodeType::Certificate: return "Certificate";
    case NodeType::MailExchanger: return "Mail exchanger";
    case NodeType::Nameserver: return "Nameserver";
    case NodeType::Cve: return "CVE";
  }
  return "Domain";
}

int graph_status_rank(const std::string& status) {
  if (status == "confirmed") return 3;
  if (status == "probable") return 2;
  if (status == "possible") return 1;
  return 0;  // "unverified" and anything unknown
}

// ---- Core graph ops ----------------------------------------------------------

GraphNode& IntelGraph::ensure(NodeType type, const std::string& raw_value,
                              const std::string& status, double confidence,
                              const std::string& source) {
  // хостоподобное в lower, остальное с регистром как есть
  std::string value = raw_value;
  switch (type) {
    case NodeType::Domain:
    case NodeType::Ip:
    case NodeType::Email:
    case NodeType::MailExchanger:
    case NodeType::Nameserver:
    case NodeType::Provider:
      value = to_lower(trim(value));
      break;
    case NodeType::Asn:
      // AS13335 канонично в верхнем регистре
      value = to_upper(trim(value));
      break;
    default:
      break;
  }
  std::string id = std::string(node_type_key(type)) + ":" + value;
  auto it = index_.find(id);
  if (it == index_.end()) {
    GraphNode n;
    n.id = id;
    n.type = type;
    n.value = value;
    n.status = status;
    n.confidence = confidence;
    if (!source.empty()) n.sources.push_back(source);
    n.first_seen = now_;
    n.last_seen = now_;
    index_[id] = nodes_.size();
    nodes_.push_back(std::move(n));
    return nodes_.back();
  }
  GraphNode& n = nodes_[it->second];
  if (std::find(n.sources.begin(), n.sources.end(), source) == n.sources.end())
    n.sources.push_back(source);
  if (graph_status_rank(status) > graph_status_rank(n.status)) {
    n.status = status;
    n.confidence = confidence;
  } else if (status == n.status && confidence > n.confidence) {
    n.confidence = confidence;
  }
  n.last_seen = now_;
  return n;
}

void IntelGraph::link(const std::string& src_id, const std::string& dst_id,
                      const std::string& relation, const std::string& status,
                      double confidence, const std::string& evidence,
                      const std::string& source) {
  for (auto& e : edges_) {
    if (e.src == src_id && e.dst == dst_id && e.relation == relation) {
      if (std::find(e.sources.begin(), e.sources.end(), source) ==
          e.sources.end())
        e.sources.push_back(source);
      if (graph_status_rank(status) > graph_status_rank(e.status)) {
        e.status = status;
        e.confidence = confidence;
      } else if (status == e.status && confidence > e.confidence) {
        e.confidence = confidence;
      }
      if (!evidence.empty() &&
          e.evidence.find(evidence) == std::string::npos &&
          e.evidence.size() < 400)
        e.evidence += (e.evidence.empty() ? "" : " | ") + evidence;
      return;
    }
  }
  GraphEdge e;
  e.src = src_id;
  e.dst = dst_id;
  e.relation = relation;
  e.status = status;
  e.confidence = confidence;
  e.evidence = evidence;
  if (!source.empty()) e.sources.push_back(source);
  edges_.push_back(std::move(e));
}

std::map<std::string, int> IntelGraph::node_counts() const {
  std::map<std::string, int> m;
  for (const auto& n : nodes_) ++m[node_type_key(n.type)];
  return m;
}

std::map<std::string, int> IntelGraph::edge_counts() const {
  std::map<std::string, int> m;
  for (const auto& e : edges_) ++m[e.relation];
  return m;
}

// ---- Build pass ---------------------------------------------------------------

namespace {

std::string norm_host(const std::string& s) { return to_lower(trim(s)); }

// CVE id из references находки
std::vector<std::string> cve_refs(const Finding& f) {
  std::vector<std::string> out;
  for (const std::string& ref : f.references) {
    size_t pos = 0;
    while ((pos = ref.find("CVE-", pos)) != std::string::npos) {
      size_t i = pos + 4;
      size_t d1 = 0;
      while (i < ref.size() &&
             std::isdigit(static_cast<unsigned char>(ref[i]))) {
        ++i;
        ++d1;
      }
      if (d1 > 0 && i < ref.size() && ref[i] == '-') {
        size_t j = i + 1;
        size_t d2 = 0;
        while (j < ref.size() &&
               std::isdigit(static_cast<unsigned char>(ref[j]))) {
          ++j;
          ++d2;
        }
        if (d2 > 0) {
          out.push_back(ref.substr(pos, j - pos));
          pos = j;
          if (out.size() >= 8) return out;
          continue;
        }
      }
      pos += 4;
    }
  }
  return out;
}

}  // namespace

void IntelGraph::build(const ScanResult& r) {
  nodes_.clear();
  index_.clear();
  edges_.clear();
  now_ = r.finished_at.empty() ? r.started_at : r.finished_at;

  // ---- 1) цели из scope ----
  for (const auto& t : r.targets) {
    if (t.is_ip)
      ensure(NodeType::Ip, norm_host(t.host), "confirmed", 1.0, "user scope");
    else
      ensure(NodeType::Domain, norm_host(t.host), "confirmed", 1.0,
             "user scope");
  }

  // ---- 2) инфраструктура хостов ----
  for (const auto& h : r.hosts) {
    const std::string hval = norm_host(h.host);
    const std::string hid =
        h.is_ip ? ("ip:" + hval) : ("domain:" + hval);

    ensure(h.is_ip ? NodeType::Ip : NodeType::Domain, hval, "confirmed", 1.0,
           "assets");

    // подтверждено ответом dns
    for (const std::string& ip : h.ips) {
      ensure(NodeType::Ip, ip, "confirmed", 1.0, "assets");
      link(hid, "ip:" + ip, "resolves_to", "confirmed", 1.0,
           "A/AAAA answer via system resolvers", "assets");
    }
    // asn из geo-базы, та может отставать
    if (h.geo.ok && !h.geo.asn.empty()) {
      const std::string asn_id =
          "asn:" + to_upper(trim(h.geo.asn));  // matches ensure() canonical id
      std::string src = h.geo.org.empty() ? std::string("geo") : h.geo.org;
      ensure(NodeType::Asn, h.geo.asn, "probable", 0.8, src);
      if (!h.ips.empty()) {
        for (const std::string& ip : h.ips)
          link("ip:" + ip, asn_id, "belongs_to_asn", "probable", 0.8,
               "network ownership lookup (ipwho.is/ip-api)", "geo");
      } else {
        link(hid, asn_id, "belongs_to_asn", "probable", 0.8,
             "network ownership lookup (ipwho.is/ip-api)", "geo");
      }
    }

    // MX / NS records (confirmed DNS answers).
    for (const auto& rec : h.dns_records) {
      std::string v = to_lower(trim(rec.value));
      if (rec.type == "MX") {
        std::string target = v;
        size_t sp = target.find(' ');
        if (sp != std::string::npos) target = trim(target.substr(sp + 1));
        while (!target.empty() && target.back() == '.') target.pop_back();
        if (!target.empty()) {
          ensure(NodeType::MailExchanger, target, "confirmed", 1.0, "assets");
          link(hid, "mail_exchanger:" + target, "mail_via", "confirmed", 1.0,
               "MX record", "assets");
        }
      } else if (rec.type == "NS") {
        while (!v.empty() && v.back() == '.') v.pop_back();
        if (!v.empty()) {
          ensure(NodeType::Nameserver, v, "confirmed", 1.0, "assets");
          link(hid, "nameserver:" + v, "delegated_to", "confirmed", 1.0,
               "NS record", "assets");
        }
      }
    }

    // предъявлен в handshake
    if (h.tls && h.tls->ok && !h.tls->subject.empty()) {
      const std::string subj = h.tls->subject;
      ensure(NodeType::Certificate, subj, "confirmed", 1.0, "ports");
      link(hid, "certificate:" + subj, "presents", "confirmed", 1.0,
           "TLS handshake certificate subject", "ports");
      if (!h.tls->issuer.empty()) {
        ensure(NodeType::Provider, h.tls->issuer, "confirmed", 0.9, "ports");
        link("certificate:" + subj, "provider:" + to_lower(h.tls->issuer),
             "issued_by", "confirmed", 0.9, "certificate issuer field",
             "ports");
      }
    }

    // статус сервиса = уверенность зонда
    for (const auto& p : h.ports) {
      if (!p.open) continue;
      const std::string sport = std::to_string(p.port);
      const std::string sid = "service:" + hval + ":" + sport;
      const char* st = p.confidence >= 3 ? "confirmed"
                       : p.confidence == 2 ? "probable"
                       : p.confidence == 1 ? "probable"
                                           : "possible";
      double conf = p.confidence >= 3 ? 1.0
                    : p.confidence == 2 ? 0.8
                    : p.confidence == 1 ? 0.7
                                        : 0.5;
      std::string ev = "port open";
      if (!p.banner.empty())
        ev += "; banner: " + truncate_ellipsis(p.banner, 60);
      if (!p.probe.empty()) ev += "; probe: " + p.probe;
      ensure(NodeType::Service, hval + ":" + sport, st, conf, "ports");
      link(hid, sid, "has_service", st, conf, ev, "ports");

      // вторая софтина в том же баннере
      for (const auto& extra : p.extra_versions) {
        std::string label = to_lower(extra.first +
                                     (extra.second.empty()
                                          ? ""
                                          : " " + extra.second));
        ensure(NodeType::Technology, label, st, conf, "ports");
        link(sid, "technology:" + label, "exposes", st, conf,
             "same banner/header evidence", "ports");
      }
    }

    // хедеры подделать можно, потому только probable
    for (const auto& t : h.tech) {
      std::string label =
          to_lower(t.name + (t.version.empty() ? "" : " " + t.version));
      ensure(NodeType::Technology, label, "probable", 0.75, "tech");
      link(hid, "technology:" + label, "runs", "probable", 0.75,
           "detected via " + t.source, "tech");
    }

    // ответ был настоящий
    for (const auto& p : h.paths) {
      std::string path = p.path.empty() ? "/" : p.path;
      ensure(NodeType::Endpoint, path, "confirmed", 1.0, "webpaths");
      link(hid, "endpoint:" + path, "exposes", "confirmed", 1.0,
           "HTTP " + std::to_string(p.status) +
               (p.source.empty() ? "" : " (found via " + p.source + ")"),
           "webpaths");
    }

    // где-то опубликованы, владение не проверено
    for (const auto& e : h.emails) {
      ensure(NodeType::Email, to_lower(e), "probable", 0.6, "emails");
      link("email:" + to_lower(e), hid, "affiliated_with", "probable", 0.6,
           "published on pages or in certificate records", "emails");
    }

    // co-hosted соседи, не сливаем
    for (const auto& nb : h.neighbors) {
      std::string nl = norm_host(nb);
      if (nl.empty() || nl == hval) continue;
      ensure(NodeType::Domain, nl, "possible", 0.5, "neighbors");
      if (!h.ips.empty())
        link("domain:" + nl, "ip:" + h.ips.front(), "resolves_to",
             "possible", 0.5, "co-hosted on the same IP (passive observation)",
             "neighbors");
    }

    // резолвились при дисковери
    if (!h.is_ip) {
      for (const auto& s : h.subdomains) {
        std::string sl = norm_host(s);
        if (sl.empty() || sl == hval) continue;
        ensure(NodeType::Domain, sl, "confirmed", 0.9, "subdom");
        link("domain:" + sl, hid, "subdomain_of", "confirmed", 0.9,
             "resolved during passive discovery", "subdom");
      }
    }

    // сам факт листинга подтверждён
    for (const auto& rep : h.reputation) {
      size_t colon = rep.find(':');
      if (colon == std::string::npos) continue;
      std::string srcname = trim(rep.substr(0, colon));
      if (srcname.empty()) continue;
      ensure(NodeType::Provider, srcname, "confirmed", 1.0, "infra");
      link(hid, "provider:" + to_lower(srcname), "listed_by", "confirmed",
           1.0, rep, "infra");
    }

    // регистратор из реестра
    if (h.whois.ok && !h.whois.registrar.empty()) {
      ensure(NodeType::Provider, h.whois.registrar, "confirmed", 0.9, "whois");
      link(hid, "provider:" + to_lower(h.whois.registrar), "registered_with",
           "confirmed", 0.9, "WHOIS/RDAP registrar field", "whois");
    }
  }

  // ---- 3) из находок ----
  for (const auto& f : r.findings) {
    std::string fhost = norm_host(f.host);
    if (fhost.empty()) continue;
    std::string hid = (looks_like_ipv4(fhost) || looks_like_ipv6(fhost))
                          ? "ip:" + fhost
                          : "domain:" + fhost;

    // сидит за cdn/waf: хинт, не доказательство
    if (f.module == "waf" &&
        f.title.rfind("Edge protection detected: ", 0) == 0) {
      std::string vendor =
          trim(f.title.substr(sizeof("Edge protection detected: ") - 1));
      if (!vendor.empty()) {
        ensure(NodeType::Provider, vendor, "probable", 0.8, "waf");
        link(hid, "provider:" + to_lower(vendor), "behind", "probable", 0.8,
             "edge fingerprint: " + f.evidence, "waf");
      }
    }
    // потенциально затронут, пока оператор не подтвердил
    if (f.module == "cve" || f.module == "infra") {
      for (const std::string& cve : cve_refs(f)) {
        ensure(NodeType::Cve, cve, "possible", 0.5, f.module);
        std::string ev = "matched by " + f.module;
        if (!f.detail.empty()) ev += ": " + truncate_ellipsis(f.detail, 100);
        link(hid, "cve:" + cve, "potentially_affected", "possible", 0.5, ev,
             f.module);
      }
    }
  }
}

}  // namespace mikto
