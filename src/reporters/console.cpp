// консольный репортер: дерево, severity-цвета, лимиты списков.
#include "mikto/win_compat.hpp"

#include <algorithm>
#include <iostream>
#include <map>

#include "mikto/config.hpp"
#include "mikto/intel_graph.hpp"
#include "mikto/reporter.hpp"
#include "mikto/scan_result.hpp"
#include "mikto/util.hpp"
#include "mikto/version.hpp"

namespace mikto {

namespace {

struct Ctx {
  bool color = false;
  const ScanResult* r = nullptr;

  std::string tag(Severity s) const {
    if (!color) {
      return std::string("[") + severity_name(s) + "]";
    }
    return std::string(severity_color(s)) + "[" + severity_name(s) + "]" +
           "\033[0m";
  }
};

const char* kDown = "├── ";
const char* kEnd = "└── ";
const char* kBar = "│   ";
const char* kGap = "    ";

void print_summary_line(const Ctx& c, const Config& cfg,
                        const std::vector<std::string>& reports) {
  (void)cfg;
  auto counts = c.r->counts();
  int total = 0;
  for (auto& kv : counts) total += kv.second;
  std::cout << "\nSummary:";
  const Severity order[] = {Severity::Critical, Severity::High, Severity::Medium,
                            Severity::Low, Severity::Info};
  for (Severity s : order) {
    if (!counts[s]) continue;
    if (c.color) std::cout << " " << severity_color(s) << counts[s] << " "
                           << severity_name(s) << "\033[0m";
    else std::cout << " " << counts[s] << " " << severity_name(s);
  }
  if (total == 0) std::cout << " no findings";
  else std::cout << " (" << total << " findings)";
  std::cout << "\nModules: ";
  for (size_t i = 0; i < c.r->modules_run.size(); ++i) {
    if (i) std::cout << ", ";
    std::cout << c.r->modules_run[i];
  }
  std::cout << " — " << format_duration(c.r->duration_s) << "\n";
  if (!c.r->intel.nodes().empty()) {
    std::cout << "Intelligence graph: " << c.r->intel.nodes().size()
              << " entities, " << c.r->intel.edges().size() << " relations (";
    size_t remaining = 4;
    for (const auto& [tk, tc] : c.r->intel.node_counts()) {
      if (!remaining) break;
      --remaining;
      std::cout << tk << " " << tc << (remaining ? ", " : "");
    }
    if (c.r->intel.node_counts().size() > 4)
      std::cout << ", ...";
    std::cout << ") — full graph in the JSON report\n";
  }
  if (!reports.empty()) {
    std::cout << "Reports: ";
    for (size_t i = 0; i < reports.size(); ++i) {
      if (i) std::cout << ", ";
      std::cout << reports[i];
    }
    std::cout << "\n";
  }
  (void)cfg;
}

class ConsoleReporter : public IReporter {
 public:
  bool write(const ScanResult& r, const Config& cfg, std::string& err) override {
    (void)err;
    Ctx c;
    c.color = !cfg.no_color && is_stdout_tty();
    c.r = &r;

    std::cout << "mikto v" << MIKTO_VERSION << " — scan report\n";

    auto passes = [&](const Finding& f) {
      return !cfg.severity_filter_set ||
             static_cast<int>(f.severity) >= static_cast<int>(cfg.min_severity);
    };

    // разбор по бакетам: infra/web/secrets/recon
    std::vector<Finding> infra, web, secrets, recon, other;
    for (const auto& f : r.findings) {
      if (!passes(f)) continue;
      if (f.module == "headers" || f.module == "tech" ||
          f.module == "webpaths")
        web.push_back(f);
      else if (f.module == "secrets") secrets.push_back(f);
      else if (f.module == "subdom" || f.module == "emails" ||
               f.module == "emailsec" || f.module == "neighbors" ||
               f.module == "infra" || f.module == "assets" ||
               f.module == "whois")
        recon.push_back(f);
      else if (f.port > 0) infra.push_back(f);
      else other.push_back(f);
    }

    if (!r.hosts.empty()) {
      std::cout << "\nInfrastructure\n";
      size_t hi = 0;
      for (const auto& h : r.hosts) {
        bool host_last = ++hi == r.hosts.size();
        std::cout << (host_last ? kEnd : kDown) << h.host;
        if (!h.ips.empty()) {
          std::string ips;
          for (size_t i = 0; i < h.ips.size(); ++i) {
            if (i) ips += ", ";
            ips += h.ips[i];
          }
          std::cout << " (" << ips << ")";
        }
        if (!h.os_guess.empty()) std::cout << " — " << h.os_guess;
        if (h.geo.ok) {
          std::cout << " — " << h.geo.country;
          if (!h.geo.city.empty()) std::cout << ", " << h.geo.city;
          if (!h.geo.asn.empty()) std::cout << " [" << h.geo.asn << "]";
        }
        if (!h.reputation.empty()) std::cout << " — MALICIOUS (URLhaus)";
        std::cout << "\n";
        if (!h.scan_visibility.empty() && h.scan_visibility != "full") {
          std::cout << (host_last ? kGap : kBar) << kEnd;
          if (h.scan_visibility == "blocked")
            std::cout << "visibility: BLOCKED — results incomplete";
          else
            std::cout << "visibility: degraded — results may be incomplete";
          if (!h.visibility_notes.empty())
            std::cout << " (" << h.visibility_notes.front() << ")";
          std::cout << "\n";
        }
        if (!h.dns_records.empty()) {
          int mx = 0, ns = 0, txt = 0;
          for (const auto& rec : h.dns_records) {
            if (rec.type == "MX") ++mx;
            else if (rec.type == "NS") ++ns;
            else if (rec.type == "TXT") ++txt;
          }
          std::cout << (host_last ? kGap : kBar) << kEnd << "DNS: "
                    << h.dns_records.size() << " records";
          if (mx) std::cout << ", MX " << mx;
          if (ns) std::cout << ", NS " << ns;
          if (txt) std::cout << ", TXT " << txt;
          if (!h.subdomains.empty())
            std::cout << ", " << h.subdomains.size() << " subdomains";
          std::cout << "\n";
        } else if (!h.subdomains.empty()) {
          std::cout << (host_last ? kGap : kBar) << kEnd << h.subdomains.size()
                    << " subdomains\n";
        }
        if (h.ports.empty()) {
          std::cout << (host_last ? kGap : kBar) << kEnd
                    << "(no open ports)\n";
          continue;
        }
        size_t pi = 0;
        size_t open_count = 0;
        for (const auto& p : h.ports)
          if (p.open) ++open_count;
        for (const auto& p : h.ports) {
          if (!p.open) continue;
          bool port_last = ++pi == open_count;
          std::cout << (host_last ? kGap : kBar)
                    << (port_last ? kEnd : kDown) << p.port << "/tcp  "
                    << p.service_label();
          if (p.confidence <= 1 && p.open) std::cout << " [guess]";
          std::cout << "\n";
          // находки на порту
          std::vector<const Finding*> pf;
          for (const auto& f : infra)
            if (f.host == h.host && f.port == p.port) pf.push_back(&f);
          const size_t cap = 4;
          size_t shown = 0;
          for (const Finding* f : pf) {
            if (shown >= cap) break;
            bool last = shown + 1 == std::min(pf.size(), cap);
            std::cout << (host_last ? kGap : kBar)
                      << (port_last ? kGap : kBar)
                      << (last ? kEnd : kDown) << c.tag(f->severity) << " "
                      << f->title << "\n";
            ++shown;
          }
          if (pf.size() > cap) {
            std::cout << (host_last ? kGap : kBar)
                      << (port_last ? kGap : kBar) << kEnd << "... "
                      << (pf.size() - cap)
                      << " more — see the JSON/HTML report\n";
          }
        }
      }
    }

    if (!web.empty()) {
      std::cout << "\nWeb\n";
      std::map<std::string, std::vector<const Finding*>> groups;
      for (const auto& f : web) {
        std::string key = f.host + (f.port ? ":" + std::to_string(f.port) : "");
        groups[key].push_back(&f);
      }
      size_t gi = 0;
      for (auto& kv : groups) {
        bool last = ++gi == groups.size();
        std::cout << (last ? kEnd : kDown) << kv.first << "\n";
        size_t fi = 0;
        size_t shown_n = std::min<size_t>(kv.second.size(), 6);
        for (const Finding* f : kv.second) {
          if (fi >= shown_n) break;
          bool flast = ++fi == shown_n;
          std::cout << (last ? kGap : kBar) << (flast ? kEnd : kDown)
                    << c.tag(f->severity) << " " << f->title;
          if (!f->location.empty() && f->location != "response")
            std::cout << " (" << f->location << ")";
          std::cout << "\n";
        }
        if (kv.second.size() > shown_n)
          std::cout << (last ? kGap : kBar) << kEnd << "... "
                    << (kv.second.size() - shown_n) << " more\n";
      }
    }

    if (!secrets.empty()) {
      std::cout << "\nSecrets\n";
      size_t shown = std::min<size_t>(secrets.size(), 6);
      for (size_t i = 0; i < shown; ++i) {
        bool last = i + 1 == shown;
        std::cout << (last ? kEnd : kDown) << c.tag(secrets[i].severity) << " "
                  << secrets[i].title;
        if (!secrets[i].location.empty())
          std::cout << " — " << secrets[i].location;
        std::cout << "\n";
      }
      if (secrets.size() > shown)
        std::cout << kEnd << "... " << (secrets.size() - shown) << " more\n";
    }

    if (!recon.empty()) {
      std::cout << "\nRecon\n";
      std::map<std::string, std::vector<const Finding*>> groups;
      for (const auto& f : recon) groups[f.host + (f.location != f.host ? " — " + f.location : "")].push_back(&f);
      size_t gi = 0;
      for (auto& kv : groups) {
        bool last = ++gi == groups.size();
        std::cout << (last ? kEnd : kDown) << kv.first << "\n";
        size_t fi = 0;
        size_t shown_n = std::min<size_t>(kv.second.size(), 4);
        for (const Finding* f : kv.second) {
          if (fi >= shown_n) break;
          bool flast = ++fi == shown_n;
          std::cout << (last ? kGap : kBar) << (flast ? kEnd : kDown)
                    << c.tag(f->severity) << " " << f->title;
          if (!f->evidence.empty() && f->evidence.size() < 120)
            std::cout << " [" << f->evidence << "]";
          std::cout << "\n";
        }
        if (kv.second.size() > shown_n)
          std::cout << (last ? kGap : kBar) << kEnd << "... "
                    << (kv.second.size() - shown_n) << " more\n";
      }
    }

    if (!other.empty()) {
      std::cout << "\nOther\n";
      size_t shown = std::min<size_t>(other.size(), 6);
      for (size_t i = 0; i < shown; ++i) {
        bool last = i + 1 == shown;
        std::cout << (last ? kEnd : kDown) << c.tag(other[i].severity) << " "
                  << other[i].title << " (" << other[i].host << ")\n";
      }
      if (other.size() > shown)
        std::cout << kEnd << "... " << (other.size() - shown) << " more\n";
    }

    if (r.hosts.empty() && r.web.empty()) {
      std::cout << "\nNo results (all targets unreachable or no modules "
                   "produced output).\n";
    }

    bool prov_line = false;
    for (const auto& [phost, st] : r.provider_stats) {
      if (st.failures == 0 && st.blocked == 0) continue;
      if (!prov_line) {
        std::cout << "\nProviders (external sources — failures/blocks recorded):\n";
        prov_line = true;
      }
      std::cout << kEnd << st.name << ": " << st.allowed << " request(s), "
                << st.failures << " failed";
      if (st.blocked) std::cout << ", " << st.blocked << " skipped (breaker)";
      if (st.circuit_open) std::cout << " — circuit OPEN at scan end";
      std::cout << "\n";
    }

    if (cfg.trace) {
      auto traffic = r.traffic_snapshot();
      auto kinds = r.trace_counts();
      std::cout << "\nTraffic (" << traffic.size() << " events:";
      for (auto& kv : kinds) std::cout << " " << kv.second << " " << kv.first;
      std::cout << ")\n";
      size_t shown = std::min<size_t>(traffic.size(), 40);
      size_t start = traffic.size() > 40 ? traffic.size() - 40 : 0;
      for (size_t i = start; i < start + shown; ++i) {
        const TrafficEvent& e = traffic[i];
        std::cout << "  [" << e.module.substr(0, 8) << "] " << e.request
                  << "  ->  " << e.response;
        if (e.ms > 0)
          std::cout << " (" << static_cast<int>(e.ms) << " ms)";
        std::cout << "\n";
      }
      if (traffic.size() > shown)
        std::cout << "  ... " << (traffic.size() - shown)
                  << " more — full log in the JSON/HTML report\n";
    }

    std::vector<std::string> reports;
    if (!cfg.json_out.empty()) reports.push_back(cfg.json_out);
    if (!cfg.html_out.empty()) reports.push_back(cfg.html_out);
    if (!cfg.sarif_out.empty()) reports.push_back(cfg.sarif_out);
    if (!cfg.csv_out.empty()) reports.push_back(cfg.csv_out);
    print_summary_line(c, cfg, reports);
    return true;
  }
};

}  // namespace

std::unique_ptr<IReporter> make_console_reporter() {
  return std::make_unique<ConsoleReporter>();
}

}  // namespace mikto
