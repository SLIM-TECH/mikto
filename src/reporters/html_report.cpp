// html репортер: самодостаточный файл, css+js инлайном, без внешних ссылок.
#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <fstream>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>

#include "mikto/config.hpp"
#include "mikto/intel_graph.hpp"
#include "mikto/reporter.hpp"
#include "mikto/scan_result.hpp"
#include "mikto/util.hpp"
#include "mikto/version.hpp"

static const char* const kCss =
#include "html_report_css.inc"
    ;

static const char* const kJs =
#include "html_report_js.inc"
    ;

namespace mikto {

namespace {

// риск-модель

struct Risk {
  int score = 0;
  char grade = 'A';
  const char* word = "clean";
};

Risk assess_risk(const std::map<Severity, int>& counts) {
  static const std::map<Severity, int> w = {
      {Severity::Critical, 25}, {Severity::High, 10}, {Severity::Medium, 4},
      {Severity::Low, 1},       {Severity::Info, 0}};
  int sum = 0;
  for (auto& kv : counts) {
    auto it = w.find(kv.first);
    if (it != w.end()) sum += it->second * kv.second;
  }
  Risk r;
  r.score = std::min(100, sum);
  if (r.score == 0) {
    r.grade = 'A';
    r.word = "clean";
  } else if (r.score <= 9) {
    r.grade = 'B';
    r.word = "low";
  } else if (r.score <= 24) {
    r.grade = 'C';
    r.word = "moderate";
  } else if (r.score <= 49) {
    r.grade = 'D';
    r.word = "elevated";
  } else {
    r.grade = 'F';
    r.word = "high";
  }
  return r;
}

const char* grade_color(char g) {
  switch (g) {
    case 'A': return "var(--ok)";
    case 'B': return "var(--low)";
    case 'C': return "var(--medium)";
    case 'D': return "var(--high)";
    default: return "var(--critical)";
  }
}

std::string fmt_size(size_t b) {
  std::ostringstream o;
  o << std::fixed;
  if (b >= 1024 * 1024) {
    o.precision(1);
    o << static_cast<double>(b) / (1024 * 1024) << " MB";
  } else if (b >= 1024) {
    o.precision(1);
    o << static_cast<double>(b) / 1024 << " KB";
  } else {
    o << b << " B";
  }
  return o.str();
}

std::string fmt_ms(double ms) {
  std::ostringstream o;
  o << std::fixed << std::setprecision(1) << ms;
  return o.str();
}

std::string status_class(long s) {
  if (s >= 200 && s < 300) return "s2";
  if (s >= 300 && s < 400) return "s3";
  if (s >= 400 && s < 600) return "s4";
  return "";
}

std::string path_source_label(const std::string& src) {
  if (src == "link") return "page link";
  if (src == "js") return "JS literal";
  if (src == "robots") return "robots.txt";
  if (src == "sitemap") return "sitemap.xml";
  if (src == "combo") return "combination";
  if (src == "wordlist") return "wordlist";
  return src.empty() ? "probe" : src;
}

std::string tag(const std::string& text, bool hot = false) {
  return "<span class=\"tag" + std::string(hot ? " hot" : "") + "\">" +
         html_escape(text) + "</span>";
}

std::string dot(Severity s) {
  return "<span class=\"dot d-" + std::string(severity_key(s)) +
         "\" aria-hidden=\"true\"></span>";
}

std::string chip(Severity s) {
  return "<span class=\"chip ch-" + std::string(severity_key(s)) + "\">" +
         severity_name(s) + "</span>";
}

std::string status_chip(const std::string& st) {
  return "<span class=\"stchip st-" + html_escape(st) + "\">" + html_escape(st) +
         "</span>";
}

std::string conf_cell(double c) {
  int pct = static_cast<int>(std::lround(c * 100));
  std::ostringstream o;
  o << "<span class=\"confbar\" aria-hidden=\"true\"><i style=\"width:" << pct
    << "%\"></i></span><span class=\"num\">" << pct << "%</span>";
  return o.str();
}

std::string rel_label(const std::string& rel) {
  std::string out = rel;
  for (auto& c : out)
    if (c == '_') c = ' ';
  return out;
}

std::string node_short(const std::string& id) {
  size_t c = id.find(':');
  return c == std::string::npos ? id : id.substr(c + 1);
}

// ip-хелперы
bool parse_ipv4(const std::string& ip, unsigned out[4]) {
  size_t i = 0;
  for (int k = 0; k < 4; ++k) {
    if (k) {
      if (i >= ip.size() || ip[i] != '.') return false;
      ++i;
    }
    if (i >= ip.size() || !std::isdigit(static_cast<unsigned char>(ip[i])))
      return false;
    unsigned v = 0;
    int digs = 0;
    while (i < ip.size() && std::isdigit(static_cast<unsigned char>(ip[i])) &&
           digs < 3) {
      v = v * 10 + static_cast<unsigned>(ip[i] - '0');
      ++i;
      ++digs;
    }
    if (!digs || (i < ip.size() && std::isdigit(static_cast<unsigned char>(ip[i]))))
      return false;
    if (v > 255) return false;
    out[k] = v;
  }
  return i == ip.size();
}

std::string ip_sort_key(const std::string& ip) {
  unsigned o[4];
  if (parse_ipv4(ip, o)) {
    char buf[24];
    std::snprintf(buf, sizeof buf, "%03u.%03u.%03u.%03u", o[0], o[1], o[2], o[3]);
    return buf;
  }
  return to_lower(ip);
}

std::string ip_subnet(const std::string& ip) {
  unsigned o[4];
  if (parse_ipv4(ip, o)) {
    std::ostringstream s;
    s << o[0] << "." << o[1] << "." << o[2] << ".0/24";
    return s.str();
  }
  std::vector<std::string> groups;
  std::string cur;
  for (char c : ip) {
    if (c == ':') {
      groups.push_back(cur);
      cur.clear();
    } else {
      cur += c;
    }
  }
  groups.push_back(cur);
  std::vector<std::string> hex;
  for (const auto& g : groups) {
    if (!g.empty()) hex.push_back(to_lower(g));
    if (hex.size() == 4) break;
  }
  if (hex.size() < 4) return "";
  return hex[0] + ":" + hex[1] + ":" + hex[2] + ":" + hex[3] + "::/64";
}

class HtmlReporter : public IReporter {
 public:
  explicit HtmlReporter(std::string path) : path_(std::move(path)) {}

  bool write(const ScanResult& r, const Config& cfg, std::string& err) override {
    auto counts = r.counts();
    int total = 0;
    for (auto& kv : counts) total += kv.second;
    Risk risk = assess_risk(counts);

    std::set<std::string> modules, hosts_seen;
    for (const auto& f : r.findings) {
      modules.insert(f.module);
      if (!f.host.empty()) hosts_seen.insert(f.host);
    }

    std::map<std::string, int> host_findings;
    for (const auto& f : r.findings)
      if (!f.host.empty()) host_findings[f.host]++;

    std::set<std::string> all_ips;
    for (const auto& h : r.hosts)
      for (const auto& ip : h.ips) all_ips.insert(ip);

    std::ostringstream o;
    o << "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
      << "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
      << "<meta name=\"color-scheme\" content=\"light dark\">\n"
      << "<meta name=\"theme-color\" content=\"#f7f6f3\" media=\"(prefers-color-scheme: light)\">\n"
      << "<meta name=\"theme-color\" content=\"#0d1013\" media=\"(prefers-color-scheme: dark)\">\n"
      << "<title>mikto audit — " << html_escape(target_summary(cfg)) << "</title>\n"
      << "<style>" << kCss << "</style>\n</head>\n<body>\n"
      << "<a class=\"skip\" href=\"#main\">Skip to content</a>\n";

    // шапка
    o << "<header class=\"masthead\">\n<div class=\"glow\" aria-hidden=\"true\"></div>\n"
      << "<div class=\"wrap masthead-grid\">\n<div>\n"
      << "<div class=\"brandline\"><span class=\"logo\" aria-hidden=\"true\">m</span>"
      << "mikto audit report <span class=\"tag\">v" << MIKTO_VERSION << "</span></div>\n"
      << "<h1>" << html_escape(target_summary(cfg)) << "</h1>\n"
      << "<p class=\"sub\">External security audit. "
      << (r.deep ? "Deep mode" : "Safe mode (default: passive, non-destructive)")
      << " &middot; " << total << " finding" << (total == 1 ? "" : "s")
      << " across " << r.hosts.size() << " host" << (r.hosts.size() == 1 ? "" : "s")
      << " &middot; risk " << risk.score << "/100 (grade " << risk.grade
      << ", " << risk.word << ").</p>\n"
      << "<div class=\"metagrid\">"
      << "<span class=\"meta\">started <b class=\"num\">" << html_escape(r.started_at) << "</b></span>"
      << "<span class=\"meta\">duration <b class=\"num\">" << html_escape(format_duration(r.duration_s)) << "</b></span>"
      << "<span class=\"meta\">mode <b>" << (r.deep ? "deep" : "safe") << "</b>"
      << (r.safe_mode ? " &middot; <b>safe</b>" : "") << "</span>"
      << "<span class=\"meta\">modules <b class=\"num\">" << r.modules_run.size() << "</b></span>"
      << "<span class=\"meta\">IPs <b class=\"num\">" << all_ips.size() << "</b></span>"
      << "<span class=\"meta\">entities <b class=\"num\">" << r.intel.nodes().size() << "</b></span>"
      << "<span class=\"meta\">events <b class=\"num\">" << r.traffic_snapshot().size() << "</b></span>"
      << "</div>\n</div>\n"
      << "<div class=\"globe\" aria-hidden=\"true\"><canvas id=\"globe\" width=\"168\" height=\"168\"></canvas></div>\n"
      << "</div>\n</header>\n";

    // навигация
    o << "<nav class=\"top\" aria-label=\"Report sections\"><div class=\"in\">"
      << navlink("overview", "Overview") << navlink("findings", "Findings")
      << navlink("hosts", "Hosts") << navlink("infra", "Infrastructure")
      << navlink("web", "Web")
      << navlink("correlations", "Correlations")
      << navlink("traffic", "Traffic") << navlink("scaninfo", "Scan info")
      << "<span class=\"spacer\"></span>"
      << "<button class=\"iconbtn\" onclick=\"window.print()\" aria-label=\"Print report\" title=\"Print\">"
      << "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" aria-hidden=\"true\"><path d=\"M6 9V3h12v6M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2M6 14h12v7H6z\"/></svg></button>"
      << "<button class=\"iconbtn\" id=\"theme-toggle\" type=\"button\"></button>"
      << "<button class=\"iconbtn\" id=\"lang-toggle\" type=\"button\""
         " title=\"Language / Язык\" aria-label=\"Switch language\">RU</button>"
      << "</div></nav>\n";

    o << "<main id=\"main\">\n";

    // обзор
    o << "<section id=\"overview\">\n<header><h2>Overview</h2>"
      << "<span class=\"cnt\">executive summary</span></header>\n";

    o << "<div class=\"panel verdict\">\n";
    o << gauge_svg(risk);
    o << "<div style=\"flex:1;min-width:240px\">\n";
    o << "<h3>" << verdict_headline(counts, total, risk) << "</h3>\n";
    o << "<p class=\"small muted\" style=\"margin:6px 0 0\">" << verdict_body(r)
      << " Grade " << risk.grade << " (" << risk.word << ") on a 0–100 scale where "
      << "critical=25, high=10, medium=4, low=1.</p>\n";
    if (risk.score > 0) {
      o << "<div class=\"riskbar\" role=\"img\" aria-label=\"Risk score composition\">";
      for (Severity s : {Severity::Critical, Severity::High, Severity::Medium,
                         Severity::Low}) {
        int w = 0;
        if (s == Severity::Critical) w = 25;
        else if (s == Severity::High) w = 10;
        else if (s == Severity::Medium) w = 4;
        else w = 1;
        int contrib = counts[s] * w;
        if (!contrib) continue;
        int width = std::min(100, contrib);
        o << "<i style=\"width:" << width << "%;background:var(--"
          << severity_key(s) << ")\" title=\"" << severity_name(s) << ": "
          << counts[s] << " × " << w << " = +" << contrib << "\"></i>";
      }
      o << "</div><div class=\"risklegend\">";
      for (Severity s : {Severity::Critical, Severity::High, Severity::Medium,
                         Severity::Low}) {
        if (!counts[s]) continue;
        o << "<span class=\"dot d-" << severity_key(s)
          << "\" aria-hidden=\"true\"></span>" << severity_name(s)
          << " <b>×" << counts[s] << "</b>";
      }
      o << "</div>\n";
    }
    o << "</div>\n</div>\n";

    o << "<div class=\"stats\" role=\"group\" aria-label=\"Findings by severity\">";
    for (Severity s : {Severity::Critical, Severity::High, Severity::Medium,
                       Severity::Low, Severity::Info}) {
      o << "<button type=\"button\" class=\"stat s-" << severity_key(s)
        << "\" data-goto-sev=\"" << severity_key(s)
        << "\" aria-label=\"Show " << severity_name(s) << " findings, "
        << counts[s] << " found\"><span class=\"n num\">" << counts[s]
        << "</span><span class=\"l\">" << severity_name(s) << "</span></button>";
    }
    o << "</div>\n";

    o << visibility_panel(r);

    o << "<div class=\"panel\"><h3>Priority actions</h3>\n";
    std::vector<const Finding*> top5;
    std::set<std::string> seen_recs;
    for (const auto& f : r.findings) {
      if (f.severity == Severity::Info) continue;
      std::string key = f.recommendation.empty() ? f.title : f.recommendation;
      if (!seen_recs.insert(key).second) continue;
      top5.push_back(&f);
      if (top5.size() == 5) break;
    }
    if (top5.empty()) {
      o << "<p class=\"small muted\" style=\"margin:0\">No action items — no "
           "issues above Info severity were observed.</p>\n";
    } else {
      o << "<ol class=\"tops\">\n";
      for (const Finding* f : top5) {
        o << "<li><div><b>" << html_escape(f->title) << "</b>";
        if (!f->recommendation.empty())
          o << "<div class=\"small muted\">" << html_escape(f->recommendation) << "</div>";
        o << "</div>" << dot(f->severity) << "</li>\n";
      }
      o << "</ol>\n";
    }
    o << "</div>\n";

    // бары по модулям, клик фильтрует находки
    if (!modules.empty()) {
      std::map<std::string, std::map<Severity, int>> mod_sev;
      for (const auto& f : r.findings) ++mod_sev[f.module][f.severity];
      std::vector<std::pair<std::string, int>> mod_order(mod_sev.size());
      size_t mi = 0;
      for (const auto& kv : mod_sev) {
        int c = 0;
        for (auto& sv : kv.second) c += sv.second;
        mod_order[mi++] = {kv.first, c};
      }
      std::sort(mod_order.begin(), mod_order.end(),
                [](const auto& a, const auto& b) {
                  if (a.second != b.second) return a.second > b.second;
                  return a.first < b.first;
                });
      int max_mod = mod_order.empty() ? 0 : mod_order.front().second;
      o << "<div class=\"panel\"><h3>Findings by module</h3>"
        << "<p class=\"small muted\" style=\"margin:0 0 8px\">Bar length = share of "
           "the noisiest module; segments are severities. Click a row to filter "
           "the findings list.</p><div class=\"modbars\">";
      for (const auto& mo : mod_order) {
        const auto& sev = mod_sev[mo.first];
        int width = max_mod > 0
                        ? std::max(3, static_cast<int>(mo.second * 100 / max_mod))
                        : 3;
        o << "<button type=\"button\" class=\"modbar\" data-mod=\""
          << html_escape(mo.first) << "\" aria-label=\"Filter findings by module "
          << html_escape(mo.first) << ", " << mo.second << " findings\">"
          << "<span class=\"mname\">" << html_escape(mo.first) << "</span>"
          << "<span class=\"mtrack\" aria-hidden=\"true\">";
        double acc = 0.0;
        auto pct1 = [](double v) {
          std::ostringstream s;
          s << std::fixed << std::setprecision(1) << v;
          return s.str();
        };
        for (Severity s : {Severity::Critical, Severity::High, Severity::Medium,
                           Severity::Low, Severity::Info}) {
          auto it = sev.find(s);
          if (it == sev.end() || !it->second) continue;
          double seg = static_cast<double>(it->second) / mo.second * width;
          acc += seg;
          o << "<i style=\"left:" << pct1(acc - seg) << "%;width:" << pct1(seg)
            << "%;background:var(--" << severity_key(s) << ")\"></i>";
        }
        o << "</span><span class=\"mnum\">" << mo.second << "</span></button>";
      }
      o << "</div></div>\n";
    }

    size_t n_ports = 0, n_dns = 0, n_sub = 0, n_eml = 0, n_paths = 0,
           n_tech = 0, n_nb = 0, n_web = r.web.size(), n_ev = r.traffic_snapshot().size();
    for (const auto& h : r.hosts) {
      for (const auto& p : h.ports)
        if (p.open) ++n_ports;
      n_dns += h.dns_records.size();
      n_sub += h.subdomains.size();
      n_eml += h.emails.size();
      n_paths += h.paths.size();
      n_tech += h.tech.size();
      n_nb += h.neighbors.size();
    }
    o << "<div class=\"panel\"><h3>Coverage</h3>"
      << "<p class=\"small muted\" style=\"margin:0 0 10px\">Everything below is rendered "
         "in full further down — nothing is sampled or truncated.</p>"
      << "<div class=\"chips\">"
      << cov_tag("hosts", r.hosts.size()) << cov_tag("open ports", n_ports)
      << cov_tag("DNS records", n_dns) << cov_tag("subdomains", n_sub)
      << cov_tag("emails", n_eml) << cov_tag("web paths", n_paths)
      << cov_tag("technologies", n_tech) << cov_tag("neighbors", n_nb)
      << cov_tag("web responses", n_web) << cov_tag("traffic events", n_ev)
      << cov_tag("entities", r.intel.nodes().size())
      << cov_tag("relations", r.intel.edges().size())
      << "</div>";
    // учёт: капы и подавленные дубли
    size_t dropped = r.trace_dropped_count();
    size_t dups = r.suppressed_duplicates_count();
    int prov_req = 0, prov_fail = 0;
    for (const auto& [ph, st] : r.provider_stats) {
      prov_req += st.allowed;
      prov_fail += st.failures;
    }
    if (dropped || dups || prov_req) {
      o << "<p class=\"small muted\" style=\"margin:10px 0 6px\">Accounting:</p>"
        << "<div class=\"chips\">";
      if (dups) o << cov_tag("duplicate findings suppressed", dups);
      if (dropped) o << cov_tag("traffic events dropped by cap", dropped);
      if (prov_req) {
        o << cov_tag("external provider requests", prov_req);
        if (prov_fail) o << cov_tag("provider failures", prov_fail);
      }
      o << "</div>";
    }
    o << "</div>\n";

    o << "</section>\n";

    // находки
    o << "<section id=\"findings\">\n<header><h2>Findings <span class=\"cnt num\">"
      << total << "</span></h2>"
      << "<span class=\"small muted\">sorted by severity</span></header>\n";

    o << "<div class=\"toolbar\" role=\"group\" aria-label=\"Findings filters\">\n";
    o << "<button type=\"button\" class=\"sevbtn active\" data-f=\"all\" aria-pressed=\"true\">All <span class=\"n num\">"
      << total << "</span></button>";
    for (Severity s : {Severity::Critical, Severity::High, Severity::Medium,
                       Severity::Low, Severity::Info}) {
      o << "<button type=\"button\" class=\"sevbtn f-" << severity_key(s)
        << "\" data-f=\"" << severity_key(s) << "\" aria-pressed=\"false\">"
        << severity_name(s) << " <span class=\"n num\">" << counts[s]
        << "</span></button>";
    }
    o << "<select id=\"f-mod\" aria-label=\"Filter by module\"><option value=\"\">module: all</option>";
    for (const auto& m : modules)
      o << "<option value=\"" << html_escape(m) << "\">" << html_escape(m) << "</option>";
    o << "</select>\n<select id=\"f-host\" aria-label=\"Filter by host\"><option value=\"\">host: all</option>";
    for (const auto& h : hosts_seen)
      o << "<option value=\"" << html_escape(h) << "\">" << html_escape(h) << "</option>";
    o << "</select>\n"
      << "<input id=\"f-q\" type=\"search\" placeholder=\"Filter findings… (text search)\" aria-label=\"Text filter\">"
      << "<span class=\"cnt\" id=\"f-cnt\" aria-live=\"polite\"></span>"
      << "<button type=\"button\" class=\"toolbtn\" data-fold=\"open\" data-scope=\"findings\">Expand all</button>"
      << "<button type=\"button\" class=\"toolbtn\" data-fold=\"close\" data-scope=\"findings\">Collapse all</button>"
      << "</div>\n";

    if (r.findings.empty()) {
      if (!r.hosts.empty() && total == 0) {
        o << "<div class=\"allclean\"><div class=\"big\">No findings.</div>"
          << "<p class=\"small muted\" style=\"margin:0\">mikto ran "
          << r.modules_run.size() << " modules and observed no issues to report. "
             "This is an observation, not a guarantee — see the full inventory below.</p></div>\n";
      } else {
        o << "<div class=\"noresults\">No data. The scan could not reach the "
             "target — check the console output and the Traffic section.</div>\n";
      }
    }
    for (const auto& f : r.findings) {
      o << "<article class=\"finding f-" << severity_key(f.severity)
        << "\" data-sev=\"" << severity_key(f.severity)
        << "\" data-mod=\"" << html_escape(f.module)
        << "\" data-host=\"" << html_escape(f.host) << "\">\n";
      o << "<div class=\"head\">" << chip(f.severity)
        << "<span class=\"title\">" << html_escape(f.title) << "</span></div>\n";
      o << "<div class=\"fmeta\">"
        << "<span>module <b>" << html_escape(f.module) << "</b></span>";
      if (!f.host.empty()) o << "<span>host <b>" << html_escape(f.host) << "</b></span>";
      if (f.port > 0) o << "<span>port <b class=\"num\">" << f.port << "</b></span>";
      if (!f.service.empty()) o << "<span>service <b>" << html_escape(f.service) << "</b></span>";
      if (!f.location.empty()) o << "<span>location <b>" << html_escape(f.location) << "</b></span>";
      o << "</div>\n";
      if (!f.detail.empty()) o << "<div class=\"body\">" << html_escape(f.detail) << "</div>\n";
      if (!f.recommendation.empty())
        o << "<div class=\"rec\"><b>Recommendation&nbsp;·</b> " << html_escape(f.recommendation)
          << "</div>\n";
      if (!f.evidence.empty())
        o << "<details><summary>evidence</summary><pre><code>" << html_escape(f.evidence)
          << "</code></pre></details>\n";
      if (!f.references.empty()) {
        o << "<div class=\"refs\"><span>references:</span>";
        for (const auto& ref : f.references) {
          if (starts_with(ref, "http"))
            o << "<a href=\"" << html_escape(ref) << "\" rel=\"noopener\">" << html_escape(ref) << "</a>";
          else
            o << tag(ref, starts_with(ref, "CVE-"));
        }
        o << "</div>\n";
      }
      o << "</article>\n";
    }
    o << "<div class=\"noresults\" id=\"f-none\" style=\"display:none\">No findings "
         "match the current filters. Clear a filter or extend the search text.</div>\n";
    o << "</section>\n";

    // хосты
    o << "<section id=\"hosts\">\n<header><h2>Hosts <span class=\"cnt num\">"
      << r.hosts.size() << "</span></h2>"
      << "<span class=\"small muted\"><button type=\"button\" class=\"toolbtn\" data-fold=\"open\" data-scope=\"hosts\">Expand all</button> "
      << "<button type=\"button\" class=\"toolbtn\" data-fold=\"close\" data-scope=\"hosts\">Collapse all</button></span></header>\n";
    if (r.hosts.empty()) {
      o << "<div class=\"noresults\">No host data was collected.</div>\n";
    }
    for (size_t i = 0; i < r.hosts.size(); ++i)
      o << host_section(r.hosts[i], i, host_findings);
    o << "</section>\n";

    // инфраструктура
    o << infra_section(r);

    // web
    o << web_section(r);
    // граф
    o << intel_section(r);
    // трафик
    o << traffic_section(r);
    // инфо о скане
    o << scaninfo_section(r, cfg);

    o << "</main>\n";
    o << "<footer><div class=\"wrap\"><b>Generated by mikto v" << MIKTO_VERSION
      << "</b> — external audit tool for <b>authorized</b> targets only. "
         "Findings are observations, not proofs of exploitability: verify before "
         "acting. Every value in this file is complete — nothing was sampled or "
         "cut. This report makes no network requests: it is a standalone document.</div></footer>\n";
    o << "</body>\n<script>\n" << kJs << "\n</script>\n</html>\n";

    std::ofstream f(path_, std::ios::trunc);
    if (!f) {
      err = "cannot open HTML report file: " + path_;
      return false;
    }
    f << o.str();
    if (!f) {
      err = "failed writing HTML report: " + path_;
      return false;
    }
    return true;
  }

 private:
  std::string path_;

  static std::string target_summary(const Config& cfg) {
    std::string out;
    for (size_t i = 0; i < cfg.targets.size(); ++i) {
      if (i) out += ", ";
      out += cfg.targets[i].original;
    }
    return out.empty() ? "-" : out;
  }

  static std::string navlink(const char* id, const char* label, bool current = false) {
    return std::string("<a href=\"#") + id + "\"" +
           (current ? " aria-current=\"true\"" : "") + ">" + label + "</a>";
  }

  static std::string cov_tag(const std::string& label, size_t n) {
    return "<span class=\"tag\">" + html_escape(label) + "&nbsp;·&nbsp;<b class=\"num\">" +
           std::to_string(n) + "</b></span>";
  }

  static std::string gauge_svg(const Risk& risk) {
    int r = 46, C = static_cast<int>(2 * 3.141592653589793 * r);
    int off = C * (100 - risk.score) / 100;
    std::ostringstream o;
    o << "<svg class=\"gauge num\" width=\"128\" height=\"128\" viewBox=\"0 0 120 120\" role=\"img\" "
      << "aria-label=\"Risk score " << risk.score << " of 100, grade " << risk.grade << "\">\n"
      << "<circle cx=\"60\" cy=\"60\" r=\"" << r << "\" fill=\"none\" stroke=\"var(--card-2)\" stroke-width=\"11\"/>\n"
      << "<circle cx=\"60\" cy=\"60\" r=\"" << r << "\" fill=\"none\" stroke=\"" << grade_color(risk.grade)
      << "\" stroke-width=\"11\" stroke-linecap=\"round\" stroke-dasharray=\"" << C
      << "\" stroke-dashoffset=\"" << off << "\" transform=\"rotate(-90 60 60)\"/>\n"
      << "<text x=\"60\" y=\"58\" text-anchor=\"middle\" font-size=\"28\" font-weight=\"700\" fill=\"var(--ink)\">"
      << risk.score << "</text>\n"
      << "<text x=\"60\" y=\"76\" text-anchor=\"middle\" font-size=\"11\" fill=\"var(--muted)\">of 100 · "
      << risk.grade << "</text>\n</svg>\n";
    return o.str();
  }

  static std::string verdict_headline(const std::map<Severity, int>& counts,
                                      int total, const Risk& risk) {
    std::ostringstream o;
    if (total == 0) return "No issues observed.";
    std::string w = risk.word;
    if (!w.empty()) w[0] = static_cast<char>(std::toupper(static_cast<unsigned char>(w[0])));
    o << w << " risk: ";
    bool first = true;
    for (Severity s : {Severity::Critical, Severity::High, Severity::Medium, Severity::Low}) {
      if (counts.at(s) > 0) {
        o << (first ? "" : ", ") << counts.at(s) << " " << severity_name(s);
        first = false;
      }
    }
    if (first) o << "only low/medium severity observations";
    o << " (" << total << " total)";
    return o.str();
  }

  static std::string verdict_body(const ScanResult& r) {
    std::ostringstream o;
    o << "mikto enumerated " << r.hosts.size() << " host" << (r.hosts.size() == 1 ? "" : "s")
      << " with " << r.modules_run.size() << " modules";
    int open_ports = 0;
    for (const auto& h : r.hosts)
      for (const auto& p : h.ports)
        if (p.open) ++open_ports;
    o << " and observed " << open_ports << " open port" << (open_ports == 1 ? "" : "s")
      << ". Counts include every check across every module.";
    return o.str();
  }

  static std::string visibility_panel(const ScanResult& r) {
    bool any_web = false;
    for (const auto& h : r.hosts)
      if (!h.scan_visibility.empty()) any_web = true;
    if (!any_web) return "";
    std::ostringstream o;
    std::vector<const HostResult*> degraded;
    for (const auto& h : r.hosts)
      if (h.scan_visibility == "degraded" || h.scan_visibility == "blocked")
        degraded.push_back(&h);
    if (degraded.empty()) {
      o << "<div class=\"vis v-full\" style=\"background:var(--ok-wash);border-color:color-mix(in oklab,var(--ok) 35%,var(--line))\">"
        << "<b>Scan visibility: full.</b> No WAF, anti-bot challenge or rate "
           "limiter interfered with the scan — results reflect the complete view "
           "mikto could obtain.</div>\n";
      return o.str();
    }
    bool blocked = false;
    for (auto* h : degraded)
      if (h->scan_visibility == "blocked") blocked = true;
    o << "<div class=\"vis " << (blocked ? "v-blocked" : "v-degraded") << "\">"
      << "<b>Scan visibility " << (blocked ? "blocked" : "degraded")
      << " on " << degraded.size() << " of " << r.hosts.size() << " hosts.</b> "
      << "A blocker stood between mikto and the target. mikto did NOT try to "
         "evade it; results below may be incomplete for these hosts.<ul>\n";
    for (auto* h : degraded) {
      o << "<li><b>" << html_escape(h->host) << "</b> — " << html_escape(h->scan_visibility);
      for (const auto& n : h->visibility_notes) o << " · " << html_escape(n);
      o << "</li>\n";
    }
    o << "</ul></div>\n";
    return o.str();
  }

  static std::string block_open(const std::string& title, const std::string& count,
                                bool open = false, const std::string& extra = "",
                                const std::string& copy_sel = "") {
    std::ostringstream o;
    o << "<details class=\"block\"" << (open ? " open" : "") << "><summary>"
      << "<span class=\"btitle\">" << html_escape(title) << "</span>";
    if (!count.empty())
      o << " <span class=\"bcount num\">" << html_escape(count) << "</span>";
    o << extra;
    if (!copy_sel.empty())
      o << "<span class=\"bopen\"><button type=\"button\" class=\"copybtn\" data-copy=\".\" data-copy-items=\""
        << copy_sel << "\" data-label=\"copy all\">copy all</button></span>";
    o << "<span class=\"bopen\" aria-hidden=\"true\">toggle</span></summary>\n<div class=\"bbody\">\n";
    return o.str();
  }
  static const char* block_close() { return "</div></details>\n"; }

  static std::string host_section(const HostResult& h, size_t idx,
                                  const std::map<std::string, int>& host_findings) {
    std::ostringstream o;
    auto fhit = host_findings.find(h.host);
    int fc = fhit == host_findings.end() ? 0 : fhit->second;
    int open_ports = 0;
    for (const auto& p : h.ports)
      if (p.open) ++open_ports;

    o << "<details class=\"host\" open id=\"host-" << idx << "\">\n<summary>"
      << "<span class=\"chev\" aria-hidden=\"true\">▸</span>"
      << "<span class=\"hname\">" << html_escape(h.host) << "</span>";
    if (h.is_ip) o << "<span class=\"tag\">IP</span>";
    for (const auto& ip : h.ips) o << tag(ip);
    if (h.geo.ok && !h.geo.country.empty()) o << tag(h.geo.country);
    if (h.geo.ok && !h.geo.asn.empty()) o << tag(h.geo.asn);
    if (!h.os_guess.empty()) o << tag(h.os_guess);
    if (!h.scan_visibility.empty() && h.scan_visibility != "full")
      o << tag("visibility: " + h.scan_visibility, h.scan_visibility == "blocked");
    o << "<span class=\"tag\">" << open_ports << "&nbsp;open</span>";
    if (fc) o << tag(std::to_string(fc) + " findings", true);
    if (!h.tech.empty()) o << tag(std::to_string(h.tech.size()) + " tech");
    if (!h.paths.empty()) o << tag(std::to_string(h.paths.size()) + " paths");
    if (!h.subdomains.empty())
      o << tag(std::to_string(h.subdomains.size()) + " subdomains");
    if (!h.dns_records.empty())
      o << tag(std::to_string(h.dns_records.size()) + " DNS");
    o << "</summary>\n<div class=\"hostbody\">\n";

    {
      std::string body;
      auto kv = [&](const std::string& k, const std::string& v) {
        if (v.empty()) return;
        body += "<dt>" + html_escape(k) + "</dt><dd>" + v + "</dd>";
      };
      if (h.geo.ok) {
        std::string v = html_escape(h.geo.country);
        if (!h.geo.region.empty() && h.geo.country.find(h.geo.region) == std::string::npos)
          v += ", " + html_escape(h.geo.region);
        if (!h.geo.city.empty()) v += ", " + html_escape(h.geo.city);
        kv("Geo", v);
        if (!h.geo.asn.empty()) kv("ASN", html_escape(h.geo.asn));
        if (!h.geo.org.empty()) kv("Network", html_escape(h.geo.org));
        std::ostringstream ll;
        ll << std::fixed << std::setprecision(4) << h.geo.lat << ", " << h.geo.lon;
        kv("Coordinates", "<span class=\"num mono\">" + ll.str() + "</span>");
      }
      if (!h.os_guess.empty()) kv("OS guess", html_escape(h.os_guess));
      if (h.wildcard_dns)
        kv("Wildcard DNS", "yes — *." + html_escape(h.host) + " resolves (wildcard zone)");
      if (h.dns_zone_transfer)
        kv("AXFR", "<b style=\"color:var(--high)\">zone transfer ALLOWED</b>");
      if (!h.scan_visibility.empty())
        kv("Scan visibility", html_escape(h.scan_visibility) + join_notes(h.visibility_notes));
      if (!body.empty())
        o << block_open("Overview", "", true) << "<dl class=\"kv\">" << body
          << "</dl>\n" << block_close();
    }

    if (!h.dns_records.empty()) {
      o << block_open("DNS records", std::to_string(h.dns_records.size()), true);
      o << "<div class=\"tablewrap\"><table><thead><tr><th scope=\"col\">Type</th>"
        << "<th scope=\"col\">Name</th><th scope=\"col\">Value</th>"
        << "<th scope=\"col\">TTL</th></tr></thead><tbody>";
      for (const auto& d : h.dns_records) {
        o << "<tr><td>" << tag(d.type) << "</td><td class=\"mono\">" << html_escape(d.name)
          << "</td><td class=\"mono\">" << html_escape(d.value)
          << "</td><td class=\"num\">" << d.ttl << "</td></tr>";
      }
      o << "</tbody></table></div>\n" << block_close();
    }

    if (h.whois.ok) {
      std::string body;
      auto kv = [&](const std::string& k, const std::string& v) {
        if (v.empty()) return;
        body += "<dt>" + html_escape(k) + "</dt><dd>" + v + "</dd>";
      };
      kv("Registrar", html_escape(h.whois.registrar));
      kv("Created", html_escape(h.whois.created));
      kv("Updated", html_escape(h.whois.updated));
      kv("Expires", html_escape(h.whois.expires));
      o << block_open("WHOIS", h.whois.registrar);
      o << "<dl class=\"kv\">" << body << "</dl>\n";
      if (!h.whois.nameservers.empty()) {
        o << "<p class=\"small muted\" style=\"margin:10px 0 4px\">Nameservers ("
          << h.whois.nameservers.size() << "):</p><div class=\"chips\">";
        for (const auto& ns : h.whois.nameservers) o << tag(ns);
        o << "</div>\n";
      }
      if (!h.whois.emails.empty()) {
        o << "<p class=\"small muted\" style=\"margin:10px 0 4px\">Contacts:</p><div class=\"chips\">";
        for (const auto& e : h.whois.emails) o << tag(e);
        o << "</div>\n";
      }
      o << block_close();
    }

    if (h.tls) {
      const TlsInfo& t = *h.tls;
      if (t.ok) {
        Severity exp_sev = Severity::Info;
        if (t.days_until_expiry < 0) exp_sev = Severity::Critical;
        else if (t.days_until_expiry < 15) exp_sev = Severity::High;
        else if (t.days_until_expiry < 30) exp_sev = Severity::Medium;
        o << block_open("TLS certificate", t.protocol, true);
        o << "<dl class=\"kv\">"
          << "<dt>Protocol</dt><dd class=\"mono\">" << html_escape(t.protocol) << "</dd>"
          << "<dt>Cipher</dt><dd class=\"mono\">" << html_escape(t.cipher) << "</dd>"
          << "<dt>Subject</dt><dd class=\"mono\">" << html_escape(t.subject) << "</dd>"
          << "<dt>Issuer</dt><dd class=\"mono\">" << html_escape(t.issuer) << "</dd>"
          << "<dt>Expires</dt><dd>" << dot(exp_sev) << "<span class=\"mono\">" << html_escape(t.not_after)
          << "</span> <span class=\"muted small\">(" << t.days_until_expiry << " days)</span></dd>"
          << (t.self_signed ? "<dt>Self-signed</dt><dd style=\"color:var(--high)\">yes</dd>" : "");
        if (!t.san_dns.empty()) {
          o << "</dl>\n<p class=\"small muted\" style=\"margin:10px 0 4px\">SAN ("
            << t.san_dns.size() << "):</p><div class=\"chips\">";
          for (const auto& s : t.san_dns) o << tag(s);
          o << "</div>\n";
        } else {
          o << "</dl>\n";
        }
        o << block_close();
      } else {
        o << block_open("TLS certificate", "error", false)
          << "<p class=\"small muted\" style=\"margin:0\">TLS handshake failed: "
          << html_escape(t.error) << "</p>\n" << block_close();
      }
    }

    if (open_ports) {
      o << block_open("Ports", std::to_string(open_ports) + " open", true);
      o << "<div class=\"tablewrap\"><table><thead><tr><th scope=\"col\">Port</th>"
        << "<th scope=\"col\">Service</th><th scope=\"col\">Product / version</th>"
        << "<th scope=\"col\">Probe</th><th scope=\"col\">Confidence</th>"
        << "<th scope=\"col\">OS clue</th><th scope=\"col\">Extra versions</th>"
        << "<th scope=\"col\">Banner</th></tr></thead><tbody>";
      for (const auto& p : h.ports) {
        if (!p.open) continue;
        std::string extra;
        for (const auto& ev : p.extra_versions)
          extra += (extra.empty() ? "" : ", ") + ev.first + "/" + ev.second;
        o << "<tr><td><b class=\"mono\">" << p.port << "</b></td>"
          << "<td>" << tag(p.service) << "</td>"
          << "<td class=\"mono\">" << html_escape(p.service_label()) << "</td>"
          << "<td>" << tag(p.probe.empty() ? p.service : p.probe) << "</td>"
          << "<td><span class=\"conf c" << p.confidence << "\">"
          << p.confidence_label() << "</span></td>"
          << "<td>" << (p.os_clue.empty() ? "<span class=\"muted\">—</span>" : tag(p.os_clue))
          << "</td><td class=\"mono\">" << (extra.empty() ? "<span class=\"muted\">—</span>" : html_escape(extra))
          << "</td><td class=\"mono\">" << (p.banner.empty() ? "<span class=\"muted\">—</span>" : html_escape(p.banner))
          << "</td></tr>";
      }
      o << "</tbody></table></div>\n" << block_close();
    }

    if (!h.tech.empty()) {
      o << block_open("Technologies", std::to_string(h.tech.size()), true);
      o << "<div class=\"tablewrap\"><table><thead><tr><th scope=\"col\">Name</th>"
        << "<th scope=\"col\">Version</th><th scope=\"col\">Detected via</th>"
        << "</tr></thead><tbody>";
      for (const auto& t : h.tech) {
        o << "<tr><td><b>" << html_escape(t.name) << "</b></td><td class=\"mono\">"
          << (t.version.empty() ? "<span class=\"muted\">—</span>" : html_escape(t.version))
          << "</td><td class=\"mono\">" << html_escape(t.source) << "</td></tr>";
      }
      o << "</tbody></table></div>\n" << block_close();
    }

    if (!h.paths.empty()) {
      o << block_open("Web paths", std::to_string(h.paths.size()), false,
                      "", "#host-" + std::to_string(idx) + " .purl");
      o << "<div class=\"tablewrap cv-auto\"><table><thead><tr><th scope=\"col\">Path</th>"
        << "<th scope=\"col\">Status</th><th scope=\"col\">Size</th>"
        << "<th scope=\"col\">Found via</th></tr></thead><tbody>";
      for (const auto& p : h.paths) {
        o << "<tr><td class=\"mono purl\">" << html_escape(p.path) << "</td>"
          << "<td><span class=\"statuscode " << status_class(p.status) << "\">" << p.status
          << "</span></td><td class=\"num\">" << fmt_size(p.size) << "</td>"
          << "<td><span class=\"tag pathsrc\">" << html_escape(path_source_label(p.source))
          << "</span></td></tr>";
      }
      o << "</tbody></table></div>\n" << block_close();
    }

    if (!h.subdomains.empty()) {
      o << block_open("Subdomains", std::to_string(h.subdomains.size()), false, "",
                      "#host-" + std::to_string(idx) + " .subtags .tag");
      o << "<div class=\"chips subtags\">";
      for (const auto& s : h.subdomains) o << tag(s);
      o << "</div>\n" << block_close();
    }

    if (!h.emails.empty()) {
      o << block_open("Emails", std::to_string(h.emails.size()), false, "",
                      "#host-" + std::to_string(idx) + " .emtags .tag");
      o << "<div class=\"chips emtags\">";
      for (const auto& e : h.emails) o << tag(e);
      o << "</div>\n" << block_close();
    }

    if (!h.neighbors.empty()) {
      o << block_open("Neighbors on same IP", std::to_string(h.neighbors.size()), false);
      o << "<div class=\"chips\">";
      for (const auto& s : h.neighbors) o << tag(s);
      o << "</div>\n" << block_close();
    }

    {
      std::string body;
      if (!h.reputation.empty()) {
        body += "<p class=\"small muted\" style=\"margin:0 0 6px\">Reputation:</p><div class=\"chips\">";
        for (const auto& rep : h.reputation) body += tag(rep, true);
        body += "</div>";
      }
      if (!h.infra_tags.empty()) {
        body += "<p class=\"small muted\" style=\"margin:10px 0 6px\">Infrastructure tags:</p><div class=\"chips\">";
        for (const auto& t : h.infra_tags) body += tag(t);
        body += "</div>";
      }
      if (!h.shodan_cpes.empty()) {
        body += "<p class=\"small muted\" style=\"margin:10px 0 6px\">CPE identifiers ("
                + std::to_string(h.shodan_cpes.size()) + "):</p><div class=\"chips\">";
        for (const auto& c : h.shodan_cpes) body += tag(c);
        body += "</div>";
      }
      if (!body.empty())
        o << block_open("Reputation &amp; infrastructure", "", false) << body << block_close();
    }

    o << "</div>\n</details>\n";
    return o.str();
  }

  static std::string join_notes(const std::vector<std::string>& notes) {
    if (notes.empty()) return "";
    std::string out = " — ";
    for (size_t i = 0; i < notes.size(); ++i) {
      if (i) out += "; ";
      out += html_escape(notes[i]);
    }
    return out;
  }

  // инфраструктура из dns/geo/whois/reverse-ip, без доп. запросов
  static std::string infra_section(const ScanResult& r) {
    struct IpRow {
      std::string subnet;
      std::set<std::string> own;  // in-scope names resolving here
      std::set<std::string> nb;   // co-hosted neighbours (passive, possible)
      std::string asn, org, loc;
      bool geo_ok = false;
      std::vector<std::string> tags;
    };
    std::map<std::string, IpRow> rows;
    std::map<std::string, std::set<std::string>> ns_map, mx_map;

    auto strip_trailing_dot = [](std::string s) {
      while (!s.empty() && s.back() == '.') s.pop_back();
      return s;
    };

    for (const auto& h : r.hosts) {
      const std::string hname = to_lower(trim(h.host));
      for (const auto& ip : h.ips) {
        IpRow& row = rows[ip];
        row.own.insert(hname);
        if (!row.geo_ok && h.geo.ok) {
          row.geo_ok = true;
          row.asn = to_upper(trim(h.geo.asn));
          row.org = trim(h.geo.org);
          std::string loc = trim(h.geo.country);
          if (!h.geo.region.empty() &&
              loc.find(h.geo.region) == std::string::npos)
            loc += (loc.empty() ? "" : ", ") + h.geo.region;
          if (!h.geo.city.empty() && loc.find(h.geo.city) == std::string::npos)
            loc += (loc.empty() ? "" : ", ") + h.geo.city;
          row.loc = loc;
        }
        if (row.tags.empty() && !h.infra_tags.empty()) row.tags = h.infra_tags;
      }
      for (const auto& d : h.dns_records) {
        std::string name = to_lower(strip_trailing_dot(trim(d.name)));
        std::string v = to_lower(strip_trailing_dot(trim(d.value)));
        if ((d.type == "A" || d.type == "AAAA") && !v.empty()) {
          IpRow& row = rows[v];
          row.own.insert(name.empty() ? hname : name);
        } else if (d.type == "NS" && !v.empty()) {
          ns_map[v].insert(name);
        } else if (d.type == "MX" && !v.empty()) {
          std::string host = v;
          size_t sp = host.find(' ');
          if (sp != std::string::npos) host = trim(host.substr(sp + 1));
          if (!host.empty()) mx_map[host].insert(name);
        }
      }
      for (const auto& ns : h.whois.nameservers) {
        std::string v = to_lower(strip_trailing_dot(trim(ns)));
        if (!v.empty()) ns_map[v].insert(hname);
      }
      if (!h.neighbors.empty() && !h.ips.empty()) {
        IpRow& row = rows[h.ips.front()];
        for (const auto& nb : h.neighbors) {
          std::string nl = to_lower(strip_trailing_dot(trim(nb)));
          if (!nl.empty() && nl != hname) row.nb.insert(nl);
        }
      }
    }
    for (auto& [ip, row] : rows) row.subnet = ip_subnet(ip);

    std::map<std::string, std::set<std::string>> nets;  // ASN | org -> IPs
    std::map<std::string, std::string> net_org;
    for (const auto& [ip, row] : rows) {
      if (row.asn.empty() && row.org.empty()) continue;
      std::string key = !row.asn.empty() ? row.asn : "org:" + to_lower(row.org);
      nets[key].insert(ip);
      if (net_org[key].empty()) net_org[key] = row.org;
    }
    std::map<std::string, std::set<std::string>> subnets;
    for (const auto& [ip, row] : rows)
      if (!row.subnet.empty()) subnets[row.subnet].insert(ip);
    size_t n_nb = 0, n_multi_sub = 0;
    for (const auto& [ip, row] : rows) n_nb += row.nb.size();
    for (const auto& [sn, set] : subnets)
      if (set.size() >= 2) ++n_multi_sub;

    std::ostringstream o;
    o << "<section id=\"infra\">\n<header><h2>Infrastructure <span class=\"cnt num\">"
      << rows.size() << " server IP" << (rows.size() == 1 ? "" : "s")
      << " &middot; " << nets.size() << " network" << (nets.size() == 1 ? "" : "s")
      << " &middot; " << n_nb << " co-hosted</span></h2>"
      << "<span class=\"small muted\">server IPs, ASN / network ownership, "
         "same-segment neighbours and shared DNS — derived from DNS answers, "
         "the network-ownership lookup and passive reverse-IP sources</span></header>\n";
    if (rows.empty() && ns_map.empty() && mx_map.empty()) {
      o << "<div class=\"noresults\">No infrastructure data was collected — the "
           "scan produced no DNS answers and no resolved server IPs.</div>\n</section>\n";
      return o.str();
    }

    o << "<div class=\"chips\" style=\"margin-bottom:4px\">"
      << cov_tag("server IPs", rows.size());
    if (!nets.empty()) o << cov_tag("networks / ASNs", nets.size());
    if (n_nb) o << cov_tag("co-hosted domains", n_nb);
    if (n_multi_sub) o << cov_tag("shared subnets", n_multi_sub);
    if (!ns_map.empty()) o << cov_tag("nameservers", ns_map.size());
    if (!mx_map.empty()) o << cov_tag("mail exchangers", mx_map.size());
    o << "</div>\n";

    if (!rows.empty()) {
      std::vector<const std::string*> order;
      order.reserve(rows.size());
      for (const auto& [ip, row] : rows) order.push_back(&ip);
      std::sort(order.begin(), order.end(),
                [](const std::string* a, const std::string* b) {
                  return ip_sort_key(*a) < ip_sort_key(*b);
                });
      o << "<div class=\"panel\"><h3>Server IPs</h3>"
        << "<p class=\"small muted\" style=\"margin:0 0 8px\">Every address the "
           "target's DNS answers pointed to. Solid chips are in-scope names; "
           "dashed chips are co-hosted neighbours from passive reverse-IP "
           "sources.</p>"
        << "<div class=\"tablewrap\"><table><thead><tr>"
        << "<th scope=\"col\">Server IP</th><th scope=\"col\">Network</th>"
        << "<th scope=\"col\">Location</th><th scope=\"col\">Points to</th>"
        << "<th scope=\"col\">Subnet</th><th scope=\"col\">Tags</th>"
        << "</tr></thead><tbody>";
      for (const std::string* ipp : order) {
        const IpRow& row = rows[*ipp];
        o << "<tr><td><b class=\"mono\">" << html_escape(*ipp) << "</b></td>";
        if (!row.asn.empty() || !row.org.empty()) {
          o << "<td>";
          if (!row.asn.empty()) o << "<b>" << html_escape(row.asn) << "</b>";
          if (!row.org.empty())
            o << (row.asn.empty() ? "" : " ") << "<span class=\"muted small\">"
              << html_escape(row.org) << "</span>";
          o << "</td>";
        } else {
          o << "<td><span class=\"muted\">—</span></td>";
        }
        o << "<td class=\"small\">"
          << (row.loc.empty() ? std::string("<span class=\"muted\">—</span>")
                              : html_escape(row.loc))
          << "</td><td>";
        if (row.own.empty() && row.nb.empty()) {
          o << "<span class=\"muted\">—</span>";
        } else {
          o << "<div class=\"chips\">";
          for (const auto& d : row.own)
            o << "<span class=\"tag own\">" << html_escape(d) << "</span>";
          for (const auto& d : row.nb)
            o << "<span class=\"tag nb\" title=\"co-hosted neighbour (possible, "
                 "not confirmed)\">" << html_escape(d) << "</span>";
          o << "</div>";
        }
        o << "</td><td class=\"mono\">"
          << (row.subnet.empty() ? std::string("<span class=\"muted\">—</span>")
                                 : html_escape(row.subnet))
          << "</td><td>";
        if (row.tags.empty()) {
          o << "<span class=\"muted\">—</span>";
        } else {
          o << "<div class=\"chips\">";
          for (const auto& t : row.tags) o << tag(t);
          o << "</div>";
        }
        o << "</td></tr>";
      }
      o << "</tbody></table></div></div>\n";
    }

    if (!nets.empty()) {
      o << "<div class=\"panel\"><h3>Networks &amp; providers</h3>"
        << "<p class=\"small muted\" style=\"margin:0 0 8px\">Who owns the "
           "address space the targets sit in (ASN from the network-ownership "
           "lookup — probable, third-party data).</p><div class=\"asncards\">";
      for (const auto& [key, ips] : nets) {
        size_t doms = 0;
        for (const auto& ip : ips) {
          auto it = rows.find(ip);
          if (it != rows.end())
            doms += it->second.own.size() + it->second.nb.size();
        }
        const std::string& org = net_org[key];
        o << "<div class=\"asncard\"><h4 class=\"mono\">" << html_escape(key)
          << (org.empty() ? ""
                          : " <span class=\"muted\" style=\"font-weight:500\">" +
                                html_escape(org) + "</span>")
          << "</h4><p class=\"small muted\">" << ips.size() << " IP"
          << (ips.size() == 1 ? "" : "s") << " &middot; " << doms << " name"
          << (doms == 1 ? "" : "s") << "</p><div class=\"chips\">";
        for (const auto& ip : ips)
          o << "<span class=\"tag mono\">" << html_escape(ip) << "</span>";
        o << "</div></div>";
      }
      o << "</div></div>\n";
    }

    {
      bool any = false;
      for (const auto& [sn, set] : subnets)
        if (set.size() >= 2) any = true;
      o << "<div class=\"panel\"><h3>Same-network proximity</h3>";
      if (any) {
        o << "<p class=\"small muted\" style=\"margin:0 0 8px\">Server IPs "
             "sharing one segment (IPv4: same /24, IPv6: same /64) — likely the "
             "same provider block or hosting cage; they typically share "
             "provider-level fate.</p>"
          << "<div class=\"tablewrap\"><table><thead><tr>"
          << "<th scope=\"col\">Segment</th><th scope=\"col\">Server IPs</th>"
          << "<th scope=\"col\">Names on the segment</th></tr></thead><tbody>";
        for (const auto& [sn, set] : subnets) {
          if (set.size() < 2) continue;
          std::set<std::string> names;
          for (const auto& ip : set) {
            auto it = rows.find(ip);
            if (it == rows.end()) continue;
            names.insert(it->second.own.begin(), it->second.own.end());
            names.insert(it->second.nb.begin(), it->second.nb.end());
          }
          o << "<tr><td><b class=\"mono\">" << html_escape(sn) << "</b></td>"
            << "<td><div class=\"chips\">";
          for (const auto& ip : set)
            o << "<span class=\"tag mono\">" << html_escape(ip) << "</span>";
          o << "</div></td><td><div class=\"chips\">";
          for (const auto& d : names)
            o << "<span class=\"tag\">" << html_escape(d) << "</span>";
          o << "</div></td></tr>";
        }
        o << "</tbody></table></div>\n";
      } else if (!rows.empty()) {
        o << "<p class=\"small muted\" style=\"margin:0\">No two server IPs "
             "share a /24 or /64 segment — no same-segment neighbours were "
             "observed for these addresses.</p>";
      } else {
        o << "<p class=\"small muted\" style=\"margin:0\">No resolved server "
             "IPs — nothing to correlate by segment.</p>";
      }
      o << "</div>\n";
    }

    {
      o << "<div class=\"panel\"><h3>Co-hosted domains</h3>";
      if (n_nb) {
        o << "<p class=\"small muted\" style=\"margin:0 0 8px\">Other names "
             "served from the same IP as the target (passive reverse-IP "
             "sources — possible, not confirmed). On shared hosting a "
             "compromise of any neighbour can spill over: same kernel, same "
             "network, sometimes the same panel.</p>"
          << "<div class=\"tablewrap\"><table><thead><tr>"
          << "<th scope=\"col\">Server IP</th>"
          << "<th scope=\"col\">Co-hosted domains</th>"
          << "<th scope=\"col\">Count</th></tr></thead><tbody>";
        for (const auto& [ip, row] : rows) {
          if (row.nb.empty()) continue;
          o << "<tr><td><b class=\"mono\">" << html_escape(ip) << "</b></td>"
            << "<td><div class=\"chips\">";
          for (const auto& d : row.nb)
            o << "<span class=\"tag\">" << html_escape(d) << "</span>";
          o << "</div></td><td class=\"num\">" << row.nb.size() << "</td></tr>";
        }
        o << "</tbody></table></div>\n";
      } else {
        o << "<p class=\"small muted\" style=\"margin:0\">No co-hosted domains "
             "were reported for these IPs.</p>";
      }
      o << "</div>\n";
    }

    if (!ns_map.empty() || !mx_map.empty()) {
      o << "<div class=\"panel\"><h3>Shared DNS infrastructure</h3>"
        << "<p class=\"small muted\" style=\"margin:0 0 8px\">Nameservers and "
           "mail exchangers serving more than one in-scope name hint at shared "
           "or provider-hosted DNS/mail infrastructure.</p>"
        << "<div class=\"tablewrap\"><table><thead><tr>"
        << "<th scope=\"col\">Server</th><th scope=\"col\">Kind</th>"
        << "<th scope=\"col\">Serves</th><th scope=\"col\">Shared</th>"
        << "</tr></thead><tbody>";
      auto srv_row = [&](const std::string& server,
                         const std::set<std::string>& doms, const char* kind) {
        o << "<tr><td><b class=\"mono\">" << html_escape(server) << "</b></td>"
          << "<td>" << tag(kind) << "</td><td><div class=\"chips\">";
        for (const auto& d : doms)
          o << "<span class=\"tag\">" << html_escape(d) << "</span>";
        o << "</div></td><td>"
          << (doms.size() >= 2
                  ? tag("yes — " + std::to_string(doms.size()) + " names", true)
                  : "<span class=\"muted\">—</span>")
          << "</td></tr>";
      };
      for (const auto& [ns, doms] : ns_map) srv_row(ns, doms, "NS");
      for (const auto& [mx, doms] : mx_map) srv_row(mx, doms, "MX");
      o << "</tbody></table></div></div>\n";
    }

    o << "</section>\n";
    return o.str();
  }

  static std::string web_section(const ScanResult& r) {
    std::ostringstream o;
    o << "<section id=\"web\">\n<header><h2>Web responses <span class=\"cnt num\">"
      << r.web.size() << "</span></h2><span class=\"small muted\">every response, every header</span></header>\n";
    if (r.web.empty()) {
      o << "<div class=\"noresults\">No web responses recorded.</div>\n</section>\n";
      return o.str();
    }
    o << "<div class=\"tablewrap\"><table><thead><tr><th scope=\"col\">URL</th>"
      << "<th scope=\"col\">Status</th><th scope=\"col\">Server</th>"
      << "<th scope=\"col\">Content-Type</th>"
      << "<th scope=\"col\">Title</th></tr></thead><tbody>";
    for (const auto& w : r.web) {
      std::string ctype = w.header("content-type");
      if (!ctype.empty()) ctype = truncate_ellipsis(ctype, 48);
      o << "<tr><td class=\"mono\">" << html_escape(w.url) << "</td><td>"
        << (w.fetched ? "<span class=\"statuscode " + status_class(w.status) + "\">" +
                            std::to_string(w.status) + "</span>"
                      : "<span class=\"muted\">" + html_escape(w.error) + "</span>")
        << "</td><td class=\"mono\">" << (w.server.empty() ? "<span class=\"muted\">—</span>" : html_escape(w.server))
        << "</td><td class=\"mono\">"
        << (ctype.empty() ? "<span class=\"muted\">—</span>"
                          : "<span title=\"" + html_escape(w.header("content-type")) + "\">" +
                                html_escape(ctype) + "</span>")
        << "</td><td>" << (w.title.empty() ? "<span class=\"muted\">—</span>" : html_escape(w.title))
        << "</td></tr>";
    }
    o << "</tbody></table></div>\n";
    o << security_headers_matrix(r);
    for (size_t i = 0; i < r.web.size(); ++i) {
      const auto& w = r.web[i];
      if (!w.fetched || w.headers.empty()) continue;
      o << block_open("Headers: " + w.url, std::to_string(w.headers.size()) + " headers", false);
      o << "<div class=\"tablewrap\"><table><thead><tr><th scope=\"col\">Header</th>"
        << "<th scope=\"col\">Value</th></tr></thead><tbody>";
      for (const auto& hd : w.headers)
        o << "<tr><td class=\"mono\"><b>" << html_escape(hd.first) << "</b></td><td class=\"mono\">"
          << html_escape(hd.second) << "</td></tr>";
      o << "</tbody></table></div>\n" << block_close();
    }
    o << "</section>\n";
    return o.str();
  }

  // матрица security-заголовков по ответам
  static std::string security_headers_matrix(const ScanResult& r) {
    struct Hdr {
      const char* name;
      const char* label;
      const char* why;
    };
    static const Hdr kHdrs[] = {
        {"content-security-policy", "CSP",
         "Content-Security-Policy — constrains what the page may load/execute"},
        {"strict-transport-security", "HSTS",
         "Strict-Transport-Security — forces HTTPS for future visits"},
        {"x-frame-options", "X-Frame-Options",
         "X-Frame-Options — anti-clickjacking framing control"},
        {"x-content-type-options", "X-Content-Type-Options",
         "X-Content-Type-Options: nosniff — stops MIME sniffing"},
        {"referrer-policy", "Referrer-Policy",
         "Referrer-Policy — controls how much referrer data leaks"},
        {"permissions-policy", "Permissions-Policy",
         "Permissions-Policy — restricts powerful browser features"},
    };
    size_t rows = 0;
    for (const auto& w : r.web)
      if (w.fetched && !w.headers.empty()) ++rows;
    if (!rows) return "";
    std::ostringstream o;
    o << block_open("Security headers matrix", std::to_string(rows) + " URL" +
                                                    (rows == 1 ? "" : "s"),
                    true);
    o << "<p class=\"small muted\" style=\"margin:0 0 10px\">✓ = header sent "
         "(hover for the value) · ✗ = not observed on that response.</p>";
    o << "<div class=\"tablewrap\"><table class=\"matrix\"><thead><tr><th scope=\"col\">URL</th>";
    for (const auto& h : kHdrs)
      o << "<th scope=\"col\"><abbr title=\"" << h.why << "\">" << h.label
        << "</abbr></th>";
    o << "<th scope=\"col\">Score</th></tr></thead><tbody>";
    for (const auto& w : r.web) {
      if (!w.fetched || w.headers.empty()) continue;
      int have = 0;
      std::string cells;
      for (const auto& h : kHdrs) {
        std::string v = w.header(h.name);
        if (!v.empty()) {
          ++have;
          cells += "<td><span class=\"hok\" title=\"" + html_escape(h.name) + ": " +
                   html_escape(truncate_ellipsis(v, 140)) + "\">✓</span></td>";
        } else {
          cells += "<td><span class=\"hmiss\" title=\"" + html_escape(h.name) +
                   " not sent\">✗</span></td>";
        }
      }
      o << "<tr><td class=\"mono\">" << html_escape(w.url) << "</td>" << cells
        << "<td class=\"num\">" << have << "/" << 6 << "</td></tr>";
    }
    o << "</tbody></table></div>\n" << block_close();
    return o.str();
  }

  // карта графа + таблицы, капы 2000/4000
  static std::string intel_section(const ScanResult& r) {
    const auto& nodes = r.intel.nodes();
    const auto& edges = r.intel.edges();
    std::ostringstream o;
    o << "<section id=\"correlations\">\n<header><h2>Correlations <span class=\"cnt num\">"
      << nodes.size() << " entities &middot; " << edges.size() << " relations</span></h2>"
      << "<span class=\"small muted\">correlated intelligence graph — every node carries "
         "its status and provenance</span></header>\n";
    if (nodes.empty()) {
      o << "<div class=\"noresults\">No intelligence graph for this scan — the "
           "scan produced no correlatable entities.</div>\n</section>\n";
      return o.str();
    }

    std::map<std::string, int> degree;
    for (const auto& e : edges) {
      ++degree[e.src];
      ++degree[e.dst];
    }
    constexpr size_t kMapNodes = 120;
    std::vector<std::pair<int, std::string>> ranked;  // (-degree, id)
    ranked.reserve(nodes.size());
    for (const auto& n : nodes) {
      auto it = degree.find(n.id);
      ranked.emplace_back(-(it == degree.end() ? 0 : it->second), n.id);
    }
    std::sort(ranked.begin(), ranked.end());
    std::set<std::string> in_map;
    for (size_t i = 0; i < ranked.size() && i < kMapNodes; ++i)
      in_map.insert(ranked[i].second);

    o << "<div class=\"tchips\" role=\"group\" aria-label=\"Focus the entity map "
         "on one entity type\">";
    for (const auto& [tk, tc] : r.intel.node_counts())
      o << "<button type=\"button\" class=\"tchip\" data-type=\"" << tk
        << "\" aria-pressed=\"false\" title=\"Click to highlight " << tk
        << " entities on the map\"><canvas class=\"ticon\" data-type=\"" << tk
        << "\" width=\"20\" height=\"20\" aria-hidden=\"true\"></canvas>"
        << html_escape(tk) << " <b class=\"num\">" << tc << "</b></button>";
    o << "</div>\n";

    o << "<div class=\"imapwrap\">"
      << "<div class=\"imapctrl\">"
      << "<button type=\"button\" data-imap=\"in\" aria-label=\"Zoom in\" title=\"Zoom in\">"
      << "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" aria-hidden=\"true\"><circle cx=\"11\" cy=\"11\" r=\"7\"/><path d=\"M21 21l-4.35-4.35M8 11h6M11 8v6\"/></svg></button>"
      << "<button type=\"button\" data-imap=\"out\" aria-label=\"Zoom out\" title=\"Zoom out\">"
      << "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" aria-hidden=\"true\"><circle cx=\"11\" cy=\"11\" r=\"7\"/><path d=\"M21 21l-4.35-4.35M8 11h6\"/></svg></button>"
      << "<button type=\"button\" data-imap=\"fit\" aria-label=\"Reset view\" title=\"Reset view (double-click the map works too)\">"
      << "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" aria-hidden=\"true\"><path d=\"M3 9V3h6M15 3h6v6M21 15v6h-6M9 21H3v-6\"/></svg></button>"
      << "</div>"
      << "<canvas id=\"intel-map\" role=\"img\" aria-label=\"Entity map of the "
         "intelligence graph — scroll to zoom, drag to pan\"></canvas>"
      << "<span class=\"imap-cap num\">";
    if (in_map.size() < nodes.size())
      o << "map: " << in_map.size() << " of " << nodes.size()
        << " entities (hubs first)";
    else
      o << "map: all " << nodes.size() << " entities";
    o << "</span>"
      << "<span class=\"imap-hint\">scroll = zoom &middot; drag = pan &middot; "
         "double-click = reset</span>"
      << "<div class=\"imap-tip\" id=\"imap-tip\"></div></div>\n";
    o << "<div class=\"legend\">";
    for (const char* st : {"confirmed", "probable", "possible", "unverified"})
      o << "<span><span class=\"sw st-" << st << "\" aria-hidden=\"true\"></span>"
        << st << "</span>";
    o << "<span class=\"muted\">· hover a node for provenance · click an entity "
         "row below to filter its relations</span></div>\n";

    constexpr size_t kMaxNodes = 2000, kMaxEdges = 4000;
    size_t nodes_shown = std::min(nodes.size(), kMaxNodes);
    std::set<std::string> types, statuses;
    for (const auto& n : nodes) {
      types.insert(node_type_key(n.type));
      statuses.insert(n.status);
    }
    o << block_open("Entities", std::to_string(nodes.size()) +
                                   (nodes_shown < nodes.size()
                                        ? " (showing " + std::to_string(nodes_shown) + ")"
                                        : ""),
                    true, "", "#intel-nodes .nval")
      << "<div class=\"fbar\">"
      << "<select id=\"n-type\" data-k=\"type\" aria-label=\"Filter entities by type\">"
         "<option value=\"\">type: all</option>";
    for (const auto& t : types) o << "<option value=\"" << t << "\">" << t << "</option>";
    o << "</select><select id=\"n-status\" data-k=\"status\" "
         "aria-label=\"Filter entities by status\"><option value=\"\">status: all</option>";
    for (const auto& st : statuses) o << "<option value=\"" << st << "\">" << st << "</option>";
    o << "</select><input id=\"n-q\" type=\"search\" data-k=\"text\" "
         "placeholder=\"Filter entities…\" aria-label=\"Entity text filter\">"
      << "<span class=\"cnt\" id=\"n-cnt\" aria-live=\"polite\"></span></div>\n";
    o << "<div class=\"tablewrap cv-auto\"><table id=\"intel-nodes\"><thead><tr>"
      << "<th scope=\"col\">Entity</th><th scope=\"col\">Type</th>"
      << "<th scope=\"col\">Status</th><th scope=\"col\">Confidence</th>"
      << "<th scope=\"col\">Sources (provenance)</th></tr></thead><tbody>";
    for (size_t i = 0; i < nodes_shown; ++i) {
      const GraphNode& n = nodes[i];
      auto dit = degree.find(n.id);
      int deg = dit == degree.end() ? 0 : dit->second;
      bool mapped = in_map.count(n.id) != 0;
      o << "<tr data-node=\"" << html_escape(n.id) << "\" data-type=\""
        << node_type_key(n.type) << "\" data-value=\"" << html_escape(n.value)
        << "\" data-status=\"" << html_escape(n.status) << "\" data-deg=\"" << deg
        << "\"" << (mapped ? " data-map=\"1\"" : "") << ">"
        << "<td class=\"mono\"><span class=\"nval\">" << html_escape(n.value)
        << "</span>"
        << (deg > 1 ? "&nbsp;<span class=\"muted num small\">×" + std::to_string(deg) + "</span>"
                    : "")
        << "</td><td>" << node_type_name(n.type) << "</td><td>"
        << status_chip(n.status) << "</td><td class=\"num\">" << conf_cell(n.confidence)
        << "</td><td>";
      for (size_t s = 0; s < n.sources.size(); ++s)
        o << (s ? " " : "") << tag(n.sources[s]);
      o << "</td></tr>";
    }
    o << "</tbody></table></div>\n";
    if (nodes_shown < nodes.size())
      o << "<p class=\"small muted\" style=\"margin:8px 0 0\">Showing "
        << nodes_shown << " of " << nodes.size() << " entities (report cap) — "
        << "the full set is in the JSON report.</p>\n";
    o << "<div class=\"noresults\" id=\"n-none\" style=\"display:none\">No entities "
         "match the filters.</div>\n";
    o << block_close();

    size_t edges_shown = std::min(edges.size(), kMaxEdges);
    std::set<std::string> rels;
    for (const auto& e : edges) rels.insert(e.relation);
    o << "<details class=\"block\" id=\"intel-edges-block\"><summary>"
      << "<span class=\"btitle\">Relations</span> <span class=\"bcount num\">"
      << edges.size() << (edges_shown < edges.size()
                              ? " (showing " + std::to_string(edges_shown) + ")"
                              : "")
      << "</summary>\n<div class=\"bbody\">\n";
    o << "<div class=\"fbar\">"
      << "<select id=\"e-rel\" data-k=\"rel\" aria-label=\"Filter relations by type\">"
         "<option value=\"\">relation: all</option>";
    for (const auto& rl : rels) o << "<option value=\"" << rl << "\">" << rel_label(rl) << "</option>";
    o << "</select><input id=\"e-q\" type=\"search\" data-k=\"text\" "
         "placeholder=\"Filter relations… (click an entity above)\" "
         "aria-label=\"Relation text filter\">"
      << "<span class=\"cnt\" id=\"e-cnt\" aria-live=\"polite\"></span></div>\n";
    o << "<div class=\"tablewrap cv-auto\"><table id=\"intel-edges\"><thead><tr>"
      << "<th scope=\"col\">From</th><th scope=\"col\">Relation</th>"
      << "<th scope=\"col\">To</th><th scope=\"col\">Status</th>"
      << "<th scope=\"col\">Confidence</th><th scope=\"col\">Evidence</th>"
      << "<th scope=\"col\">Sources</th></tr></thead><tbody>";
    for (size_t i = 0; i < edges_shown; ++i) {
      const GraphEdge& e = edges[i];
      bool mapped = in_map.count(e.src) && in_map.count(e.dst);
      o << "<tr data-edge=\"1\" data-src=\"" << html_escape(e.src) << "\" data-dst=\""
        << html_escape(e.dst) << "\" data-rel=\"" << html_escape(e.relation)
        << "\" data-status=\"" << html_escape(e.status) << "\""
        << (mapped ? " data-map=\"1\"" : "") << ">"
        << "<td class=\"mono\">" << html_escape(node_short(e.src)) << "</td>"
        << "<td>" << tag(rel_label(e.relation)) << "</td>"
        << "<td class=\"mono\">" << html_escape(node_short(e.dst)) << "</td>"
        << "<td>" << status_chip(e.status) << "</td>"
        << "<td class=\"num\">" << conf_cell(e.confidence) << "</td>"
        << "<td class=\"small\">"
        << (e.evidence.empty() ? "<span class=\"muted\">—</span>"
                               : html_escape(truncate_ellipsis(e.evidence, 220)))
        << "</td><td>";
      for (size_t s = 0; s < e.sources.size(); ++s)
        o << (s ? " " : "") << tag(e.sources[s]);
      o << "</td></tr>";
    }
    o << "</tbody></table></div>\n";
    if (edges_shown < edges.size())
      o << "<p class=\"small muted\" style=\"margin:8px 0 0\">Showing "
        << edges_shown << " of " << edges.size() << " relations (report cap) — "
        << "the full set is in the JSON report.</p>\n";
    o << "<div class=\"noresults\" id=\"e-none\" style=\"display:none\">No relations "
         "match the filters.</div>\n";
    o << "</div>\n</details>\n";
    o << "</section>\n";
    return o.str();
  }

  static std::string traffic_section(const ScanResult& r) {
    auto traffic = r.traffic_snapshot();
    std::ostringstream o;
    o << "<section id=\"traffic\">\n<header><h2>Traffic <span class=\"cnt num\">"
      << traffic.size() << "</span></h2><span class=\"small muted\">what mikto sent, what came back — complete log</span></header>\n";
    if (traffic.empty()) {
      o << "<div class=\"noresults\">No traffic recorded (run with --trace to capture it).</div>\n</section>\n";
      return o.str();
    }
    size_t dropped = r.trace_dropped_count();
    if (dropped) {
      o << "<div class=\"vis v-degraded\" style=\"margin-top:0;margin-bottom:10px\">"
        << "<b>Trace buffer capped.</b> Showing " << traffic.size() << " of "
        << (traffic.size() + dropped) << " events — " << dropped
        << " were dropped by the in-memory cap on this large scan. Kind totals "
           "below still count what was captured; the boundary is stated, not hidden.</div>\n";
    }
    auto kinds = r.trace_counts();
    o << "<div class=\"chips\" style=\"margin-bottom:10px\">";
    for (auto& kv : kinds)
      o << "<span class=\"tag\"><b class=\"num\">" << kv.second << "</b>&nbsp;" << html_escape(kv.first) << "</span>";
    o << "</div>\n";
    {
      std::vector<const TrafficEvent*> slow;
      for (const auto& e : traffic)
        if (e.ms > 0) slow.push_back(&e);
      std::stable_sort(slow.begin(), slow.end(),
                       [](const TrafficEvent* a, const TrafficEvent* b) {
                         return a->ms > b->ms;
                       });
      if (slow.size() >= 3) {
        o << "<div class=\"panel\"><h3>Slowest round-trips</h3>"
          << "<p class=\"small muted\" style=\"margin:0 0 8px\">Top "
          << std::min<size_t>(slow.size(), 5) << " by response time — useful for "
             "spotting rate limiting or overloaded services.</p><ol class=\"tops\">";
        for (size_t i = 0; i < slow.size() && i < 5; ++i) {
          const TrafficEvent& e = *slow[i];
          o << "<li><div><span class=\"num\"><b>" << fmt_ms(e.ms)
            << " ms</b></span> — <span class=\"mono\">" << html_escape(truncate_ellipsis(e.request, 90))
            << "</span><div class=\"small muted\">→ " << html_escape(truncate_ellipsis(e.response, 110))
            << " · module " << html_escape(e.module) << "</div></div>"
            << "<span class=\"tag num\">" << fmt_ms(e.ms) << "</span></li>\n";
        }
        o << "</ol></div>\n";
      }
    }
    o << "<div class=\"tablewrap cv-auto\"><table><thead><tr><th scope=\"col\">#</th>"
      << "<th scope=\"col\">Module</th><th scope=\"col\">Kind</th><th scope=\"col\">Target</th>"
      << "<th scope=\"col\">Request</th><th scope=\"col\">Response</th>"
      << "<th scope=\"col\">Status</th><th scope=\"col\">Bytes</th><th scope=\"col\">ms</th></tr></thead><tbody>";
    for (size_t i = 0; i < traffic.size(); ++i) {
      const TrafficEvent& e = traffic[i];
      o << "<tr><td class=\"num muted\">" << i + 1 << "</td>"
        << "<td>" << tag(e.module) << "</td><td>" << tag(e.kind)
        << "</td><td class=\"mono\">" << html_escape(e.target)
        << "</td><td class=\"mono\">" << html_escape(e.request)
        << "</td><td class=\"mono\">" << html_escape(e.response)
        << "</td><td><span class=\"statuscode " << status_class(e.status) << "\">"
        << (e.status ? std::to_string(e.status) : "—") << "</span></td>"
        << "<td class=\"num\">" << (e.sent || e.recv ? fmt_size(e.sent) + " → " + fmt_size(e.recv) : "—")
        << "</td><td class=\"num\">" << fmt_ms(e.ms) << "</td></tr>";
    }
    o << "</tbody></table></div>\n</section>\n";
    return o.str();
  }

  static std::string scaninfo_section(const ScanResult& r, const Config& cfg) {
    std::ostringstream o;
    o << "<section id=\"scaninfo\">\n<header><h2>Scan info</h2>"
      << "<span class=\"small muted\">configuration and module timings</span></header>\n";
    o << "<div class=\"panel\"><h3>Targets</h3><div class=\"chips\">";
    for (const auto& t : cfg.targets) o << tag(t.original);
    o << "</div></div>\n";
    o << "<div class=\"panel\"><h3>Modules run <span class=\"muted num\">"
      << r.modules_run.size() << "</span></h3>\n<div class=\"tablewrap\"><table>"
      << "<thead><tr><th scope=\"col\">Module</th><th scope=\"col\">Duration</th>"
      << "</tr></thead><tbody>";
    for (const auto& m : r.modules_run) {
      std::string dur = "—";
      auto it = r.module_timings.find(m);
      if (it != r.module_timings.end())
        dur = fmt_ms(it->second * 1000.0) + " ms";
      o << "<tr><td>" << tag(m) << "</td><td class=\"num\">" << dur << "</td></tr>";
    }
    o << "</tbody></table></div></div>\n";
    if (!r.provider_stats.empty()) {
      o << "<div class=\"panel\"><h3>External providers <span class=\"muted num\">"
        << r.provider_stats.size() << "</span></h3>"
        << "<p class=\"small muted\" style=\"margin:0 0 8px\">Per-source request "
           "accounting and circuit-breaker state at scan end — a degraded "
           "provider means the affected sections may be incomplete.</p>"
        << "<div class=\"tablewrap\"><table><thead><tr><th scope=\"col\">Provider</th>"
        << "<th scope=\"col\">Requests</th><th scope=\"col\">OK</th>"
        << "<th scope=\"col\">Failed</th><th scope=\"col\">Blocked</th>"
        << "<th scope=\"col\">Breaker trips</th><th scope=\"col\">End state</th>"
        << "</tr></thead><tbody>";
      for (const auto& [phost, st] : r.provider_stats) {
        std::string state;
        if (st.circuit_open)
          state = "<span class=\"chip ch-critical\">circuit open</span>";
        else if (st.capped)
          state = "<span class=\"chip ch-medium\">cap reached</span>";
        else if (st.failures > 0)
          state = "<span class=\"chip ch-high\">degraded</span>";
        else
          state = "<span class=\"chip ch-info\">healthy</span>";
        o << "<tr><td><b>" << html_escape(st.name.empty() ? phost : st.name)
          << "</b>" << (st.name.empty() ? "" : " <span class=\"muted mono small\">" +
                                                   html_escape(phost) + "</span>")
          << "</td><td class=\"num\">" << st.allowed << "</td><td class=\"num\">"
          << st.successes << "</td><td class=\"num\">"
          << (st.failures ? std::to_string(st.failures) : "0") << "</td><td class=\"num\">"
          << (st.blocked ? std::to_string(st.blocked) : "0") << "</td><td class=\"num\">"
          << st.circuit_trips << "</td><td>" << state << "</td></tr>";
      }
      o << "</tbody></table></div></div>\n";
    }
    o << "<div class=\"panel\"><h3>Settings</h3><dl class=\"kv\">"
      << "<dt>Mode</dt><dd>" << (r.deep ? "deep" : "safe") << "</dd>"
      << "<dt>Safe mode</dt><dd>" << (r.safe_mode ? "enabled — destructive checks skipped" : "disabled") << "</dd>"
      << "<dt>Started</dt><dd class=\"mono\">" << html_escape(r.started_at) << "</dd>"
      << "<dt>Finished</dt><dd class=\"mono\">" << html_escape(r.finished_at) << "</dd>"
      << "<dt>Duration</dt><dd class=\"num\">" << html_escape(format_duration(r.duration_s)) << "</dd>"
      << "<dt>mikto</dt><dd class=\"mono\">v" << MIKTO_VERSION << "</dd>"
      << "</dl></div>\n</section>\n";
    return o.str();
  }
};

}  // namespace

std::unique_ptr<IReporter> make_html_reporter(const std::string& path) {
  return std::make_unique<HtmlReporter>(path);
}

}  // namespace mikto
