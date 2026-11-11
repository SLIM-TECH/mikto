// diff по секциям, каждое изменение с таймстампами обоих сканов
#include "mikto/scan_diff.hpp"

#include <algorithm>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <vector>

#include "mikto/util.hpp"

namespace mikto {

namespace {

using json = nlohmann::json;

int severity_rank(const std::string& s) {
  if (s == "critical") return 4;
  if (s == "high") return 3;
  if (s == "medium") return 2;
  if (s == "low") return 1;
  return 0;  // "info" and anything unknown
}

std::set<std::string> strings_of(const json& j, const char* key) {
  std::set<std::string> out;
  if (!j.contains(key) || !j.at(key).is_array()) return out;
  for (const auto& v : j.at(key))
    if (v.is_string()) out.insert(v.get<std::string>());
  return out;
}

// host -> values map for per-host string arrays.
std::map<std::string, std::set<std::string>> host_strings(
    const json& j, const char* key) {
  std::map<std::string, std::set<std::string>> out;
  if (!j.contains("hosts")) return out;
  for (const auto& h : j.at("hosts")) {
    if (!h.contains("host")) continue;
    std::string host = h.at("host").get<std::string>();
    out[host] = strings_of(h, key);
  }
  return out;
}

// "443 (nginx 1.25)"
std::map<std::string, std::map<int, std::string>> host_ports(const json& j) {
  std::map<std::string, std::map<int, std::string>> out;
  if (!j.contains("hosts")) return out;
  for (const auto& h : j.at("hosts")) {
    if (!h.contains("host") || !h.contains("ports")) continue;
    std::string host = h.at("host").get<std::string>();
    for (const auto& p : h.at("ports")) {
      if (!p.contains("port")) continue;
      int port = p.at("port").get<int>();
      std::string label;
      if (p.contains("product") && p.at("product").is_string() &&
          !p.at("product").get<std::string>().empty()) {
        label = p.at("product").get<std::string>();
        if (p.contains("version") && p.at("version").is_string() &&
            !p.at("version").get<std::string>().empty())
          label += " " + p.at("version").get<std::string>();
      } else if (p.contains("service") && p.at("service").is_string()) {
        label = p.at("service").get<std::string>();
      }
      out[host][port] = label;
    }
  }
  return out;
}

// name -> версия, первая побеждает
std::map<std::string, std::map<std::string, std::string>> host_tech(
    const json& j) {
  std::map<std::string, std::map<std::string, std::string>> out;
  if (!j.contains("hosts")) return out;
  for (const auto& h : j.at("hosts")) {
    if (!h.contains("host") || !h.contains("tech")) continue;
    std::string host = h.at("host").get<std::string>();
    for (const auto& t : h.at("tech")) {
      if (!t.contains("name") || !t.at("name").is_string()) continue;
      std::string name = to_lower(t.at("name").get<std::string>());
      std::string ver = t.contains("version") && t.at("version").is_string()
                            ? t.at("version").get<std::string>()
                            : std::string();
      auto& m = out[host];
      auto it = m.find(name);
      if (it == m.end()) m[name] = ver;
      else if (it->second.empty()) it->second = ver;
    }
  }
  return out;
}

// "type/name" -> значения
std::map<std::string, std::map<std::string, std::set<std::string>>>
host_dns(const json& j) {
  std::map<std::string, std::map<std::string, std::set<std::string>>> out;
  if (!j.contains("hosts")) return out;
  for (const auto& h : j.at("hosts")) {
    if (!h.contains("host") || !h.contains("dns_records")) continue;
    std::string host = h.at("host").get<std::string>();
    for (const auto& r : h.at("dns_records")) {
      if (!r.contains("type") || !r.contains("value")) continue;
      std::string k = r.at("type").get<std::string>() + "/" +
                      (r.contains("name") && r.at("name").is_string()
                           ? r.at("name").get<std::string>()
                           : std::string());
      out[host][k].insert(r.at("value").get<std::string>());
    }
  }
  return out;
}

// TLS cert identity: host -> "subject|issuer|not_after".
std::map<std::string, std::string> host_certs(const json& j) {
  std::map<std::string, std::string> out;
  if (!j.contains("hosts")) return out;
  for (const auto& h : j.at("hosts")) {
    if (!h.contains("host") || !h.contains("tls")) continue;
    const auto& t = h.at("tls");
    auto s = [&](const char* k) -> std::string {
      return t.contains(k) && t.at(k).is_string() ? t.at(k).get<std::string>()
                                                  : std::string();
    };
    out[h.at("host").get<std::string>()] =
        s("subject") + "|" + s("issuer") + "|" + s("not_after");
  }
  return out;
}

// Findings: "module|host|title" -> (severity, location).
std::map<std::string, std::pair<std::string, std::string>> finding_map(
    const json& j) {
  std::map<std::string, std::pair<std::string, std::string>> out;
  if (!j.contains("findings")) return out;
  for (const auto& f : j.at("findings")) {
    auto s = [&](const char* k) -> std::string {
      return f.contains(k) && f.at(k).is_string()
                 ? f.at(k).get<std::string>()
                 : std::string();
    };
    std::string key = s("module") + "|" + s("host") + "|" + s("title");
    out[key] = {s("severity"), s("location")};
  }
  return out;
}

void push(ScanDiffResult& d, const std::string& kind, const std::string& action,
          const std::string& entity, const std::string& detail,
          const std::string& severity) {
  DiffChange c;
  c.kind = kind;
  c.action = action;
  c.entity = entity.empty() ? "global" : entity;
  c.detail = detail;
  c.severity = severity;
  c.first_seen = action == "added" ? "" : d.old_started;
  c.last_seen = action == "removed" ? "" : d.new_started;
  d.changes.push_back(std::move(c));
}

// добавления и удаления по хостам
void diff_host_sets(ScanDiffResult& d, const std::string& kind,
                    const std::map<std::string, std::set<std::string>>& oldm,
                    const std::map<std::string, std::set<std::string>>& newm,
                    const std::string& added_sev,
                    const std::string& removed_sev) {
  std::set<std::string> hosts;
  for (const auto& kv : oldm) hosts.insert(kv.first);
  for (const auto& kv : newm) hosts.insert(kv.first);
  for (const std::string& host : hosts) {
    std::set<std::string> o, n;
    if (auto it = oldm.find(host); it != oldm.end()) o = it->second;
    if (auto it = newm.find(host); it != newm.end()) n = it->second;
    for (const std::string& v : n)
      if (!o.count(v)) push(d, kind, "added", host, v, added_sev);
    for (const std::string& v : o)
      if (!n.count(v)) push(d, kind, "removed", host, v, removed_sev);
  }
}

}  // namespace

ScanDiffResult diff_reports(const json& old_j, const json& new_j) {
  ScanDiffResult d;
  auto started = [](const json& j) -> std::string {
    if (j.contains("scan") && j.at("scan").contains("started_at") &&
        j.at("scan").at("started_at").is_string())
      return j.at("scan").at("started_at").get<std::string>();
    return "";
  };
  d.old_started = started(old_j);
  d.new_started = started(new_j);

  // ---- строки по хостам ----
  diff_host_sets(d, "ip", host_strings(old_j, "ips"), host_strings(new_j, "ips"),
                 "medium", "info");  // a new address is infrastructure drift
  diff_host_sets(d, "subdomain", host_strings(old_j, "subdomains"),
                 host_strings(new_j, "subdomains"), "low", "info");
  diff_host_sets(d, "email", host_strings(old_j, "emails"),
                 host_strings(new_j, "emails"), "low", "info");
  diff_host_sets(d, "neighbor", host_strings(old_j, "neighbors"),
                 host_strings(new_j, "neighbors"), "low", "info");
  diff_host_sets(d, "infra_tag", host_strings(old_j, "infra_tags"),
                 host_strings(new_j, "infra_tags"), "low", "info");

  // ---- порты ----
  {
    auto oldp = host_ports(old_j), newp = host_ports(new_j);
    std::set<std::string> hosts;
    for (const auto& kv : oldp) hosts.insert(kv.first);
    for (const auto& kv : newp) hosts.insert(kv.first);
    for (const std::string& host : hosts) {
      std::map<int, std::string> o, n;
      if (auto it = oldp.find(host); it != oldp.end()) o = it->second;
      if (auto it = newp.find(host); it != newp.end()) n = it->second;
      for (const auto& [port, label] : n)
        if (!o.count(port))
          push(d, "port", "added", host,
               std::to_string(port) + "/tcp opened" +
                   (label.empty() ? "" : " — " + label),
               "medium");
      for (const auto& [port, label] : o)
        if (!n.count(port))
          push(d, "port", "removed", host,
               std::to_string(port) + "/tcp closed" +
                   (label.empty() ? "" : " — " + label),
               "info");
    }
  }

  // ---- технологии ----
  {
    auto oldt = host_tech(old_j), newt = host_tech(new_j);
    std::set<std::string> hosts;
    for (const auto& kv : oldt) hosts.insert(kv.first);
    for (const auto& kv : newt) hosts.insert(kv.first);
    for (const std::string& host : hosts) {
      std::map<std::string, std::string> o, n;
      if (auto it = oldt.find(host); it != oldt.end()) o = it->second;
      if (auto it = newt.find(host); it != newt.end()) n = it->second;
      for (const auto& [name, ver] : n) {
        auto it = o.find(name);
        if (it == o.end()) {
          push(d, "tech", "added", host,
               "technology appeared: " + name + (ver.empty() ? "" : " " + ver),
               "low");
        } else if (!it->second.empty() && !ver.empty() && it->second != ver) {
          push(d, "tech", "changed", host,
               "technology version changed: " + name + " " + it->second +
                   " -> " + ver,
               "medium");
        }
      }
      for (const auto& [name, ver] : o)
        if (!n.count(name))
          push(d, "tech", "removed", host,
               "technology disappeared: " + name + (ver.empty() ? "" : " " + ver),
               "low");
    }
  }

  // ---- пути ----
  {
    auto paths_of = [](const json& j) {
      std::map<std::string, std::set<std::string>> out;
      if (!j.contains("hosts")) return out;
      for (const auto& h : j.at("hosts")) {
        if (!h.contains("host") || !h.contains("paths")) continue;
        std::string host = h.at("host").get<std::string>();
        for (const auto& p : h.at("paths"))
          if (p.contains("path") && p.at("path").is_string())
            out[host].insert(p.at("path").get<std::string>());
      }
      return out;
    };
    auto oldm = paths_of(old_j), newm = paths_of(new_j);
    std::set<std::string> hosts;
    for (const auto& kv : oldm) hosts.insert(kv.first);
    for (const auto& kv : newm) hosts.insert(kv.first);
    for (const std::string& host : hosts) {
      std::set<std::string> o, n;
      if (auto it = oldm.find(host); it != oldm.end()) o = it->second;
      if (auto it = newm.find(host); it != newm.end()) n = it->second;
      for (const std::string& v : n)
        if (!o.count(v)) push(d, "path", "added", host, "new endpoint: " + v, "low");
      for (const std::string& v : o)
        if (!n.count(v)) push(d, "path", "removed", host, "endpoint gone: " + v, "info");
    }
  }

  // ---- dns ----
  {
    auto oldd = host_dns(old_j), newd = host_dns(new_j);
    std::set<std::string> hosts;
    for (const auto& kv : oldd) hosts.insert(kv.first);
    for (const auto& kv : newd) hosts.insert(kv.first);
    for (const std::string& host : hosts) {
      std::map<std::string, std::set<std::string>> o, n;
      if (auto it = oldd.find(host); it != oldd.end()) o = it->second;
      if (auto it = newd.find(host); it != newd.end()) n = it->second;
      std::set<std::string> keys;
      for (const auto& kv : o) keys.insert(kv.first);
      for (const auto& kv : n) keys.insert(kv.first);
      for (const std::string& k : keys) {
        std::set<std::string> ov, nv;
        if (auto it = o.find(k); it != o.end()) ov = it->second;
        if (auto it = n.find(k); it != n.end()) nv = it->second;
        bool same = ov == nv;
        if (ov.empty() && !nv.empty()) {
          std::string vals;
          for (const auto& v : nv) vals += (vals.empty() ? "" : ", ") + v;
          push(d, "dns", "added", host, k + " added: " + vals, "low");
        } else if (!ov.empty() && nv.empty()) {
          push(d, "dns", "removed", host, k + " removed", "medium");
        } else if (!same) {
          std::string detail = k + " changed";
          if (ov.size() != nv.size())
            detail += " (" + std::to_string(ov.size()) + " -> " +
                      std::to_string(nv.size()) + " values)";
          push(d, "dns", "changed", host, detail, "medium");
        }
      }
    }
  }

  // ---- сертификаты ----
  {
    auto oldc = host_certs(old_j), newc = host_certs(new_j);
    for (const auto& [host, oc] : oldc) {
      auto it = newc.find(host);
      if (it == newc.end() || it->second == oc) continue;
      std::vector<std::string> parts_old = split(oc, '|');
      std::vector<std::string> parts_new = split(it->second, '|');
      std::string detail = "certificate changed";
      if (!parts_old.empty() && !parts_new.empty() && parts_old[0] != parts_new[0])
        detail += "; subject " + parts_old[0] + " -> " + parts_new[0];
      if (parts_old.size() > 2 && parts_new.size() > 2 && parts_old[2] != parts_new[2])
        detail += "; expires " + parts_old[2] + " -> " + parts_new[2];
      push(d, "certificate", "changed", host, detail, "medium");
    }
  }

  // ---- находки ----
  {
    auto oldf = finding_map(old_j), newf = finding_map(new_j);
    for (const auto& [key, nv] : newf) {
      if (oldf.count(key)) continue;
      // kind = module of the finding
      std::string module = key.substr(0, key.find('|'));
      push(d, module.empty() ? "finding" : module, "added",
           key.substr(key.find('|') + 1, key.rfind('|') - key.find('|') - 1),
           "new finding: " + key.substr(key.rfind('|') + 1) +
               (nv.second.empty() ? "" : " (" + nv.second + ")"),
           nv.first.empty() ? "info" : nv.first);
    }
    for (const auto& [key, ov] : oldf) {
      if (newf.count(key)) continue;
      push(d, "finding", "removed",
           key.substr(key.find('|') + 1, key.rfind('|') - key.find('|') - 1),
           "finding resolved: " + key.substr(key.rfind('|') + 1), "info");
    }
  }

  // ---- агрегация + сортировка ----
  for (const auto& c : d.changes) {
    ++d.by_kind[c.kind];
    ++d.by_action[c.action];
  }
  std::stable_sort(d.changes.begin(), d.changes.end(),
                   [](const DiffChange& a, const DiffChange& b) {
                     if (a.severity != b.severity)
                       return severity_rank(a.severity) >
                              severity_rank(b.severity);
                     if (a.kind != b.kind) return a.kind < b.kind;
                     return a.entity < b.entity;
                   });
  return d;
}

json diff_to_json(const ScanDiffResult& d) {
  json j;
  j["tool"] = "mikto diff";
  j["compared"] = {{"old_started", d.old_started}, {"new_started", d.new_started}};
  json changes = json::array();
  for (const auto& c : d.changes) {
    changes.push_back({{"kind", c.kind},
                       {"action", c.action},
                       {"entity", c.entity},
                       {"detail", c.detail},
                       {"severity", c.severity},
                       {"first_seen", c.first_seen},
                       {"last_seen", c.last_seen}});
  }
  j["changes"] = changes;
  j["identical"] = d.identical();
  json kinds = json::object(), actions = json::object();
  for (const auto& [k, v] : d.by_kind) kinds[k] = v;
  for (const auto& [k, v] : d.by_action) actions[k] = v;
  j["summary"] = {{"total", d.changes.size()}, {"by_kind", kinds},
                  {"by_action", actions}};
  return j;
}

std::string diff_console_text(const ScanDiffResult& d, bool color) {
  std::ostringstream out;
  auto tag = [&](const std::string& sev) -> std::string {
    if (!color) return "[" + sev + "]";
    const char* c = "\033[36m";
    if (sev == "critical") c = "\033[1;31m";
    else if (sev == "high") c = "\033[31m";
    else if (sev == "medium") c = "\033[33m";
    else if (sev == "low") c = "\033[32m";
    return std::string(c) + "[" + sev + "]" + "\033[0m";
  };
  if (d.identical()) {
    out << "mikto diff: no differences between scans\n";
    if (!d.old_started.empty() && !d.new_started.empty())
      out << "  compared: " << d.old_started << "  vs  " << d.new_started << "\n";
    return out.str();
  }
  out << "mikto diff: " << d.changes.size() << " change(s) between "
      << d.old_started << " and " << d.new_started << "\n";
  size_t shown = std::min<size_t>(d.changes.size(), 60);
  for (size_t i = 0; i < shown; ++i) {
    const DiffChange& c = d.changes[i];
    out << "  " << tag(c.severity) << " " << c.action << " " << c.kind << ": "
        << c.entity << " — " << c.detail << "\n";
  }
  if (d.changes.size() > shown)
    out << "  ... " << (d.changes.size() - shown)
        << " more — full list in the JSON diff report\n";
  out << "\nSummary:";
  for (const auto& [k, v] : d.by_action)
    out << " " << v << " " << k;
  out << "\n";
  return out.str();
}

bool write_diff_html(const ScanDiffResult& d, const std::string& path,
                     std::string& err) {
  std::ofstream f(path, std::ios::trunc);
  if (!f) {
    err = "cannot open HTML diff file: " + path;
    return false;
  }
  f << "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n"
    << "<title>mikto diff report</title>\n<style>\n"
    << ":root{color-scheme:light dark}\n"
    << "body{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;"
    << "max-width:1100px;margin:24px auto;padding:0 16px;}\n"
    << "h1{font-size:20px} .meta{opacity:.7;font-size:13px}\n"
    << "table{border-collapse:collapse;width:100%;margin-top:16px}\n"
    << "th,td{border:1px solid rgba(128,128,128,.35);padding:6px 9px;"
    << "text-align:left;vertical-align:top}\n"
    << "th{background:rgba(128,128,128,.12);position:sticky;top:0}\n"
    << ".critical{color:#c0392b;font-weight:600}.high{color:#d35400}"
    << ".medium{color:#b7950b}.low{color:#27ae60}.info{opacity:.8}\n"
    << ".added{color:#27ae60}.removed{color:#c0392b}.changed{color:#b7950b}\n"
    << ".sum{margin:10px 0 0;font-size:13px;opacity:.85}\n"
    << "</style></head><body>\n"
    << "<h1>mikto diff — infrastructure changes</h1>\n"
    << "<div class=\"meta\">compared scans: " << html_escape(d.old_started)
    << " &rarr; " << html_escape(d.new_started) << "</div>\n";
  f << "<div class=\"sum\">";
  for (const auto& [k, v] : d.by_action) f << v << " " << k << " &nbsp; ";
  f << "</div>\n";
  f << "<table><tr><th>severity</th><th>action</th><th>kind</th><th>entity</th>"
    << "<th>detail</th><th>first seen</th><th>last seen</th></tr>\n";
  for (const auto& c : d.changes) {
    f << "<tr><td class=\"" << c.severity << "\">" << c.severity
      << "</td><td class=\"" << c.action << "\">" << c.action
      << "</td><td>" << html_escape(c.kind) << "</td><td>"
      << html_escape(c.entity) << "</td><td>" << html_escape(c.detail)
      << "</td><td>" << html_escape(c.first_seen) << "</td><td>"
      << html_escape(c.last_seen) << "</td></tr>\n";
  }
  f << "</table>\n";
  if (d.identical()) f << "<p>No differences between the two scans.</p>\n";
  f << "</body></html>\n";
  if (!f) {
    err = "failed writing HTML diff: " + path;
    return false;
  }
  return true;
}

}  // namespace mikto
