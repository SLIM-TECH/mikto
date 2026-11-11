// nvd 2.0 + кэш на диске
#include "mikto/cve_db.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <thread>

#include "mikto/http_client.hpp"
#include "mikto/util.hpp"
#include "mikto/version.hpp"

namespace mikto {

using nlohmann::json;

std::optional<std::pair<std::string, std::string>> cpe_for_product(
    const std::string& product, const std::string& version) {
  std::string p = to_lower(product);
  auto hit = [&](const char* vendor, const char* prod) {
    return std::optional<std::pair<std::string, std::string>>{std::make_pair(
        std::string(vendor), std::string(prod))};
  };
  if (p.find("nginx") != std::string::npos) return hit("nginx", "nginx");
  if (p.find("openssh") != std::string::npos) return hit("openbsd", "openssh");
  if (p.find("apache") != std::string::npos || p == "httpd")
    return hit("apache", "httpd");
  if (p.find("mariadb") != std::string::npos) return hit("mariadb", "mariadb");
  if (p.find("mysql") != std::string::npos) {
    // mysql 8+ живёт под вендором oracle
    if (!version.empty() && compare_versions(version, "8.0.0") >= 0)
      return hit("oracle", "mysql");
    return hit("mysql", "mysql");
  }
  if (p.find("mongo") != std::string::npos) return hit("mongodb", "mongodb");
  if (p.find("redis") != std::string::npos) return hit("redis", "redis");
  if (p.find("postgres") != std::string::npos)
    return hit("postgresql", "postgresql");
  if (p.find("memcached") != std::string::npos)
    return hit("memcached", "memcached");
  if (p.find("elastic") != std::string::npos)
    return hit("elastic", "elasticsearch");
  if (p.find("vsftpd") != std::string::npos) return hit("vsftpd", "vsftpd");
  if (p.find("proftpd") != std::string::npos) return hit("proftpd", "proftpd");
  if (p.find("lighttpd") != std::string::npos)
    return hit("lighttpd", "lighttpd");
  if (p.find("dovecot") != std::string::npos) return hit("dovecot", "dovecot");
  if (p.find("exim") != std::string::npos) return hit("exim", "exim");
  // ---- веб-стеки и популярный софт ----
  if (p.find("wordpress") != std::string::npos)
    return hit("wordpress", "wordpress");
  if (p == "php" || p == "php-fpm" || p.find("php/") == 0)
    return hit("php", "php");
  if (p.find("joomla") != std::string::npos)
    return hit("joomla", "joomla\\!");
  if (p.find("drupal") != std::string::npos)
    return hit("drupal", "drupal");
  if (p.find("jquery") != std::string::npos)
    return hit("jquery", "jquery");
  if (p.find("iis") != std::string::npos || p.find("internet information") != std::string::npos)
    return hit("microsoft", "internet_information_server");
  if (p.find("tomcat") != std::string::npos)
    return hit("apache", "tomcat");
  if (p.find("jetty") != std::string::npos)
    return hit("eclipse", "jetty");
  if (p.find("jenkins") != std::string::npos)
    return hit("jenkins", "jenkins");
  if (p.find("grafana") != std::string::npos)
    return hit("grafana", "grafana");
  if (p.find("gitlab") != std::string::npos)
    return hit("gitlab", "gitlab");
  if (p.find("gitea") != std::string::npos)
    return hit("gitea", "gitea");
  if (p.find("nextcloud") != std::string::npos)
    return hit("nextcloud", "nextcloud");
  if (p.find("postfix") != std::string::npos)
    return hit("postfix", "postfix");
  if (p.find("pure-ftpd") != std::string::npos || p.find("pureftpd") != std::string::npos)
    return hit("pureftpd", "pure-ftpd");
  if (p.find("rabbitmq") != std::string::npos)
    return hit("pivotal_software", "rabbitmq");
  if (p.find("haproxy") != std::string::npos)
    return hit("haproxy", "haproxy");
  if (p.find("squid") != std::string::npos)
    return hit("squid-cache", "squid");
  if (p.find("caddy") != std::string::npos)
    return hit("caddyserver", "caddy");
  if (p.find("kibana") != std::string::npos)
    return hit("elastic", "kibana");
  if (p.find("zabbix") != std::string::npos)
    return hit("zabbix", "zabbix");
  if (p.find("minio") != std::string::npos)
    return hit("minio", "minio");
  // ---- фреймворки, панели, тулинг ----
  if (p == "bootstrap") return hit("getbootstrap", "bootstrap");
  if (p == "django") return hit("djangoproject", "django");
  if (p == "laravel") return hit("laravel", "laravel");
  if (p == "rails" || p == "ruby on rails")
    return hit("rubyonrails", "rails");
  if (p == "flask") return hit("palletsprojects", "flask");
  if (p == "express") return hit("expressjs", "express");
  if (p == "node.js" || p == "nodejs") return hit("nodejs", "node.js");
  if (p == "next.js") return hit("vercel", "next.js");
  if (p == "nuxt") return hit("nuxtjs", "nuxt.js");
  if (p == "ghost") return hit("ghost", "ghost");
  if (p == "magento") return hit("magento", "magento");
  if (p == "opencart") return hit("opencart", "opencart");
  if (p == "prestashop") return hit("prestashop", "prestashop");
  if (p == "phpmyadmin") return hit("phpmyadmin", "phpmyadmin");
  if (p == "mediawiki") return hit("mediawiki", "mediawiki");
  if (p == "typo3") return hit("typo3", "typo3.cms");
  if (p == "thinkphp") return hit("topthink", "think-php");
  if (p == "keycloak") return hit("redhat", "keycloak");
  if (p == "traefik") return hit("traefik", "traefik");
  if (p == "envoy" || p == "envoy proxy")
    return hit("envoyproxy", "envoy");
  if (p == "asp.net") return hit("microsoft", "asp.net");
  if (p == "asp.net core") return hit("microsoft", "asp.net_core");
  if (p == "openresty") return hit("openresty", "openresty");
  if (p == "solr") return hit("apache", "solr");
  if (p == "activemq") return hit("apache", "activemq");
  if (p == "kafka") return hit("apache", "kafka");
  if (p == "couchdb") return hit("apache", "couchdb");
  if (p == "confluence") return hit("atlassian", "confluence");
  if (p == "jira") return hit("atlassian", "jira");
  if (p == "bitbucket") return hit("atlassian", "bitbucket");
  if (p == "nexus") return hit("sonatype", "nexus_repository_manager");
  if (p == "artifactory") return hit("jfrog", "artifactory");
  if (p == "harbor") return hit("goharbor", "harbor");
  if (p == "openssl") return hit("openssl", "openssl");
  if (p == "curl" || p == "libcurl") return hit("haxx", "curl");
  if (p == "nextcloud") return hit("nextcloud", "nextcloud");
  // ---- сервисы из probe ladder ----
  if (p == "mssql" || p.find("sql server") != std::string::npos ||
      p.find("microsoft sql") != std::string::npos)
    return hit("microsoft", "sql_server");
  if (p == "oracle") return hit("oracle", "database_server");
  if (p == "wildfly" || p == "jboss") return hit("redhat", "wildfly");
  if (p == "weblogic") return hit("oracle", "weblogic_server");
  if (p == "vault") return hit("hashicorp", "vault");
  if (p == "consul") return hit("hashicorp", "consul");
  if (p == "nomad") return hit("hashicorp", "nomad");
  if (p == "prometheus") return hit("prometheus", "prometheus");
  if (p == "sonarqube") return hit("sonarsource", "sonarqube");
  if (p == "airflow") return hit("apache", "airflow");
  if (p == "portainer") return hit("portainer", "portainer");
  if (p == "kong") return hit("kong", "kong");
  if (p == "zookeeper") return hit("apache", "zookeeper");
  return std::nullopt;
}

NvdClient::NvdClient(std::string cache_dir, std::string api_key)
    : cache_dir_(std::move(cache_dir)), api_key_(std::move(api_key)) {}

void NvdClient::pace() {
  // без ключа ~5 req/30s, с ключом 50
  double interval = api_key_.empty() ? 6.5 : 0.8;
  auto now = std::chrono::steady_clock::now();
  if (have_last_) {
    double elapsed = std::chrono::duration<double>(now - last_query_).count();
    if (elapsed < interval)
      std::this_thread::sleep_for(
          std::chrono::duration_cast<std::chrono::milliseconds>(
              std::chrono::duration<double>(interval - elapsed)));
  }
  last_query_ = std::chrono::steady_clock::now();
  have_last_ = true;
}

namespace {

std::string cache_key(const std::string& vendor, const std::string& product,
                      const std::string& version) {
  std::string k = vendor + "_" + product + "_" + (version.empty() ? "any" : version);
  for (char& c : k) {
    if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_' && c != '-')
      c = '_';
  }
  return k;
}

}  // namespace

bool NvdClient::load_cache(const std::string& key, std::string& body) const {
  namespace fs = std::filesystem;
  fs::path p = fs::path(cache_dir_) / "nvd" / (key + ".json");
  std::error_code ec;
  auto t = fs::last_write_time(p, ec);
  if (ec) return false;
  auto age = fs::file_time_type::clock::now() - t;
  if (age > std::chrono::hours(24)) return false;
  std::ifstream f(p);
  if (!f) return false;
  std::ostringstream ss;
  ss << f.rdbuf();
  body = ss.str();
  return body.find("\"vulnerabilities\"") != std::string::npos;
}

void NvdClient::store_cache(const std::string& key,
                            const std::string& body) const {
  namespace fs = std::filesystem;
  std::error_code ec;
  fs::create_directories(fs::path(cache_dir_) / "nvd", ec);
  std::ofstream f(fs::path(cache_dir_) / "nvd" / (key + ".json"),
                  std::ios::trunc);
  if (f) f << body;
}

void parse_nvd_response(const std::string& body, const std::string& vendor,
                        const std::string& product, const std::string& version,
                        std::vector<CveEntry>& out) {
  json j = json::parse(body, nullptr, false);
  if (j.is_discarded() || !j.is_object() || !j.contains("vulnerabilities") ||
      !j["vulnerabilities"].is_array())
    return;

  // ---- cpe хелперы ----
  // Un-escape CPE notation ("joomla\!" -> "joomla!").
  auto cpe_unescape = [](std::string s) {
    std::string r;
    for (size_t i = 0; i < s.size(); ++i) {
      if (s[i] == '\\' && i + 1 < s.size()) { r.push_back(s[++i]); continue; }
      r.push_back(s[i]);
    }
    return r;
  };
  // сплит по ':' с учетом бэкслешей
  auto cpe_split = [](const std::string& c) {
    std::vector<std::string> parts;
    std::string cur;
    for (size_t i = 0; i < c.size(); ++i) {
      if (c[i] == '\\' && i + 1 < c.size()) {
        cur.push_back(c[i]);
        cur.push_back(c[++i]);
        continue;
      }
      if (c[i] == ':') { parts.push_back(cur); cur.clear(); continue; }
      cur.push_back(c[i]);
    }
    parts.push_back(cur);
    return parts;
  };

  // One cpeMatch evaluated against the detected version.
  struct MatchEval {
    int rank = -1;              // 3 exact > 2 range > 1 any > 0 none
    bool verified = false;
    std::string kind;           // "exact" | "range" | "any" | ""
    std::string rule;
  };
  auto eval_cpe_match = [&](const json& m) -> MatchEval {
    MatchEval ev;
    if (!m.is_object() || !m.contains("criteria") ||
        !m["criteria"].is_string())
      return ev;
    std::string criteria = m["criteria"].get<std::string>();
    std::string cvendor, cproduct, cversion;
    auto parts = cpe_split(criteria);
    if (parts.size() >= 6 && to_lower(parts[0]) == "cpe" &&
        to_lower(parts[1]) == "2.3") {
      cvendor = parts[3];
      cproduct = parts[4];
      cversion = parts[5];
      // наша мапа даёт только cpe:/a
      if (to_lower(parts[2]) != "a") return ev;
    } else if (parts.size() >= 5 && to_lower(parts[0]) == "cpe" &&
               parts[1].size() >= 2 && parts[1][0] == '/') {
      // в 2.2 "cpe:/a" режется сплиттером по ':'
      if (to_lower(std::string(1, parts[1][1])) != "a") return ev;
      cvendor = parts[2];
      cproduct = parts[3];
      cversion = parts[4];
    } else {
      return ev;
    }
    std::string uv = cpe_unescape(cvendor);
    std::string up = cpe_unescape(cproduct);
    if (!iequals(uv, vendor) || !iequals(up, product)) return ev;

    std::string ver = cpe_unescape(cversion);
    auto constraint = [&](const char* key) -> std::string {
      if (!m.contains(key) || !m[key].is_string()) return "";
      std::string v = m[key].get<std::string>();
      return v.empty() ? "" : v;
    };
    std::string si = constraint("versionStartIncluding");
    std::string sx = constraint("versionStartExcluding");
    std::string ei = constraint("versionEndIncluding");
    std::string ex = constraint("versionEndExcluding");

    if (!si.empty() || !sx.empty() || !ei.empty() || !ex.empty()) {
      // проверяем каждую границу
      bool ok = true;
      if (!si.empty() && compare_versions(version, si) < 0) ok = false;
      if (!sx.empty() && compare_versions(version, sx) <= 0) ok = false;
      if (!ei.empty() && compare_versions(version, ei) > 0) ok = false;
      if (!ex.empty() && compare_versions(version, ex) >= 0) ok = false;
      std::string rule = "version range";
      auto add_bound = [&](const std::string& op, const std::string& v) {
        rule += " " + op + " " + v;
      };
      if (!si.empty()) add_bound(">=", si);
      if (!sx.empty()) add_bound(">", sx);
      if (!ei.empty()) add_bound("<=", ei);
      if (!ex.empty()) add_bound("<", ex);
      ev.rank = 2;
      ev.kind = "range";
      ev.verified = ok && !version.empty();
      ev.rule = "cpeMatch " + criteria.substr(0, 120) + " - " + rule;
      return ev;
    }
    if (ver.empty() || ver == "*" || ver == "-" || ver == "NA") {
      ev.rank = 1;
      ev.kind = "any";
      ev.verified = false;
      ev.rule = "cpeMatch " + criteria.substr(0, 120) +
                " - vendor-wide match (version wildcard)";
      return ev;
    }
    ev.rank = 3;
    ev.kind = "exact";
    ev.verified = !version.empty() && compare_versions(version, ver) == 0;
    ev.rule = "cpeMatch " + criteria.substr(0, 120) +
              " - exact version " + ver +
              (ev.verified ? "" : " (detected version differs)");
    return ev;
  };

  auto pick_best = [](const MatchEval& a, const MatchEval& b) {
    return a.rank >= b.rank ? a : b;
  };

  for (const auto& vuln : j["vulnerabilities"]) {
    if (!vuln.is_object() || !vuln.contains("cve")) continue;
    const json& cve = vuln["cve"];

    CveEntry e;
    e.id = cve.value("id", "");
    if (e.id.empty()) continue;

    for (const auto& d : cve.value("descriptions", json::array())) {
      if (d.is_object() && d.value("lang", "") == "en") {
        e.description = d.value("value", "");
        break;
      }
    }

    double score = 0.0;
    std::string sev;
    if (cve.contains("metrics") && cve["metrics"].is_object()) {
      const json& metrics = cve["metrics"];
      auto extract = [&](const char* key) {
        if (!sev.empty()) return;
        if (!metrics.contains(key) || !metrics[key].is_array() ||
            metrics[key].empty())
          return;
        const json& m0 = metrics[key][0];
        if (m0.is_object() && m0.contains("cvssData") &&
            m0["cvssData"].is_object()) {
          score = m0["cvssData"].value("baseScore", 0.0);
          sev = m0["cvssData"].value("baseSeverity", "");
        }
      };
      extract("cvssMetricV31");
      extract("cvssMetricV30");
      extract("cvssMetricV2");
    }
    e.cvss = score;
    e.severity = sev.empty() ? "UNKNOWN" : sev;
    e.published = cve.value("published", "");

    // ---- сверка конфигураций ----
    if (cve.contains("configurations") && cve["configurations"].is_array()) {
      MatchEval best;
      for (const auto& conf : cve["configurations"]) {
        if (!conf.is_object() || !conf.contains("nodes") ||
            !conf["nodes"].is_array())
          continue;
        for (const auto& node : conf["nodes"]) {
          if (!node.is_object() || !node.contains("cpeMatch") ||
              !node["cpeMatch"].is_array())
            continue;
          for (const auto& m : node["cpeMatch"]) {
            MatchEval ev = eval_cpe_match(m);
            if (ev.rank > 0) best = pick_best(best, ev);
          }
        }
      }
      if (best.rank > 0) {
        e.match_kind = best.kind;
        e.match_rule = best.rule;
        e.version_verified = best.verified;
      }
    }

    e.description = truncate_ellipsis(e.description, 2400);
    out.push_back(std::move(e));
  }
}

bool NvdClient::fetch_cves(const std::string& vendor,
                           const std::string& product,
                           const std::string& version,
                           std::vector<CveEntry>& out, std::string& err) {
  std::string key = cache_key(vendor, product, version);
  std::string body;
  if (load_cache(key, body)) {
    parse_nvd_response(body, vendor, product, version, out);
    return true;
  }

  if (request_budget <= 0) {
    err = "NVD request budget exhausted for this scan (keyless pace is "
          "~5 req/30s) - pass --nvd-key for 10x budget";
    return false;
  }

  pace();

  std::string ver = version.empty() ? "*" : version;
  std::string url =
      "https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString="
      "cpe:2.3:a:" + vendor + ":" + product + ":" + ver +
      ":*:*:*:*:*:*:*&resultsPerPage=50";

  HttpOptions opt;
  opt.timeout_s = 20;
  opt.user_agent = std::string("mikto/") + MIKTO_VERSION;
  HttpClient http;
  HttpResponse resp = http.get(url, opt);

  // 429 даже после pacing: ждём окно, ретраим один раз
  if (resp.status == 429) {
    std::this_thread::sleep_for(std::chrono::seconds(7));
    resp = http.get(url, opt);
  }

  if (!resp.ok_network()) {
    err = "NVD request failed: " +
          (resp.error.empty() ? ("HTTP " + std::to_string(resp.status))
                              : resp.error);
    return false;
  }
  if (resp.status != 200) {
    err = "NVD returned HTTP " + std::to_string(resp.status);
    return false;
  }

  --request_budget;
  store_cache(key, resp.body);
  parse_nvd_response(resp.body, vendor, product, version, out);
  return true;
}

}  // namespace mikto
