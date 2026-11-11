// каталог провайдеров + breaker
#include "mikto/providers.hpp"

#include <algorithm>
#include <cstdlib>
#include <iomanip>
#include <map>
#include <sstream>

#include "mikto/util.hpp"

namespace mikto {

const std::vector<ProviderInfo>& provider_catalog() {
  static const std::vector<ProviderInfo> catalog = {
      // name, host, category, endpoint, auth_env, cache_ttl, limits, notes
      {"crt.sh", "crt.sh", "cert-transparency",
       "https://crt.sh/?q=<domain>&output=json", "", "not cached (deduped per scan)",
       "public community instance, best-effort, often slow under load",
       "keyless; subdomain + e-mail discovery; on 503 mikto degrades gracefully"},
      {"urlscan.io", "urlscan.io", "passive-dns",
       "https://urlscan.io/api/v1/search/?q=domain:<domain>", "",
       "not cached (deduped per scan)", "free search API, rate-limited without a key",
       "keyless; subdomain discovery"},
      {"Hackertarget", "api.hackertarget.com", "reverse-ip",
       "https://api.hackertarget.com/reverseiplookup/?q=<ip> | /hostsearch/?q=<domain>",
       "", "not cached", "free community API with a small daily quota, then HTTP 429",
       "keyless; shared public quota — expect exhaustion; results are best-effort"},
      {"ipwho.is", "ipwho.is", "geo", "https://ipwho.is/<ip>", "",
       "24h disk cache", "free, no key required", "IP geolocation / ASN; fallback: ip-api.com"},
      {"ip-api.com", "ip-api.com", "geo", "http://ip-api.com/json/<ip>", "",
       "24h disk cache", "free tier: 45 req/min, HTTP only (no HTTPS on free tier)",
       "geo fallback when ipwho.is fails"},
      {"Shodan InternetDB", "internetdb.shodan.io", "exposure-db",
       "https://internetdb.shodan.io/<ip>", "", "24h disk cache",
       "free, no key required",
       "aggregated HISTORICAL port/vulnerability tags, not live observations"},
      {"Shodan API", "api.shodan.io", "exposure-db",
       "https://api.shodan.io/shodan/host/<ip>", "SHODAN_API_KEY", "24h disk cache",
       "free tier: 1 query/s with monthly query credits",
       "optional; only used when the key is provided"},
      {"Censys", "search.censys.io", "exposure-db",
       "https://search.censys.io/api/v2/hosts/<ip>", "CENSYS_API_ID + CENSYS_API_SECRET",
       "24h disk cache", "free tier: limited monthly request quota",
       "optional; per-service software/CPE enrichment"},
      {"NVD", "services.nvd.nist.gov", "vuln-db",
       "https://services.nvd.nist.gov/rest/json/cves/2.0", "NVD_API_KEY (optional)",
       "24h disk cache", "without key: 5 req / 30 s; with key: 50 req / 30 s (documented)",
       "CVE matching; mikto paces itself and caches responses"},
      {"CVE Project cvelistV5", "raw.githubusercontent.com", "vuln-db",
       "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/<path>", "",
       "24h disk cache", "GitHub raw hosting, generous limits",
       "per-CVE record details (description, CVSS)"},
      {"RDAP", "rdap.org", "whois", "https://rdap.org/domain/<domain>", "",
       "not cached", "keyless; redirects to the registry RDAP server",
       "fallback when TCP/43 WHOIS is blocked"},
      {"Exploit-DB", "gitlab.com", "exploit-index",
       "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv",
       "", "24h disk cache", "keyless public index", "CVE exploit prioritization"},
      {"OpenPhish", "raw.githubusercontent.com", "threat-feed",
       "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
       "", "6h disk cache", "keyless community feed", "phishing-URL host check"},
      {"Feodo Tracker", "feodotracker.abuse.ch", "threat-feed",
       "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt", "",
       "1h disk cache", "keyless", "botnet C2 IP blocklist (abuse.ch)"},
  };
  return catalog;
}

// ---- Pure helpers ------------------------------------------------------------

std::string provider_url_host(const std::string& url) {
  const std::string scheme1 = "https://";
  const std::string scheme2 = "http://";
  std::string rest;
  if (url.compare(0, scheme1.size(), scheme1) == 0)
    rest = url.substr(scheme1.size());
  else if (url.compare(0, scheme2.size(), scheme2) == 0)
    rest = url.substr(scheme2.size());
  else
    return "";
  size_t end = rest.size();
  for (size_t i = 0; i < rest.size(); ++i) {
    char c = rest[i];
    if (c == '/' || c == '?' || c == '#') {
      end = i;
      break;
    }
  }
  std::string hostport = rest.substr(0, end);
  // Strip userinfo ("user:pass@host").
  size_t at = hostport.rfind('@');
  if (at != std::string::npos) hostport = hostport.substr(at + 1);
  // порт не трогаем у [ipv6]
  if (!hostport.empty() && hostport.front() == '[') {
    size_t close = hostport.find(']');
    if (close != std::string::npos) hostport = hostport.substr(1, close - 1);
  } else {
    size_t colon = hostport.rfind(':');
    if (colon != std::string::npos && hostport.find(']') == std::string::npos)
      hostport = hostport.substr(0, colon);
  }
  return to_lower(hostport);
}

// префикс пути, чтобы развести провайдеров на одном хосте
static std::string endpoint_path_token(const char* endpoint) {
  if (!endpoint) return "";
  std::string s = to_lower(endpoint);
  size_t scheme = s.find("://");
  if (scheme == std::string::npos) return "";
  std::string rest = s.substr(scheme + 3);
  size_t slash = rest.find('/');
  if (slash == std::string::npos) return "";
  std::string eh = rest.substr(0, slash);
  std::string path = rest.substr(slash + 1);
  size_t bar = path.find('|');  // "a | b" endpoint alternatives
  if (bar != std::string::npos) path = path.substr(0, bar);
  size_t ph = path.find('<');   // "<ip>", "<domain>" placeholders
  if (ph != std::string::npos) path = path.substr(0, ph);
  return eh + "/" + path;
}

const ProviderInfo* classify_provider(
    const std::string& url, const std::vector<std::string>& target_hosts,
    std::string& host) {
  host = provider_url_host(url);
  if (host.empty()) return nullptr;
  // цель не провайдер
  for (const std::string& t : target_hosts)
    if (iequals(t, host)) return nullptr;

  std::string lowurl = to_lower(url);
  const ProviderInfo* best = nullptr;    // matched on host + path token
  size_t best_len = 0;
  const ProviderInfo* fallback = nullptr;  // matched on host only
  for (const ProviderInfo& p : provider_catalog()) {
    if (!iequals(p.host, host)) continue;
    std::string tok = endpoint_path_token(p.endpoint);
    if (!tok.empty() && lowurl.find(tok) != std::string::npos) {
      if (!best || tok.size() > best_len) {
        best = &p;
        best_len = tok.size();
      }
    } else if (!fallback) {
      fallback = &p;
    }
  }
  return best ? best : fallback;
}

bool provider_key_configured(const std::string& auth_env) {
  if (auth_env.empty()) return true;  // keyless
  for (const std::string& raw : split(auth_env, '+')) {
    std::string name = trim(raw);
    if (name.empty()) continue;
    // срезаем "(optional)"
    size_t sp = name.find(' ');
    if (sp != std::string::npos) name = name.substr(0, sp);
    const char* v = std::getenv(name.c_str());
    if (!v || !*v) return false;
  }
  return true;
}

std::string providers_help_text() {
  std::ostringstream out;
  out << "external data providers compiled into this mikto build\n"
      << "(all work without API keys unless noted; keys are read from env\n"
      << " variables, never stored in config or source)\n\n";
  out << "  " << std::left << std::setw(22) << "provider" << std::setw(18)
      << "category" << std::setw(34) << "auth (env)" << "key\n";
  out << "  " << std::string(78, '-') << "\n";
  for (const ProviderInfo& p : provider_catalog()) {
    out << "  " << std::left << std::setw(22) << p.name << std::setw(18)
        << p.category << std::setw(34)
        << (p.auth_env[0] ? p.auth_env : "keyless")
        << (provider_key_configured(p.auth_env) ? (p.auth_env[0] ? "set" : "-")
                                                : "NOT SET")
        << "\n";
    out << "      " << p.endpoint << "\n";
    out << "      limits: " << p.limits << "; cache: " << p.cache_ttl << "\n";
    out << "      " << p.notes << "\n";
  }
  out << "\nProvider health is tracked per scan: after 5 consecutive\n"
         "transport failures (or a per-provider request cap) the circuit\n"
         "opens and further requests to that provider are skipped — affected\n"
         "results degrade honestly and every block is recorded in the report\n"
         "(see the `providers` section of the JSON report).\n";
  return out.str();
}

// ---- ProviderTracker -----------------------------------------------------------

ProviderStat& ProviderTracker::stat_for(const std::string& host) {
  auto& s = stats_[host];
  if (s.name.empty()) {
    for (const ProviderInfo& p : provider_catalog())
      if (iequals(p.host, host)) {
        s.name = p.name;
        break;
      }
    if (s.name.empty()) s.name = host;
  }
  return s;
}

bool ProviderTracker::would_block(const std::string& host) const {
  std::lock_guard<std::mutex> g(mu_);
  auto it = stats_.find(host);
  if (it == stats_.end()) return false;
  const ProviderStat& s = it->second;
  if (cap_ > 0 && s.allowed >= cap_) return true;
  if (!s.circuit_open) return false;
  // каждый 10-й блок проходит насквозь (half-open)
  return (s.blocked + 1) % 10 != 0;
}

bool ProviderTracker::allow(const std::string& host) {
  std::lock_guard<std::mutex> g(mu_);
  ProviderStat& s = stat_for(host);
  if (cap_ > 0 && s.allowed >= cap_) {
    s.capped = true;
    ++s.blocked;
    return false;
  }
  if (s.circuit_open) {
    ++s.blocked;
    if (s.blocked % 10 == 0) {
      ++s.allowed;
      return true;
    }
    return false;
  }
  ++s.allowed;
  return true;
}

void ProviderTracker::record_success(const std::string& host) {
  std::lock_guard<std::mutex> g(mu_);
  ProviderStat& s = stat_for(host);
  ++s.successes;
  s.consecutive_failures = 0;
  s.circuit_open = false;  // half-open прошёл, закрываем
}

void ProviderTracker::record_failure(const std::string& host) {
  std::lock_guard<std::mutex> g(mu_);
  ProviderStat& s = stat_for(host);
  ++s.failures;
  ++s.consecutive_failures;
  if (trip_threshold_ > 0 && s.consecutive_failures >= trip_threshold_) {
    if (!s.circuit_open) ++s.circuit_trips;
    s.circuit_open = true;
    s.consecutive_failures = trip_threshold_;  // stay tripped until a success
  }
}

void ProviderTracker::set_name(const std::string& host,
                               const std::string& name) {
  std::lock_guard<std::mutex> g(mu_);
  ProviderStat& s = stat_for(host);
  if (s.name.empty() || s.name == host) s.name = name;
}

int ProviderTracker::blocked_count(const std::string& host) const {
  std::lock_guard<std::mutex> g(mu_);
  auto it = stats_.find(host);
  return it == stats_.end() ? 0 : it->second.blocked;
}

std::map<std::string, ProviderStat> ProviderTracker::snapshot() const {
  std::lock_guard<std::mutex> g(mu_);
  return stats_;
}

}  // namespace mikto
