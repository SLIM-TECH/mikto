#pragma once
// mikto — каталог провайдеров + breaker, ключи только из env
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace mikto {

struct ProviderInfo {
  const char* name;      // display name, e.g. "crt.sh"
  const char* host;      // contacted host (circuit-breaker key)
  const char* category;  // "cert-transparency", "geo", "vuln", "threat-feed", ...
  const char* endpoint;  // API endpoint pattern (documented)
  const char* auth_env;  // env var(s) that grant auth; "" = keyless
  const char* cache_ttl; // on-disk cache behaviour inside mikto
  const char* limits;    // documented public-tier limits
  const char* notes;     // honest free-tier caveats
};

// то, что показывает mikto providers
const std::vector<ProviderInfo>& provider_catalog();

std::string providers_help_text();

// ---- runtime health: аккаунтинг + breaker ----

struct ProviderStat {
  std::string name;    // catalog name when known, else hostname
  int allowed = 0;     // requests actually sent
  int blocked = 0;     // denied by an open circuit or the request cap
  int successes = 0;
  int failures = 0;    // transport-level failures (timeout, refused, TLS)
  int consecutive_failures = 0;
  int circuit_trips = 0;      // how many times the breaker opened
  bool circuit_open = false;  // state at scan end
  bool capped = false;        // per-provider request cap exhausted
};

class ProviderTracker {
 public:
  // сколько фейлов подряд открывают цепь; cap на провайдера за скан (0 = нет)
  explicit ProviderTracker(int breaker_trips = 5, int per_provider_cap = 60)
      : trip_threshold_(breaker_trips), cap_(per_provider_cap) {}

  // false = в сеть не ходить, отказ уже посчитан
  bool allow(const std::string& host);

  // без записи
  bool would_block(const std::string& host) const;

  void record_success(const std::string& host);
  void record_failure(const std::string& host);

  void set_name(const std::string& host, const std::string& name);

  // чтобы варнинг только раз
  int blocked_count(const std::string& host) const;

  // для отчёта
  std::map<std::string, ProviderStat> snapshot() const;

 private:
  ProviderStat& stat_for(const std::string& host);  // guarded by mu_
  mutable std::mutex mu_;
  std::map<std::string, ProviderStat> stats_;
  int trip_threshold_;
  int cap_;
};

// ---- классификация url ----

// "" если не абсолютный http(s)
std::string provider_url_host(const std::string& url);

// nullptr = не внешний провайдер, ключом остаётся сам хост
const ProviderInfo* classify_provider(const std::string& url,
                                      const std::vector<std::string>& target_hosts,
                                      std::string& host);

// пустой auth_env = keyless = true
bool provider_key_configured(const std::string& auth_env);

}  // namespace mikto
