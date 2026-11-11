#pragma once
// mikto — nvd api 2.0 + кэш на диске; без ключа сам себя тормозит
#include <chrono>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace mikto {

struct CveEntry {
  std::string id;          // CVE-2024-12345
  double cvss = 0.0;
  std::string severity;    // "CRITICAL" | "HIGH" | ... (NVD spelling)
  std::string description; // English description, truncated
  std::string published;   // date

  // что nvd говорит про версию: exact | range | any | ""
  std::string match_kind;
  // текст правила для evidence
  std::string match_rule;
  // версия проходит правило
  bool version_verified = false;
};

// version нужен чтобы развести вендоров (mysql), nullopt когда неизвестно
std::optional<std::pair<std::string, std::string>> cpe_for_product(
    const std::string& product, const std::string& version);

class NvdClient {
 public:
  NvdClient(std::string cache_dir, std::string api_key);

  // живых запросов nvd за скан, кэш бюджет не ест
  int request_budget = 15;

  // false = транспорт или бюджет; пусто + true = cve нет
  bool fetch_cves(const std::string& vendor, const std::string& product,
                  const std::string& version, std::vector<CveEntry>& out,
                  std::string& err);

 private:
  std::string cache_dir_;
  std::string api_key_;
  std::chrono::steady_clock::time_point last_query_{};
  bool have_last_ = false;
  void pace();

  bool load_cache(const std::string& key, std::string& body) const;
  void store_cache(const std::string& key, const std::string& body) const;
};

// конфиги nvd сверяем с детектнутой версией
void parse_nvd_response(const std::string& body, const std::string& vendor,
                        const std::string& product, const std::string& version,
                        std::vector<CveEntry>& out);

}  // namespace mikto
