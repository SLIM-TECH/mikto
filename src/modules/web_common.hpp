#pragma once
// mikto — общие хелперы для web-модулей
#include <string>
#include <vector>

#include "mikto/scan_result.hpp"
#include "mikto/target.hpp"

namespace mikto {

struct UrlRef {
  std::string url;
  std::string host;
  int port = 0;
  bool https = false;
};

// урлы для проверки: явный порт или открытые порты от ports
std::vector<UrlRef> urls_for_target(const Target& t, const HostResult* host);

}  // namespace mikto
