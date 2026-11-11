// mikto — реализация urls_for_target
#include "web_common.hpp"

namespace mikto {

std::vector<UrlRef> urls_for_target(const Target& t, const HostResult* host) {
  std::vector<UrlRef> out;
  auto push = [&](const std::string& scheme, int port) {
    UrlRef r;
    r.https = scheme == "https";
    r.host = t.host;
    r.port = port;
    r.url = scheme + "://" + t.host +
            ((port == 80 && !r.https) || (port == 443 && r.https)
                 ? ""
                 : ":" + std::to_string(port));
    out.push_back(std::move(r));
  };
  if (t.scheme == "https") {
    push("https", t.port ? t.port : 443);
    return out;
  }
  if (t.scheme == "http") {
    push("http", t.port ? t.port : 80);
    return out;
  }
  // без схемы: смотрим открытые порты
  if (!host) return out;
  auto open = [&](int p) {
    const PortInfo* pi = host->port(static_cast<uint16_t>(p));
    return pi && pi->open;
  };
  if (open(443)) push("https", 443);
  if (open(80)) push("http", 80);
  for (const auto& p : host->ports) {
    if (!p.open) continue;
    if (p.service != "http" && p.service != "https") continue;
    bool dup = false;
    for (const auto& r : out)
      if (r.port == p.port) dup = true;
    if (!dup) push(p.service, p.port);
  }
  if (out.empty()) {
    if (open(8443)) push("https", 8443);
    if (open(8080)) push("http", 8080);
  }
  return out;
}

}  // namespace mikto
