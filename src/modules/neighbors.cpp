// mikto — соседи по ip: реверс-ip + данные shodan
#include "modules.hpp"

#include <algorithm>
#include <set>
#include <vector>

#include "mikto/rate_limiter.hpp"
#include "mikto/util.hpp"

namespace mikto {

namespace {

bool plausible_domain(const std::string& s) {
  if (s.size() < 4 || s.size() > 253) return false;
  if (s.find('.') == std::string::npos) return false;
  if (s.find(' ') != std::string::npos || s.find('/') != std::string::npos)
    return false;
  if (s.find("..") != std::string::npos) return false;
  for (unsigned char c : s)
    if (!(std::isalnum(c) || c == '-' || c == '.')) return false;
  if (s.front() == '-' || s.back() == '-' || s.front() == '.' ||
      s.back() == '.')
    return false;
  return true;
}

class NeighborsModule : public IModule {
 public:
  std::string name() const override { return "neighbors"; }
  std::string description() const override {
    return "co-hosted domains on the same IP (reverse-IP lookup, shared-hosting risk)";
  }
  Maturity maturity() const override { return Maturity::Preview; }
  std::vector<std::string> depends() const override { return {"assets", "infra"}; }

  bool run(ModuleContext& ctx) override {
    std::vector<std::pair<std::string, std::string>> ips;
    for (const auto& t : ctx.cfg.targets) {
      if (t.is_ip) {
        ips.push_back({t.host, t.host});
      } else {
        const HostResult* hr = ctx.result.find_host(t.host);
        if (hr && !hr->ips.empty() &&
            std::find_if(ips.begin(), ips.end(),
                         [&](const auto& p) { return p.first == hr->ips.front(); }) ==
                ips.end())
          ips.push_back({hr->ips.front(), t.host});
      }
    }
    if (ips.empty()) return true;

    ctx.pstage("neighbors", "reverse-IP lookup", ips.size());
    HttpOptions opt;
    opt.timeout_s = 20;
    opt.user_agent = ctx.cfg.user_agent;
    opt.max_body_bytes = 512 * 1024;

    // сеть в пуле, результат применяет главный поток
    struct RevIpOut {
      std::vector<std::string> found;
      bool ok = false;
    };
    std::vector<RevIpOut> per_ip(ips.size());
    ctx.parallel(ips.size(), [&](size_t ii) {
      const auto& [ip, label] = ips[ii];
      ctx.ptick();
      ctx.pitem(ip);
      // известные соседи нужны только для дедупа — читаем копию
      std::set<std::string> known;
      if (const HostResult* hr0 = ctx.result.find_host(label)) {
        known.insert(hr0->neighbors.begin(), hr0->neighbors.end());
      }
      known.erase(label);

      // через ctx.get чтобы попало в trace и rate limit
      HttpResponse resp =
          ctx.get("https://api.hackertarget.com/reverseiplookup/?q=" + ip, opt);
      if (resp.ok_network() && resp.status == 200) {
        std::string body = to_lower(resp.body);
        if (body.find("api count exceeded") == std::string::npos &&
            body.find("error") != 0) {
          per_ip[ii].ok = true;
          for (const std::string& line_raw : split(resp.body, '\n')) {
            std::string line = trim(line_raw);
            size_t comma = line.find(',');
            if (comma != std::string::npos) line = line.substr(0, comma);
            line = trim(line);
            if (!plausible_domain(line)) continue;
            if (line == label) continue;
            if (known.insert(line).second) per_ip[ii].found.push_back(line);
            if (per_ip[ii].found.size() >= 100) break;
          }
        }
      }
    });

    for (size_t ii = 0; ii < ips.size(); ++ii) {
      const auto& [ip, label] = ips[ii];
      RevIpOut& out = per_ip[ii];
      HostResult& host = ctx.result.ensure_host(label, false);
      if (!out.ok)
        ctx.log("neighbors: reverse-ip lookup unavailable for " + ip);

      for (const auto& d : out.found)
        if (host.neighbors.size() < 100 &&
            std::find(host.neighbors.begin(), host.neighbors.end(), d) ==
                host.neighbors.end())
          host.neighbors.push_back(d);

      if (host.neighbors.empty()) {
        ctx.log("neighbors: no co-hosted domains known for " + ip);
        continue;
      }

      std::string evidence;
      for (size_t i = 0; i < host.neighbors.size() && i < 10; ++i) {
        if (!evidence.empty()) evidence += ", ";
        evidence += host.neighbors[i];
      }
      if (host.neighbors.size() > 10) evidence += ", ...";

      Finding f;
      f.severity = host.neighbors.size() >= 10 ? Severity::Medium
                                               : Severity::Low;
      f.module = "neighbors";
      f.host = label;
      f.service = "recon";
      f.location = ip;
      f.title = std::to_string(host.neighbors.size()) +
                " other site(s) hosted on the same IP";
      f.detail =
          "The IP " + ip + " also serves: " + evidence +
          ". On shared hosting, a compromise of any neighbour (or of the "
          "hosting node itself) can affect your site: shared kernel, "
          "shared network, sometimes a shared control panel and filesystem. "
          "Cross-site contamination and IP reputation damage are realistic "
          "risks.";
      f.recommendation =
          "For production workloads consider a dedicated IP or isolated "
          "container/VM; if sharing is intentional, verify the provider's "
          "isolation guarantees and monitor IP reputation.";
      ctx.result.add_finding(std::move(f));
    }
    ctx.pdone();
    return true;
  }
};

}  // namespace

std::unique_ptr<IModule> make_neighbors_module() {
  return std::make_unique<NeighborsModule>();
}

}  // namespace mikto
