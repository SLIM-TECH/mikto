// mikto — сверка версий с nvd онлайн + ссылки на эксплойты
#include "modules.hpp"

#include <chrono>
#include <map>
#include <set>
#include <vector>

#include <tuple>

#include "mikto/cve_db.hpp"
#include "mikto/osint.hpp"
#include "mikto/util.hpp"
#include "mikto/version.hpp"

namespace mikto {

namespace {

struct ProductRef {
  std::string product;
  std::string version;
  int port = 0;          // 0 = host-level (tech/infra)
  std::string source;    // "ports", "tech", "infra"
};

// на ступень вниз: совпадение версии не доказывает эксплойт
Severity downgrade(Severity s) {
  switch (s) {
    case Severity::Critical: return Severity::High;
    case Severity::High: return Severity::Medium;
    case Severity::Medium: return Severity::Low;
    case Severity::Low: return Severity::Info;
    default: return Severity::Info;
  }
}

// первый cve id из находки
std::string first_cve_id(const Finding& f) {
  auto collect = [](const std::string& s, size_t p) -> std::string {
    std::string id;
    size_t i = p;
    while (i < s.size() && id.size() < 20) {
      char c = s[i];
      if (std::isalnum(static_cast<unsigned char>(c)) || c == '-') {
        id.push_back(c);
        ++i;
      } else {
        break;
      }
    }
    // хвост не-цифр долой
    while (!id.empty() && !std::isdigit(static_cast<unsigned char>(id.back())))
      id.pop_back();
    return id;
  };
  size_t p = f.title.find("CVE-");
  if (p != std::string::npos) return collect(f.title, p);
  for (const auto& r : f.references) {
    size_t q = r.find("CVE-");
    if (q != std::string::npos) return collect(r, q);
  }
  return "";
}

class CveModule : public IModule {
 public:
  std::string name() const override { return "cve"; }
  std::string description() const override {
    return "match detected versions (services, web stack, Shodan CPEs) against NVD CVE data (network + local cache)";
  }
  Maturity maturity() const override { return Maturity::Preview; }
  std::vector<std::string> depends() const override { return {"ports", "tech", "infra"}; }

  bool run(ModuleContext& ctx) override {
    const Config& cfg = ctx.cfg;
    NvdClient nvd(cfg.cache_dir.string(), cfg.nvd_key);
    nvd.request_budget = cfg.nvd_key.empty() ? 15 : 60;

    bool warned_network = false;
    // дедуп по (cve, хост, продукт), один продукт через два источника не дублируем
    std::set<std::tuple<std::string, std::string, std::string>> emitted;
    int queried = 0, matched = 0, verified = 0;

    std::vector<std::pair<const HostResult*, ProductRef>> products;
    for (const auto& host : ctx.result.hosts) {
      for (const auto& p : host.ports) {
        if (!p.open || p.product.empty() || p.version.empty()) continue;
        products.push_back({&host, ProductRef{p.product, p.version, p.port, "ports"}});
        // второй продукт из multi-product server заголовка
        for (const auto& [ep, ev] : p.extra_versions)
          if (!ev.empty())
            products.push_back(
                {&host, ProductRef{ep, ev, p.port, "ports:server-header"}});
      }
      for (const auto& t : host.tech) {
        if (t.version.empty()) continue;
        products.push_back({&host, ProductRef{t.name, t.version, 0, "tech"}});
      }
      for (const auto& cpe : host.shodan_cpes) {
        // cpe 2.3 или легаси формат
        std::vector<std::string> parts;
        std::string cur;
        for (char c : cpe) {
          if (c == ':') {
            parts.push_back(cur);
            cur.clear();
          } else {
            cur.push_back(c);
          }
        }
        parts.push_back(cur);
        if (parts.size() >= 6 && to_lower(parts[0]) == "cpe" &&
            parts[1] == "2.3" && parts[5] != "*" && !parts[5].empty())
          products.push_back({&host, ProductRef{parts[4], parts[5], 0, "infra:" + parts[3]}});
        else if (parts.size() >= 5 && to_lower(parts[0]) == "cpe" &&
                 parts[1].size() >= 2 && parts[1][0] == '/')
          products.push_back({&host, ProductRef{parts[3], parts[4], 0,
                                                "infra:" + parts[2]}});
      }
    }
    ctx.pstage("cve", "querying NVD", products.size());

    for (const auto& [host_p, pr] : products) {
      const HostResult& host = *host_p;
      auto cpe = cpe_for_product(pr.product, pr.version);
      std::string vendor, product;
      if (starts_with(pr.source, "infra:")) {
        vendor = pr.source.substr(6);
        product = to_lower(pr.product);
      } else if (cpe) {
        vendor = cpe->first;
        product = cpe->second;
      } else {
        continue;
      }

      ctx.pitem(pr.product + " " + pr.version);
      std::vector<CveEntry> entries;
      std::string err;
      ++queried;
      if (!nvd.fetch_cves(vendor, product, pr.version, entries, err)) {
        if (!warned_network) {
          ctx.warn("cve: " + err +
                   " — CVE results will be incomplete (use --nvd-key for "
                   "higher rate limits)");
          warned_network = true;
        }
        ctx.ptick();
        continue;
      }
      ctx.ptick();
      for (const auto& e : entries) {
        std::string prod_key = to_lower(pr.product);
        if (emitted.count({e.id, host.host, prod_key})) continue;
        emitted.insert({e.id, host.host, prod_key});

        Finding f;
        if (e.cvss > 0) {
          f.severity = severity_from_cvss(e.cvss);
        } else {
          f.severity = severity_from_nvd(e.severity);
        }

        // классификация матча
        std::string kind_note;
        if (e.match_kind == "exact" && e.version_verified) {
          kind_note = "version match confirmed against NVD rule";
        } else if (e.match_kind == "range" && e.version_verified) {
          kind_note = "version falls inside the NVD affected range";
        } else if (e.match_kind == "range") {
          // версия вне диапазона nvd, не пишем
          continue;
        } else if (e.match_kind == "exact") {
          // точный матч на другую версию, мимо
          continue;
        } else {
          // any/пусто: применимость не проверена, понижаем
          kind_note = e.match_kind == "any"
                          ? "vendor-wide NVD rule (version wildcard) - "
                            "applicability of this exact version is NOT "
                            "verified; treat as potential"
                          : "unverified: NVD returned no parseable CPE "
                            "configuration for this product; treat as "
                            "potential";
          f.severity = downgrade(f.severity);
        }
        f.module = "cve";
        f.host = host.host;
        f.port = pr.port;
        f.service = pr.source == "ports"
                        ? ("tcp/" + std::to_string(pr.port))
                        : pr.source;
        f.location = pr.port > 0 ? "tcp/" + std::to_string(pr.port)
                                 : pr.product + " " + pr.version;
        char score[16];
        std::snprintf(score, sizeof score, "%.1f", e.cvss);
        f.title = e.id + " (CVSS " + std::string(score) + ")";
        f.detail =
            "Detected " + pr.product + " " + pr.version + " (source: " +
            pr.source + "). " +
            (e.description.empty()
                 ? "A known vulnerability (" + e.id + ") is published for " +
                       pr.product + "."
                 : e.description) +
            " Match: " + kind_note +
            ". A version match is not proof of exploitability - verify "
            "against the vendor advisory before acting.";
        f.recommendation =
            "Upgrade " + pr.product + " to a release that fixes " + e.id +
            " per the vendor advisory, then re-scan to confirm.";
        f.evidence = e.match_rule.empty()
                         ? "NVD virtualMatchString cpe:2.3:a:" + vendor +
                               ":" + product + ":" + pr.version
                         : e.match_rule;
        f.references.push_back(
            "https://nvd.nist.gov/vuln/detail/" + e.id);
        ctx.result.add_finding(std::move(f));
        ++matched;
        if (e.version_verified) ++verified;
      }
      ctx.log("cve: " + std::to_string(entries.size()) + " CVEs for " +
              host.host + " " + pr.product + " " + pr.version + " (" +
              pr.source + ")");
    }
    ctx.pdone();
    if (queried == 0)
      ctx.log("cve: no versioned products detected (ports/tech/infra)");
    else
      ctx.log("cve: " + std::to_string(matched) + " findings (" +
              std::to_string(verified) + " version-verified) over " +
              std::to_string(queried) + " product queries");

    // exploit-db индекс, кэш 24ч
    std::map<std::string, std::vector<EdbEntry>> exploits;
    std::string edb_err;
    if (load_exploit_index(cfg.cache_dir.string(), exploits, edb_err)) {
      int enriched = 0;
      for (auto& f : ctx.result.findings) {
        if (f.module != "cve" && f.module != "infra") continue;
        std::string id = first_cve_id(f);
        if (id.empty()) continue;
        auto it = exploits.find(id);
        if (it == exploits.end()) continue;
        int added = 0;
        for (const auto& e : it->second) {
          if (added >= 3) break;
          std::string url = "https://www.exploit-db.com/exploits/" + e.id;
          if (std::find(f.references.begin(), f.references.end(), url) ==
              f.references.end()) {
            f.references.push_back(url);
            ++added;
          }
        }
        if (added > 0) {
          if (f.title.find("[public exploit]") == std::string::npos)
            f.title += " [public exploit]";
          ++enriched;
        }
      }
      if (enriched > 0)
        ctx.log("cve: " + std::to_string(enriched) +
                " finding(s) linked to public Exploit-DB entries");
    } else {
      ctx.log("cve: Exploit-DB index unavailable (" + edb_err + ")");
    }
    return true;
  }
};

}  // namespace

std::unique_ptr<IModule> make_cve_module() {
  return std::make_unique<CveModule>();
}

}  // namespace mikto
