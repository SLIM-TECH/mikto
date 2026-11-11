// mikto — пассивные сабдомены из публичных источников, потом dns-чек
#include "modules.hpp"

#include "mikto/win_compat.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <map>
#include <mutex>
#include <set>
#include <thread>
#include <vector>

#include "mikto/rate_limiter.hpp"
#include "mikto/util.hpp"

namespace mikto {

namespace {

struct Source {
  const char* name;
  std::string url;
};

std::vector<Source> sources_for(const std::string& domain) {
  std::vector<Source> out;
  std::string enc = domain;
  out.push_back({"crt.sh",
                 "https://crt.sh/?q=%25." + enc + "&output=json"});
  out.push_back({"urlscan.io",
                 "https://urlscan.io/api/v1/search/?q=domain%3A" + enc +
                     "&size=1000"});
  out.push_back({"hackertarget",
                 "https://api.hackertarget.com/hostsearch/?q=" + enc});
  out.push_back({"wayback",
                 "http://web.archive.org/cdx/search/cdx?url=*." + enc +
                     "&output=text&fl=original&collapse=urlkey&limit=4000"});
  return out;
}

bool valid_hostname_char(unsigned char c) {
  return std::isalnum(c) || c == '-' || c == '.';
}

bool looks_like_host(const std::string& s) {
  if (s.empty() || s.size() > 253) return false;
  if (s.find(' ') != std::string::npos) return false;
  if (s.find("..") != std::string::npos) return false;
  if (s.front() == '-' || s.back() == '-' || s.front() == '.' ||
      s.back() == '.')
    return false;
  for (unsigned char c : s)
    if (!valid_hostname_char(c)) return false;
  return s.find('.') != std::string::npos;
}

}  // namespace

// чистый экстрактор

void extract_hostnames(const std::string& text, const std::string& root_domain,
                       std::vector<std::string>& out) {
  std::string root = to_lower(root_domain);
  std::string low = to_lower(text);
  std::set<std::string> seen(out.begin(), out.end());

  size_t i = 0;
  while (i < low.size()) {
    size_t start = i;
    while (i < low.size() && valid_hostname_char(static_cast<unsigned char>(low[i])))
      ++i;
    if (i > start) {
      std::string tok = low.substr(start, i - start);
      if (tok.size() > root.size() + 1 && tok != root &&
          tok.compare(tok.size() - root.size(), root.size(), root) == 0 &&
          tok[tok.size() - root.size() - 1] == '.') {
        std::string sub = tok.substr(0, tok.size() - root.size() - 1);
        // мусор от wildcard и crt
        if (!sub.empty() && sub.find('*') == std::string::npos &&
            looks_like_host(tok)) {
          // максимум 4 лейбла до корня, иначе шум
          int dots = 0;
          for (char c : sub) if (c == '.') ++dots;
          if (dots <= 3 && seen.insert(tok).second) out.push_back(tok);
        }
      }
    }
    if (i < low.size()) ++i;  // разделитель
  }
}

// модуль

namespace {

bool resolve_host(const std::string& host, std::vector<std::string>& ips) {
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* res = nullptr;
  int rc = getaddrinfo(host.c_str(), nullptr, &hints, &res);
  if (rc != 0 || !res) return false;
  std::set<std::string> seen;
  for (addrinfo* ai = res; ai && ips.size() < 4; ai = ai->ai_next) {
    char buf[INET6_ADDRSTRLEN] = {0};
    if (ai->ai_family == AF_INET) {
      auto* sa = reinterpret_cast<sockaddr_in*>(ai->ai_addr);
      inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof buf);
    } else if (ai->ai_family == AF_INET6) {
      auto* sa = reinterpret_cast<sockaddr_in6*>(ai->ai_addr);
      inet_ntop(AF_INET6, &sa->sin6_addr, buf, sizeof buf);
    } else {
      continue;
    }
    if (seen.insert(buf).second) ips.push_back(buf);
  }
  freeaddrinfo(res);
  return !ips.empty();
}

class SubdomModule : public IModule {
 public:
  std::string name() const override { return "subdom"; }
  std::string description() const override {
    return "passive subdomain discovery from public sources (crt.sh, urlscan, wayback, hackertarget — no API key)";
  }
  Maturity maturity() const override { return Maturity::Preview; }
  std::vector<std::string> depends() const override { return {"assets"}; }

  bool run(ModuleContext& ctx) override {
    std::vector<std::string> domains;
    for (const auto& t : ctx.cfg.targets)
      if (!t.is_ip && std::find(domains.begin(), domains.end(), t.host) ==
                          domains.end())
        domains.push_back(t.host);
    if (domains.empty()) {
      ctx.log("subdom: no hostname targets (IP-only scan) — skipping");
      return true;
    }

    // 4 источника + слот под wildcard-чек на каждый домен
    ctx.pstage("subdom", "querying public sources", domains.size() * 5);

    HttpOptions opt;
    opt.timeout_s = 15;
    opt.user_agent = ctx.cfg.user_agent;
    opt.max_redirects = 2;
    opt.max_body_bytes = 4 * 1024 * 1024;

    for (const std::string& domain : domains) {
      // параллельно: самый медленный источник раньше тормозил всех
      auto sources = sources_for(domain);
      std::mutex res_mu;
      std::vector<std::pair<std::string, HttpResponse>> responses;
      std::vector<mikto_thread> fetchers;
      for (const Source& src : sources) {
        ctx.pitem(src.name);
        fetchers.emplace_back([&ctx, &opt, &src, &domain, &responses,
                               &res_mu]() {
          HttpResponse resp = ctx.get(src.url, opt);
          std::lock_guard<std::mutex> g(res_mu);
          responses.push_back({src.name, std::move(resp)});
          ctx.ptick();
        });
      }
      for (auto& t : fetchers) t.join();

      std::vector<std::string> found;
      std::set<std::string> failed_sources;
      for (auto& [name, resp] : responses) {
        if (!resp.ok_network() || resp.status != 200) {
          failed_sources.insert(name);
          continue;
        }
        // hackertarget при исчерпанной квоте печатает текст ошибки
        size_t before = found.size();
        extract_hostnames(resp.body, domain, found);
        if (found.size() == before &&
            to_lower(resp.body).find("api count") != std::string::npos)
          failed_sources.insert(name);
        (void)before;
      }
      ctx.ptick();  // слот под wildcard чек

      if (found.empty()) {
        ctx.log("subdom: no subdomains found for " + domain +
                (failed_sources.empty()
                     ? ""
                     : " (sources unreachable: " +
                           [&] {
                             std::string s;
                             for (const auto& f : failed_sources) {
                               if (!s.empty()) s += ", ";
                               s += f;
                             }
                             return s;
                           }() +
                           ")"));
        continue;
      }

      // сортируем и ограничиваем резолв
      std::sort(found.begin(), found.end());
      if (found.size() > 200) found.resize(200);

      ctx.pstage("subdom", "resolving " + domain, found.size() + 2);

      // wildcard: случайный лейбл не должен резолвиться
      // (clock+счётчик вместо rand(): потокобезопасно и без srand)
      ctx.pitem("wildcard check");
      static std::atomic<uint64_t> rnd_seq{0};
      uint64_t rndv =
          static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count()) +
          rnd_seq.fetch_add(1);
      std::string rnd = "mikto-rand-" + std::to_string(rndv % 1000000) +
                        "-" + std::to_string((rndv / 1000000) % 1000000);
      std::vector<std::string> wc_ips;
      bool wildcard = resolve_host(rnd + "." + domain, wc_ips);
      ctx.ptick();

      // 12 воркеров, иначе на медленном резолвере минуты
      ctx.pitem("resolving");
      HostResult& host = ctx.result.ensure_host(domain, false);
      host.wildcard_dns = wildcard;

      struct ResolveOutcome {
        std::string sub;
        bool ok = false;
        std::string first_ip;
      };
      std::vector<ResolveOutcome> outcomes(found.size());
      std::atomic<size_t> cursor{0};
      std::mutex out_mu;
      auto resolver = [&]() {
        for (;;) {
          size_t i = cursor.fetch_add(1);
          if (i >= found.size()) break;
          std::vector<std::string> ips;
          bool ok = resolve_host(found[i], ips);
          std::lock_guard<std::mutex> g(out_mu);
          outcomes[i] = {found[i], ok, ok && !ips.empty() ? ips.front() : ""};
          ctx.ptick();
        }
      };
      std::vector<mikto_thread> pool;
      int nthreads = 12;
      for (int i = 0; i < nthreads; ++i) pool.emplace_back(resolver);
      for (auto& t : pool) t.join();

      int resolved = 0;
      std::string evidence;
      for (const auto& o : outcomes) {
        if (!o.ok) continue;
        ++resolved;
        if (host.subdomains.size() < 100) host.subdomains.push_back(o.sub);
        if (evidence.size() < 400) {
          if (!evidence.empty()) evidence += ", ";
          evidence += o.sub;
        }
      }
      ctx.ptick();  // чтобы прогресс сходился

      Finding f;
      f.severity = Severity::Info;
      f.module = "subdom";
      f.host = domain;
      f.service = "recon";
      f.location = domain;
      f.title = std::to_string(resolved) + " of " +
                std::to_string(found.size()) + " subdomains resolve";
      f.detail =
          "Hostnames under " + domain +
          " were found in public certificate-transparency and archive "
          "datasets. They are listed for inventory only — mikto did NOT "
          "scan them. Add authorized names to the scan targets explicitly "
          "if they belong to you." +
          (wildcard
               ? " NOTE: a wildcard DNS record was detected for this zone; "
                 "non-resolving names may still exist."
               : "");
      f.recommendation =
          "Keep the subdomain inventory current; abandoned subdomains "
          "that still point to your infrastructure are a classic takeover "
          "target.";
      f.evidence = evidence + (evidence.size() >= 400 ? ", ..." : "");
      ctx.result.add_finding(std::move(f));
      ctx.log("subdom: " + std::to_string(resolved) + "/" +
              std::to_string(found.size()) + " subdomains resolve for " +
              domain);
    }
    ctx.pdone();
    return true;
  }
};

}  // namespace

std::unique_ptr<IModule> make_subdom_module() {
  return std::make_unique<SubdomModule>();
}

}  // namespace mikto
