// mikto — whois по tcp/43, ключи не нужны
#include "modules.hpp"

#include <chrono>

#include "mikto/osint.hpp"
#include "mikto/util.hpp"

namespace mikto {

namespace {

double days_until(const std::string& ymd) {
  // парс даты, параша -> 1e9
  if (ymd.size() < 10) return 1e9;
  auto mk = [](const std::string& s, int a, int b) {
    int v = 0;
    for (int i = a; i < b; ++i) {
      char c = s[i];
      if (!std::isdigit(static_cast<unsigned char>(c))) return -1;
      v = v * 10 + (c - '0');
    }
    return v;
  };
  int y = mk(ymd, 0, 4), m = mk(ymd, 5, 7), d = mk(ymd, 8, 10);
  if (y <= 1970 || m < 1 || m > 12 || d < 1 || d > 31) return 1e9;
  std::tm tm{};
  tm.tm_year = y - 1900;
  tm.tm_mon = m - 1;
  tm.tm_mday = d;
  time_t target = timegm(&tm);
  if (target < 0) return 1e9;
  time_t now = time(nullptr);
  return difftime(target, now) / 86400.0;
}

class WhoisModule : public IModule {
 public:
  std::string name() const override { return "whois"; }
  std::string description() const override {
    return "domain registration data from WHOIS (TCP/43, keyless): registrar, dates, contacts, nameservers";
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
      ctx.log("whois: no hostname targets — skipping");
      return true;
    }

    ctx.pstage("whois", "querying whois servers", domains.size());

    // сеть в пуле (TCP/43), применяет главный поток
    struct WhoisOut {
      WhoisInfo info;
      bool ok = false;
      std::string err;
      double ms = 0;
    };
    std::vector<WhoisOut> per_domain(domains.size());
    ctx.parallel(domains.size(), [&](size_t di) {
      const std::string& domain = domains[di];
      ctx.ptick();
      ctx.pitem(domain);
      WhoisOut& out = per_domain[di];
      auto t0 = std::chrono::steady_clock::now();
      out.info = whois_lookup(domain, 5000, &out.err);
      out.ok = out.info.ok;
      out.ms = std::chrono::duration<double, std::milli>(
                   std::chrono::steady_clock::now() - t0)
                   .count();
      ctx.trace("whois", domain,
                "domain " + domain + " (TCP/43, keyless)",
                out.ok ? ("ok: " +
                          (out.info.registrar.empty() ? std::string("?")
                                                      : out.info.registrar))
                       : ("failed: " + (out.err.empty() ? std::string("no data")
                                                        : out.err)),
                out.ok ? 0 : 1, 30, 800, out.ms);
    });

    for (size_t di = 0; di < domains.size(); ++di) {
      const std::string& domain = domains[di];
      WhoisOut& out = per_domain[di];
      WhoisInfo& info = out.info;
      if (!out.ok) {
        ctx.log("whois: no usable data for " + domain +
                (out.err.empty() ? "" : " (" + out.err + ")"));
        continue;
      }

      HostResult& hr = ctx.result.ensure_host(domain, false);
      hr.whois = info;
      // только имейлы своего домена, реестровый мусор долой (регресс на hidencloud)
      std::string root = to_lower(domain);
      for (const auto& e : info.emails) {
        std::string dom = e.substr(e.find('@') == std::string::npos
                                       ? std::string::npos
                                       : e.find('@') + 1);
        if (hr.emails.size() >= 30) break;
        if (dom != root && !ends_with(dom, "." + root)) continue;
        if (std::find(hr.emails.begin(), hr.emails.end(), e) ==
            hr.emails.end())
          hr.emails.push_back(e);
      }

      double days = days_until(info.expires);
      if (days < 30) {
        Finding f;
        f.severity = Severity::Medium;
        f.module = "whois";
        f.host = domain;
        f.service = "recon";
        f.location = "whois";
        f.title = "Domain expires in " +
                  std::to_string(days < 0 ? 0 : static_cast<int>(days)) +
                  " days";
        f.detail =
            "The registration expires on " + info.expires +
            ". An expired domain can be dropped and re-registered by anyone, "
            "which transfers mail (MX), certificates issuance rights (CAA "
            "notwithstanding) and every brand-trust relationship with it. "
            "Expired-domain hijacking is a well-known takeover vector.";
        f.recommendation =
            "Renew the domain now and move to multi-year registration with "
            "auto-renew plus registrar lock enabled.";
        f.evidence = "expires=" + info.expires;
        ctx.result.add_finding(std::move(f));
      } else if (days < 90) {
        Finding f;
        f.severity = Severity::Low;
        f.module = "whois";
        f.host = domain;
        f.service = "recon";
        f.location = "whois";
        f.title = "Domain expires soon (" +
                  std::to_string(static_cast<int>(days)) + " days)";
        f.detail =
            "The registration window ends on " + info.expires +
            ". Failure to renew (expired card, missed notice) is one of the "
            "most common real-world causes of site outages and mail loss.";
        f.recommendation =
            "Verify auto-renew is active and the billing contact is current.";
        f.evidence = "expires=" + info.expires;
        ctx.result.add_finding(std::move(f));
      }

      Finding f;
      f.severity = Severity::Info;
      f.module = "whois";
      f.host = domain;
      f.service = "recon";
      f.location = "whois";
      f.title = "Registration: " +
                (info.registrar.empty() ? "unknown registrar" : info.registrar);
      f.detail =
          "Registrar, lifecycle dates and contacts as published by the "
          "authoritative WHOIS server. Redacted-by-GDPR fields appear empty; "
          "that is the registry's choice, not a scan failure.";
      f.recommendation =
          "Keep registrant contact data current; enable registrar transfer "
          "lock and monitor expiry.";
      std::string ev = "registrar: " + info.registrar;
      if (!info.created.empty()) ev += "\ncreated:  " + info.created;
      if (!info.updated.empty()) ev += "\nupdated:  " + info.updated;
      if (!info.expires.empty()) ev += "\nexpires:  " + info.expires;
      if (!info.nameservers.empty()) {
        ev += "\nns: ";
        for (size_t i = 0; i < info.nameservers.size() && i < 4; ++i) {
          if (i) ev += ", ";
          ev += info.nameservers[i];
        }
      }
      f.evidence = ev;
      ctx.result.add_finding(std::move(f));
    }
    ctx.pdone();
    return true;
  }
};

}  // namespace

std::unique_ptr<IModule> make_whois_module() {
  return std::make_unique<WhoisModule>();
}

}  // namespace mikto
