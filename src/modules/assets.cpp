// mikto — полный dns рекон + tls осмотр
#include "modules.hpp"

#include "mikto/win_compat.hpp"

#include <chrono>
#include <set>
#include <vector>

#include "mikto/dns.hpp"
#include "mikto/util.hpp"

namespace mikto {

namespace {

double ms_since(std::chrono::steady_clock::time_point t0) {
  return std::chrono::duration<double, std::milli>(
             std::chrono::steady_clock::now() - t0)
      .count();
}

bool has_spf(const std::vector<DnsRecord>& recs) {
  for (const auto& r : recs)
    if (r.type == "TXT" && starts_with(to_lower(r.value), "v=spf1"))
      return true;
  return false;
}

bool has_dmarc(const std::vector<DnsRecord>& recs) {
  for (const auto& r : recs)
    if (r.type == "TXT" && to_lower(r.value).find("v=dmarc1") == 0)
      return true;
  return false;
}

class AssetsModule : public IModule {
 public:
  std::string name() const override { return "assets"; }
  std::string description() const override {
    return "DNS reconnaissance (A/AAAA/MX/NS/TXT/SOA/CAA/PTR, SPF+DMARC+CAA checks, deep: AXFR) and TLS certificate inspection";
  }
  Maturity maturity() const override { return Maturity::Preview; }

  bool run(ModuleContext& ctx) override {
    for (const auto& t : ctx.cfg.targets) {
      HostResult& hr = ctx.result.ensure_host(t.host, t.is_ip);
      if (t.is_ip) {
        hr.ips.push_back(t.host);
        do_reverse(ctx, hr);
        continue;
      }
      do_dns_recon(ctx, hr);
    }

    // tls собран в ports, тут только находки
    for (const auto& host : ctx.result.hosts) {
      if (!host.tls || !host.tls->ok) continue;
      const TlsInfo& ti = *host.tls;

      if (ti.days_until_expiry < 0) {
        Finding f;
        f.severity = Severity::High;
        f.module = "assets";
        f.host = host.host;
        f.port = 443;
        f.service = "tls";
        f.location = "certificate";
        f.title = "TLS certificate expired";
        f.detail = "The certificate served on " + host.host +
                   " expired on " + ti.not_after + ". Browsers and clients "
                   "reject expired certificates, which breaks availability "
                   "and trains users to click through warnings.";
        f.recommendation = "Renew the certificate immediately and enable "
                           "automated renewal (ACME).";
        f.evidence = "notAfter=" + ti.not_after;
        ctx.result.add_finding(std::move(f));
      } else if (ti.days_until_expiry <= 14) {
        Finding f;
        f.severity = Severity::Medium;
        f.module = "assets";
        f.host = host.host;
        f.port = 443;
        f.service = "tls";
        f.location = "certificate";
        f.title = "TLS certificate expires soon";
        f.detail = "The certificate on " + host.host + " expires in " +
                   std::to_string(ti.days_until_expiry) + " days (" +
                   ti.not_after + ").";
        f.recommendation = "Renew before expiry; ensure automated renewal is "
                           "in place and monitored.";
        f.evidence = "notAfter=" + ti.not_after;
        ctx.result.add_finding(std::move(f));
      }
      if (ti.self_signed) {
        Finding f;
        f.severity = Severity::Low;
        f.module = "assets";
        f.host = host.host;
        f.port = 443;
        f.service = "tls";
        f.location = "certificate";
        f.title = "Self-signed certificate";
        f.detail = "The certificate issuer equals its subject. Self-signed "
                   "certificates cannot be revoked and force clients to "
                   "bypass validation, normalising dangerous behaviour.";
        f.recommendation = "Use a CA-issued certificate (public CA or your "
                           "internal PKI) with automated renewal.";
        ctx.result.add_finding(std::move(f));
      }
      if (!ti.san_dns.empty()) {
        Finding f;
        f.severity = Severity::Info;
        f.module = "assets";
        f.host = host.host;
        f.port = 443;
        f.service = "tls";
        f.location = "certificate";
        f.title = "Certificate SANs (" + std::to_string(ti.san_dns.size()) +
                  " names)";
        f.detail =
            "The certificate lists additional DNS names. They are recorded "
            "here for your inventory only — mikto does NOT scan them unless "
            "you list them as targets explicitly.";
        f.recommendation = "Review the list; add authorized names to your "
                           "scan scope manually if they belong to you.";
        std::string ev;
        for (size_t i = 0; i < ti.san_dns.size() && i < 8; ++i) {
          if (i) ev += ", ";
          ev += ti.san_dns[i];
        }
        if (ti.san_dns.size() > 8) ev += ", ...";
        f.evidence = ev;
        ctx.result.add_finding(std::move(f));
      }
    }
    return true;
  }

 private:
  void do_reverse(ModuleContext& ctx, HostResult& hr) {
    auto t0 = std::chrono::steady_clock::now();
    std::string ptr = dns_reverse(hr.host);
    ctx.trace("dns", hr.host, "PTR " + hr.host,
              ptr.empty() ? "no PTR record" : ("PTR " + ptr), ptr.empty() ? 3 : 0,
              30, ptr.empty() ? 0 : ptr.size(), ms_since(t0));
    if (!ptr.empty())
      ctx.log("assets: PTR " + hr.host + " -> " + ptr);
  }

  void do_dns_recon(ModuleContext& ctx, HostResult& hr) {
    // записи
    auto t0 = std::chrono::steady_clock::now();
    std::string err;
    hr.dns_records = dns_all_records(hr.host, 2000, &err);
    double ms = ms_since(t0);
    if (!hr.dns_records.empty()) {
      int a = 0, mx = 0, ns = 0, txt = 0, other = 0;
      for (const auto& r : hr.dns_records) {
        if (r.type == "A" || r.type == "AAAA") ++a;
        else if (r.type == "MX") ++mx;
        else if (r.type == "NS") ++ns;
        else if (r.type == "TXT") ++txt;
        else ++other;
      }
      hr.ips.clear();
      for (const auto& r : hr.dns_records)
        if ((r.type == "A" || r.type == "AAAA") &&
            hr.ips.size() < 8 &&
            std::find(hr.ips.begin(), hr.ips.end(), r.value) == hr.ips.end())
          hr.ips.push_back(r.value);
      ctx.trace("dns", hr.host,
                "A/AAAA/MX/NS/TXT/SOA/CAA " + hr.host,
                std::to_string(hr.dns_records.size()) + " records (" +
                    std::to_string(a) + " addr, " + std::to_string(mx) +
                    " MX, " + std::to_string(ns) + " NS, " +
                    std::to_string(txt) + " TXT)",
                0, 90, 400, ms);
      ctx.log("assets: " + std::to_string(hr.dns_records.size()) +
              " DNS records for " + hr.host);
    } else {
      // фолбек на getaddrinfo, иначе на закрытых сетях глухо
      std::vector<std::string> ips;
      if (dns_resolve(hr.host, ips)) {
        hr.ips = ips;
        ctx.trace("dns", hr.host, "A/AAAA " + hr.host,
                  std::to_string(ips.size()) + " address(es) via system resolver",
                  0, 40, 200, ms);
      } else {
        ctx.trace("dns", hr.host, "A/AAAA/MX/NS/TXT/SOA/CAA " + hr.host,
                  "no answer" + (err.empty() ? "" : " (" + err + ")"), 0, 90, 0,
                  ms);
        ctx.warn("assets: DNS resolution failed for " + hr.host +
                 (err.empty() ? "" : ": " + err));
      }
    }

    // spf/dmarc/caa
    bool spf = has_spf(hr.dns_records);
    int mx_count = 0;
    for (const auto& r : hr.dns_records)
      if (r.type == "MX") ++mx_count;

    if (!spf) {
      Finding f;
      f.severity = mx_count > 0 ? Severity::Medium : Severity::Low;
      f.module = "assets";
      f.host = hr.host;
      f.service = "dns";
      f.location = "TXT";
      f.title = "No SPF record";
      f.detail =
          std::string(mx_count > 0
                          ? "The domain exchanges mail (MX records present) "
                            "but publishes no SPF policy. Anyone can forge "
                            "email From: this domain and recipients have no "
                            "cheap way to reject the forgery."
                          : "The domain publishes no SPF policy. If mail is "
                            "added later, forged email becomes trivially "
                            "possible; publishing SPF is a one-line change.") +
          " This also makes phishing that impersonates the brand easier.";
      f.recommendation =
          "Publish a TXT record like \"v=spf1 include:_spf.<provider> -all\" "
          "for every domain that can receive mail.";
      f.evidence = "no TXT record starting with v=spf1";
      ctx.result.add_finding(std::move(f));
    }

    auto t1 = std::chrono::steady_clock::now();
    int rc = 0;
    std::string derr;
    auto dmarc = dns_query("_dmarc." + hr.host, kDnsTXT, 2000, rc, derr);
    ctx.trace("dns", "_dmarc." + hr.host, "TXT _dmarc." + hr.host,
              dmarc.empty() ? "no record" : "TXT " + dmarc.front().value, 0, 60,
              dmarc.empty() ? 0 : 120, ms_since(t1));
    if (!has_dmarc(dmarc)) {
      Finding f;
      f.severity = Severity::Low;
      f.module = "assets";
      f.host = hr.host;
      f.service = "dns";
      f.location = "_dmarc." + hr.host;
      f.title = "No DMARC policy";
      f.detail =
          "DMARC tells receivers what to do with SPF/DKIM failures and gives "
          "you reports about abuse of the domain. Without it, even domains "
          "with SPF are commonly accepted by mailbox providers when SPF does "
          "not align, keeping spoofing viable.";
      f.recommendation =
          "Publish \"_dmarc.<domain> TXT v=Dmarc1; p=quarantine; "
          "rua=mailto:dmarc@<domain>\" (start with p=none while monitoring).";
      f.evidence = "no TXT v=Dmarc1 at _dmarc." + hr.host;
      ctx.result.add_finding(std::move(f));
    }

    bool caa = false;
    for (const auto& r : hr.dns_records)
      if (r.type == "CAA" && !r.value.empty()) caa = true;
    if (!caa) {
      Finding f;
      f.severity = Severity::Low;
      f.module = "assets";
      f.host = hr.host;
      f.service = "dns";
      f.location = "CAA";
      f.title = "No CAA record — any CA may issue certificates";
      f.detail =
          "Certificate Authority Authorization narrows which CAs are allowed "
          "to issue certificates for the domain. Without CAA every publicly "
          "trusted CA in the WebPKI ecosystem can issue a cert, so a CA "
          "incident or a mis-issued certificate cannot be prevented by policy.";
      f.recommendation =
          "Publish CAA records for the CAs you actually use, e.g. "
          "\"0 issue \"letsencrypt.org\"\", plus an iodef reporting address.";
      f.evidence = "no CAA records returned";
      ctx.result.add_finding(std::move(f));
    }

    // mx/ns резолвятся?
    int verified = 0;
    for (const auto& r : hr.dns_records) {
      if ((r.type != "MX" && r.type != "NS") || verified >= 6) continue;
      std::string host_part =
          r.type == "MX" ? (r.value.find(' ') == std::string::npos
                                ? r.value
                                : r.value.substr(r.value.find(' ') + 1))
                         : r.value;
      if (host_part.empty()) continue;
      ++verified;
      auto tv0 = std::chrono::steady_clock::now();
      std::vector<std::string> ips;
      dns_resolve(host_part, ips);
      ctx.trace("dns", host_part, "A/AAAA " + host_part + " (" + r.type + " verification)",
                ips.empty() ? "does not resolve"
                            : ("resolves: " + ips.front() +
                               (ips.size() > 1 ? " (+" +
                                                     std::to_string(ips.size() - 1) + ")"
                                               : "")),
                0, 40, ips.empty() ? 0 : 120, ms_since(tv0));
      if (ips.empty()) {
        Finding f;
        f.severity = Severity::Low;
        f.module = "assets";
        f.host = hr.host;
        f.service = "dns";
        f.location = r.type + " " + host_part;
        f.title = r.type + " target does not resolve";
        f.detail = "The " + r.type +
                   " record points at \"" + host_part +
                   "\" which has no A/AAAA record. Mail (or name service) "
                   "that depends on it silently fails, and dangling records "
                   "are a classic subdomain-takeover hunting ground.";
        f.recommendation = "Remove or fix the dangling " + r.type +
                           " record so it points at a live, allocated host.";
        f.evidence = r.type + " " + r.value + " -> NXDOMAIN/NODATA";
        ctx.result.add_finding(std::move(f));
      }
    }

    // axfr только в deep
    if (ctx.cfg.deep) {
      std::set<std::string> tried;
      for (const auto& r : hr.dns_records) {
        if (r.type != "NS" || tried.size() >= 3) continue;
        if (tried.insert(r.value).second) {
          auto ta0 = std::chrono::steady_clock::now();
          std::vector<std::string> zone;
          bool allowed = dns_axfr(hr.host, r.value, zone, 4000);
          ctx.trace("tcp", r.value + ":53",
                    "AXFR " + hr.host + " via TCP/53 to " + r.value,
                    allowed ? ("zone transferred: " +
                               std::to_string(zone.size()) + " records")
                            : "refused / failed",
                    allowed ? 0 : 5, 60, allowed ? 2000 : 0, ms_since(ta0));
          if (allowed) {
            hr.dns_zone_transfer = true;
            Finding f;
            f.severity = Severity::High;
            f.module = "assets";
            f.host = hr.host;
            f.service = "dns";
            f.location = r.value + ":53";
            f.title = "DNS zone transfer (AXFR) allowed";
            f.detail =
                "The nameserver " + r.value +
                " transferred the whole zone to an unauthenticated client. "
                "An attacker now has a complete map of the naming scheme — "
                "internal host names, staging systems and legacy services "
                "included — without scanning anything.";
            f.recommendation =
                "Restrict AXFR to approved secondaries (\"allow-transfer "
                "{ <secondaries>; };\" in BIND, identical controls on other "
                "servers) and confirm on every NS of the zone.";
            std::string ev;
            for (size_t i = 0; i < zone.size() && i < 12; ++i) {
              if (i) ev += "\n";
              ev += zone[i];
            }
            f.evidence = ev;
            ctx.result.add_finding(std::move(f));
          }
        }
      }
    }
  }
};

}  // namespace

std::unique_ptr<IModule> make_assets_module() {
  return std::make_unique<AssetsModule>();
}

}  // namespace mikto
