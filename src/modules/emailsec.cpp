// mikto — качество почтовых политик (spf/dmarc/dkim/mta-sts/dnssec), только dns
#include "modules.hpp"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <set>
#include <vector>

#include "mikto/dns.hpp"
#include "mikto/rate_limiter.hpp"
#include "mikto/util.hpp"

namespace mikto {

// чистые оценки

SpfPolicy evaluate_spf(const std::string& record) {
  SpfPolicy out;
  std::string low = to_lower(record);
  std::vector<std::string> tokens = split(low, ' ');
  if (tokens.empty() || tokens[0] != "v=spf1") return out;
  out.valid = true;

  for (const std::string& tok : tokens) {
    if (tok.empty()) continue;
    if (tok == "all" || tok == "+all") {
      out.all_policy = "allow_all";
    } else if (tok == "-all") {
      out.all_policy = "fail";
    } else if (tok == "~all") {
      out.all_policy = "softfail";
    } else if (tok == "?all") {
      out.all_policy = "neutral";
    } else if (tok.rfind("include:", 0) == 0) {
      ++out.lookup_count;
      out.includes.push_back(tok.substr(8));
    } else if (tok.rfind("redirect=", 0) == 0 ||
               tok.rfind("exists:", 0) == 0) {
      ++out.lookup_count;
    } else if (tok == "a" || tok == "mx" || tok == "ptr") {
      ++out.lookup_count;
    } else if (tok.rfind("a:", 0) == 0 || tok.rfind("mx:", 0) == 0) {
      ++out.lookup_count;
    } else if (tok.rfind("ip4:", 0) == 0) {
      std::string ip = tok.substr(4);
      // приватные диапазоны в публичной записи
      if (ip.rfind("0.0.0.0", 0) == 0 || ip.rfind("127.", 0) == 0 ||
          ip.rfind("10.", 0) == 0 || ip.rfind("192.168.", 0) == 0 ||
          ip.rfind("169.254.", 0) == 0)
        out.private_ip4 = true;
      if (ip.rfind("172.", 0) == 0) {
        // 172.16.0.0/12
        std::vector<std::string> parts = split(ip, '.');
        if (parts.size() >= 2) {
          int o2 = std::atoi(parts[1].c_str());
          if (o2 >= 16 && o2 <= 31) out.private_ip4 = true;
        }
      }
    }
  }
  if (out.all_policy.empty()) out.all_policy = "missing";
  return out;
}

DmarcPolicy evaluate_dmarc(const std::string& record) {
  DmarcPolicy out;
  std::string low = to_lower(record);
  std::vector<std::string> tags = split(low, ';');
  for (std::string tag : tags) {
    tag = trim(tag);
    size_t eq = tag.find('=');
    if (eq == std::string::npos) continue;
    std::string key = trim(tag.substr(0, eq));
    std::string val = trim(tag.substr(eq + 1));
    if (key == "v") {
      if (val == "dmarc1") out.valid = true;
    } else if (key == "p") {
      out.p = val;
    } else if (key == "sp") {
      out.sp = val;
    } else if (key == "rua") {
      out.has_rua = !val.empty();
    } else if (key == "pct") {
      int n = std::atoi(val.c_str());
      if (n >= 0 && n <= 100) out.pct = n;
    }
  }
  return out;
}

const std::vector<std::string>& dkim_selectors() {
  static const std::vector<std::string> sels = {
      "google",   "default", "selector1", "selector2", "s1",   "s2",
      "k1",       "mail",    "dkim",      "smtp",      "mandrill",
      "api",      "zendesk", "freshmail", "ebay",      "everlytic"};
  return sels;
}

// модуль

namespace {

std::vector<DnsRecord> txt_query(ModuleContext& ctx, const std::string& qname,
                                 int& rcode) {
  auto t0 = std::chrono::steady_clock::now();
  std::string err;
  auto recs = dns_query(qname, kDnsTXT, 2000, rcode, err);
  double ms = std::chrono::duration<double, std::milli>(
                  std::chrono::steady_clock::now() - t0)
                  .count();
  std::string resp = recs.empty() ? (err.empty() ? "no record" : "error: " + err)
                                  : "TXT " + recs.front().value;
  ctx.trace("dns", qname, "TXT " + qname, resp, rcode, 50,
            recs.empty() ? 0 : recs.front().value.size(), ms);
  return recs;
}

void add_finding(ModuleContext& ctx, Severity sev, const std::string& host,
                 const std::string& location, const std::string& title,
                 const std::string& detail, const std::string& rec,
                 const std::string& evidence,
                 std::vector<std::string> refs = {}) {
  Finding f;
  f.severity = sev;
  f.module = "emailsec";
  f.host = host;
  f.service = "email/dns";
  f.location = location;
  f.title = title;
  f.detail = detail;
  f.recommendation = rec;
  f.evidence = evidence;
  f.references = std::move(refs);
  ctx.result.add_finding(std::move(f));
}

class EmailsecModule : public IModule {
 public:
  std::string name() const override { return "emailsec"; }
  std::string description() const override {
    return "e-mail security posture: SPF/DMARC policy quality, DKIM selectors, "
           "MTA-STS, TLS-RPT, DNSSEC (DNS-only, passive)";
  }
  Maturity maturity() const override { return Maturity::Preview; }
  std::vector<std::string> depends() const override { return {"assets"}; }

  bool run(ModuleContext& ctx) override {
    std::vector<std::string> domains;
    for (const auto& t : ctx.cfg.targets)
      if (!t.is_ip &&
          std::find(domains.begin(), domains.end(), t.host) == domains.end())
        domains.push_back(t.host);
    if (domains.empty()) return true;

    // тик раз за домен: внутри условные чеки, точный count заранее неизвестен
    ctx.pstage("emailsec", "evaluating e-mail security", domains.size());

    for (const std::string& domain : domains) {
      HostResult& hr = ctx.result.ensure_host(domain, false);
      check_domain(ctx, domain, hr);
      ctx.ptick();
    }
    ctx.pdone();
    return true;
  }

 private:
  static int mx_count(const HostResult& hr) {
    int n = 0;
    for (const auto& r : hr.dns_records)
      if (r.type == "MX") ++n;
    return n;
  }

  void check_domain(ModuleContext& ctx, const std::string& domain,
                    HostResult& hr) {
    const bool has_mx = mx_count(hr) > 0;

    // spf качество (assets уже сказал что его нет)
    std::vector<std::string> spf_records;
    for (const auto& r : hr.dns_records)
      if (r.type == "TXT" && to_lower(trim(r.value)).rfind("v=spf1", 0) == 0)
        spf_records.push_back(r.value);

    if (spf_records.size() > 1) {
      add_finding(
          ctx, Severity::High, domain, "TXT",
          "Multiple SPF records — receivers must discard them all",
          "RFC 7208 requires exactly one v=spf1 record per domain. When two "
          "or more are present the result is a permerror: most receivers "
          "treat the policy as broken, so the published SPF gives no "
          "protection at all.",
          "Merge all mechanisms into a single v=spf1 TXT record and delete "
          "the duplicates.",
          std::to_string(spf_records.size()) + " v=spf1 TXT records found",
          {"https://www.rfc-editor.org/rfc/rfc7208"});
    }
    if (!spf_records.empty()) {
      SpfPolicy spf = evaluate_spf(spf_records[0]);
      if (spf.all_policy == "allow_all") {
        add_finding(
            ctx, Severity::Critical, domain, "TXT",
            "SPF permits any sender (+all)",
            "The +all mechanism authorizes EVERY host on the internet to "
            "send mail as this domain. SPF as published provides zero "
            "spoofing protection — this is the weakest possible policy.",
            "Replace +all with -all (or ~all during a transition) and list "
            "only the actual sending infrastructure via include:/ip4:.",
            "mechanism +all present",
            {"https://www.rfc-editor.org/rfc/rfc7208"});
      } else if (spf.all_policy == "missing") {
        add_finding(
            ctx, Severity::High, domain, "TXT",
            "SPF record has no 'all' mechanism",
            "Without an all mechanism the policy defaults to ?all "
            "(neutral): any host not explicitly listed is still authorized "
            "by receivers that ignore neutral results. Forgeries pass "
            "SPF checks.",
            "Append -all (strict) or ~all (softfail during rollout) to the "
            "record.",
            "no all mechanism in v=spf1",
            {"https://www.rfc-editor.org/rfc/rfc7208"});
      } else if (spf.all_policy == "neutral") {
        add_finding(
            ctx, Severity::Low, domain, "TXT",
            "SPF uses ?all (neutral) — forgeries largely pass",
            "?all declares 'unknown' for unlisted hosts; most receivers "
            "accept such mail, so the record barely limits spoofing.",
            "Use ~all (softfail) or -all (hardfail) once all senders are "
            "listed.",
            "mechanism ?all present",
            {"https://www.rfc-editor.org/rfc/rfc7208"});
      } else if (spf.all_policy == "softfail") {
        add_finding(
            ctx, Severity::Info, domain, "TXT",
            "SPF is enforced in softfail mode (~all)",
            "Unlisted senders get a softfail verdict: legitimate during a "
            "rollout, but spoofed mail is usually still delivered to spam "
            "folders rather than rejected.",
            "Switch to -all once DMARC reports confirm the sender list is "
            "complete.",
            "mechanism ~all present",
            {"https://www.rfc-editor.org/rfc/rfc7208"});
      } else {
        add_finding(
            ctx, Severity::Info, domain, "TXT",
            "SPF policy is strict (-all)",
            "The domain publishes a hardfail SPF policy: only listed "
            "infrastructure may send as the domain.",
            "Keep the record synchronized with the real sender list.",
            "mechanism -all present",
            {"https://www.rfc-editor.org/rfc/rfc7208"});
      }
      if (spf.lookup_count > 10) {
        add_finding(
            ctx, Severity::High, domain, "TXT",
            "SPF DNS lookup limit exceeded (" + std::to_string(spf.lookup_count) +
                " > 10)",
            "RFC 7208 allows at most 10 DNS lookups (include/a/mx/ptr/"
            "exists/redirect) per SPF evaluation. Beyond that the result is "
            "a permanent error and receivers discard the policy — the "
            "domain loses SPF protection entirely.",
            "Flatten the record: replace nested includes with direct ip4: "
            "ranges provided by the mail provider.",
            std::to_string(spf.lookup_count) + " DNS-consuming mechanisms",
            {"https://www.rfc-editor.org/rfc/rfc7208"});
      }
      if (spf.private_ip4) {
        add_finding(
            ctx, Severity::Low, domain, "TXT",
            "SPF references loopback/private IP ranges",
            "The record lists loopback or RFC1918 addresses. They can never "
            "be matched by real internet mail and usually come from "
            "copy-pasted vendor examples.",
            "Remove the private ip4: entries.",
            "private ip4: range present",
            {"https://www.rfc-editor.org/rfc/rfc7208"});
      }
    }

    // dmarc
    int rc = 0;
    auto dmarc_recs = txt_query(ctx, "_dmarc." + domain, rc);
    std::string dmarc_record;
    for (const auto& r : dmarc_recs) {
      if (to_lower(trim(r.value)).rfind("v=dmarc1", 0) == 0) {
        dmarc_record = r.value;
        break;
      }
    }
    if (!dmarc_record.empty()) {
      DmarcPolicy dp = evaluate_dmarc(dmarc_record);
      if (!dp.valid || dp.p.empty()) {
        add_finding(
            ctx, Severity::High, domain, "_dmarc." + domain,
            "DMARC record is malformed (p= missing)",
            "A v=DMARC1 record without a valid p= tag is treated as no "
            "policy: receivers cannot apply any action to failing mail.",
            "Set p=quarantine or p=reject explicitly.",
            "record: " + truncate_ellipsis(dmarc_record, 100),
            {"https://www.rfc-editor.org/rfc/rfc7489"});
      } else if (dp.p == "none") {
        add_finding(
            ctx, Severity::Low, domain, "_dmarc." + domain,
            "DMARC policy is p=none (monitoring only)",
            "p=none asks receivers to do nothing with failing mail — "
            "spoofed messages still reach inboxes. Useful while collecting "
            "reports, but not an end state.",
            "After reviewing rua reports move to p=quarantine, then "
            "p=reject.",
            "p=none" + std::string(dp.has_rua ? "" : "; no rua= reports"),
            {"https://www.rfc-editor.org/rfc/rfc7489"});
        if (!dp.has_rua) {
          add_finding(
              ctx, Severity::Low, domain, "_dmarc." + domain,
              "DMARC has no rua= report address",
              "Without aggregate reports there is no feedback about who "
              "sends as the domain — the main input for tightening the "
              "policy safely.",
              "Add rua=mailto:dmarc@<domain> (an address that can handle "
              "XML reports).",
              "no rua tag",
              {"https://www.rfc-editor.org/rfc/rfc7489"});
        }
      } else {
        add_finding(
            ctx, Severity::Info, domain, "_dmarc." + domain,
            "DMARC policy is enforced (p=" + dp.p + ")",
            "Failing mail is " +
                (dp.p == "reject" ? std::string("rejected")
                                  : std::string("quarantined")) +
                " by compliant receivers. Spoofing of this domain is "
                "actively blocked.",
            "Keep monitoring rua reports for legitimate senders breaking.",
            "p=" + dp.p + (dp.pct < 100 ? "; pct=" + std::to_string(dp.pct) : ""),
            {"https://www.rfc-editor.org/rfc/rfc7489"});
        if (dp.pct < 100) {
          add_finding(
              ctx, Severity::Info, domain, "_dmarc." + domain,
              "DMARC applies to only " + std::to_string(dp.pct) +
                  "% of messages (pct=)",
              "The pct tag throttles policy application; the remaining "
              "failing messages pass through unchecked.",
              "Raise pct to 100 once reports confirm no legitimate mail is "
              "affected.",
              "pct=" + std::to_string(dp.pct),
              {"https://www.rfc-editor.org/rfc/rfc7489"});
        }
        if (dp.sp == "none") {
          add_finding(
              ctx, Severity::Low, domain, "_dmarc." + domain,
              "DMARC sp=none leaves subdomains unprotected",
              "The subdomain policy explicitly disables enforcement for "
              "all subdomains — a common spoofing bypass targeting "
              "mail.<domain>-style names.",
              "Set sp=quarantine or sp=reject once subdomain senders are "
              "known.",
              "sp=none",
              {"https://www.rfc-editor.org/rfc/rfc7489"});
        }
      }
    }

    // dkim
    std::string dkim_found;
    for (const std::string& sel : dkim_selectors()) {
      int rcd = 0;
      auto recs = txt_query(ctx, sel + "._domainkey." + domain, rcd);
      for (const auto& r : recs) {
        std::string v = to_lower(trim(r.value));
        if (v.find("v=dkim1") != std::string::npos ||
            v.find("p=") != std::string::npos) {
          dkim_found = sel;
          break;
        }
      }
      if (!dkim_found.empty()) break;
    }
    if (!dkim_found.empty()) {
      add_finding(
          ctx, Severity::Info, domain, dkim_found + "._domainkey." + domain,
          "DKIM signing confirmed (selector '" + dkim_found + "')",
          "A DKIM public key is published at this selector, so outbound "
          "mail can be cryptographically signed and verified by receivers "
          "together with DMARC alignment.",
          "Rotate DKIM keys periodically; keep both old and new selectors "
          "published during rotation.",
          "TXT v=DKIM1 published",
          {"https://www.rfc-editor.org/rfc/rfc6376"});
    } else if (has_mx) {
      add_finding(
          ctx, Severity::Low, domain, "*._domainkey." + domain,
          "No DKIM record found on common selectors",
          "The domain exchanges mail but none of the most common DKIM "
          "selectors is published. Note: a non-standard selector may still "
          "exist — this check is best-effort, not proof of absence.",
          "If DKIM is used, verify the selector name; if not, enable DKIM "
          "signing — DMARC alignment depends on it when SPF alignment is "
          "impossible.",
          "no v=DKIM1 record on " + std::to_string(dkim_selectors().size()) +
              " common selectors",
          {"https://www.rfc-editor.org/rfc/rfc6376"});
    }

    // mta-sts
    int rcm = 0;
    auto sts = txt_query(ctx, "_mta-sts." + domain, rcm);
    bool sts_ok = false;
    for (const auto& r : sts)
      if (to_lower(trim(r.value)).rfind("v=sts1", 0) == 0) sts_ok = true;
    if (sts_ok) {
      add_finding(
          ctx, Severity::Info, domain, "_mta-sts." + domain,
          "MTA-STS policy record published",
          "The domain advertises MTA-STS: sending servers are instructed "
          "to require a valid TLS certificate on the MX host. (mikto reads "
          "the DNS record only; it does not fetch the HTTPS policy file.)",
          "Keep the policy id fresh on every policy change so caches "
          "invalidate.",
          "TXT v=STS1 present",
          {"https://www.rfc-editor.org/rfc/rfc8461"});
    } else if (has_mx) {
      add_finding(
          ctx, Severity::Low, domain, "_mta-sts." + domain,
          "No MTA-STS record — SMTP connections fall back to plain TCP",
          "Without MTA-STS an active attacker can strip TLS on inbound "
          "SMTP connections even though the MX hosts may support it "
          "(STARTTLS downgrade).",
          "Publish an MTA-STS DNS record plus the policy file under "
          "https://mta-sts.<domain>/.well-known/mta-sts.txt.",
          "no v=STS1 record",
          {"https://www.rfc-editor.org/rfc/rfc8461"});
    }

    // tls-rpt
    int rct = 0;
    auto trpt = txt_query(ctx, "_smtp._tls." + domain, rct);
    bool trpt_ok = false;
    for (const auto& r : trpt)
      if (to_lower(trim(r.value)).rfind("v=tlsrptv1", 0) == 0) trpt_ok = true;
    if (trpt_ok) {
      add_finding(
          ctx, Severity::Info, domain, "_smtp._tls." + domain,
          "TLS-RPT record published",
          "The domain requests TLS failure reports from sending servers, "
          "giving visibility into STARTTLS downgrade attempts and "
          "certificate problems.",
          "Keep the reporting endpoint healthy.",
          "TXT v=TLSRPTv1 present",
          {"https://www.rfc-editor.org/rfc/rfc8460"});
    } else if (has_mx) {
      add_finding(
          ctx, Severity::Low, domain, "_smtp._tls." + domain,
          "No TLS-RPT record — TLS problems on inbound SMTP stay invisible",
          "Without TLS-RPT nobody gets aggregate reports about failed "
          "opportunistic TLS towards the MX hosts.",
          "Publish \"_smtp._tls.<domain> TXT v=TLSRPTv1; rua=mailto:...\".",
          "no v=TLSRPTv1 record",
          {"https://www.rfc-editor.org/rfc/rfc8460"});
    }

    // dnssec
    {
      auto t0 = std::chrono::steady_clock::now();
      std::string err;
      int rck = 0;
      auto keys = dns_query(domain, kDnsDNSKEY, 2500, rck, err);
      double ms = std::chrono::duration<double, std::milli>(
                      std::chrono::steady_clock::now() - t0)
                      .count();
      ctx.trace("dns", domain, "DNSKEY " + domain,
                keys.empty() ? (err.empty() ? "no DNSKEY (rcode " +
                                                  std::to_string(rck) + ")"
                                             : "error: " + err)
                             : "DNSKEY present",
                rck, 60, keys.empty() ? 0 : 300, ms);
      if (err.empty()) {
        if (!keys.empty()) {
          add_finding(
              ctx, Severity::Info, domain, "DNSKEY",
              "Zone is DNSSEC-signed",
              "DNS answers for this zone can be cryptographically "
              "validated, which prevents resolver cache poisoning for the "
              "whole domain (including SPF/DKIM/DMARC records).",
              "Keep signatures renewed before expiry.",
              "DNSKEY RRset present",
              {"https://www.rfc-editor.org/rfc/rfc4034"});
        } else {
          add_finding(
              ctx, Severity::Low, domain, "DNSKEY",
              "Zone is not DNSSEC-signed",
              "Without DNSSEC a network attacker can forge DNS answers for "
              "the domain — including the MX/TXT records that e-mail "
              "security (SPF, DKIM, DMARC, MTA-STS) depends on.",
              "Sign the zone at the registrar/DNS provider and publish the "
              "DS record in the parent zone.",
              "no DNSKEY returned (rcode " + std::to_string(rck) + ")",
              {"https://www.rfc-editor.org/rfc/rfc4034"});
        }
      }
    }

    // caa (позитив, отсутствие уже в assets)
    {
      std::vector<std::string> caa;
      for (const auto& r : hr.dns_records)
        if (r.type == "CAA" && !r.value.empty()) caa.push_back(r.value);
      if (!caa.empty()) {
        std::string ev;
        for (size_t i = 0; i < caa.size() && i < 4; ++i)
          ev += (i ? ", " : "") + caa[i];
        if (caa.size() > 4) ev += ", ...";
        add_finding(
            ctx, Severity::Info, domain, "CAA",
            "CAA records restrict certificate issuance",
            "Only the CAs listed in these records may issue certificates "
            "for the domain; mis-issuance by other CAs is reportable and "
            "should be blocked by auditors.",
            "Keep the list in sync with the CAs actually used; add an "
            "iodef= mailto: address for incident reports.",
            ev,
            {"https://www.rfc-editor.org/rfc/rfc8659"});
      }
    }
  }
};

}  // namespace

std::unique_ptr<IModule> make_emailsec_module() {
  return std::make_unique<EmailsecModule>();
}

}  // namespace mikto
