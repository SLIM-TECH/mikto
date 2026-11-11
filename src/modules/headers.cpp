// mikto — security заголовки и куки
#include <algorithm>
#include <cctype>
#include "modules.hpp"

#include <algorithm>
#include <cstdlib>
#include <map>
#include <set>
#include <vector>

#include "mikto/rate_limiter.hpp"
#include "mikto/util.hpp"
#include "web_common.hpp"

namespace mikto {

// чистый анализ

CookieFlags parse_cookie_flags(const std::string& setcookie) {
  // матчим токен целиком, иначе value "secure-dark" даёт ложняк
  CookieFlags out;
  size_t pos = 0;
  while (pos < setcookie.size()) {
    size_t semi = setcookie.find(';', pos);
    if (semi == std::string::npos) semi = setcookie.size();
    std::string attr = trim(setcookie.substr(pos, semi - pos));
    pos = semi + 1;
    std::string low = to_lower(attr);
    size_t eq = low.find('=');
    if (eq != std::string::npos) low = trim(low.substr(0, eq));
    if (low == "secure") out.secure = true;
    else if (low == "httponly") out.httponly = true;
    else if (low == "samesite") out.samesite = true;
  }
  return out;
}

std::vector<Finding> analyze_security_headers(const HeaderCheckInput& in,
                                              WebResult& w) {
  std::vector<Finding> out;
  auto add = [&](Severity sev, const std::string& title,
                 const std::string& location, const std::string& detail,
                 const std::string& rec, const std::string& evidence = "") {
    Finding f;
    f.severity = sev;
    f.module = "headers";
    f.host = in.host;
    f.port = in.port;
    f.service = "web";
    f.location = location;
    f.title = title;
    f.detail = detail;
    f.recommendation = rec;
    f.evidence = evidence;
    out.push_back(std::move(f));
  };

  const bool https = in.https;
  const std::string csp = w.header("Content-Security-Policy");
  const std::string hsts = w.header("Strict-Transport-Security");
  const std::string xcto = w.header("X-Content-Type-Options");
  const std::string xfo = w.header("X-Frame-Options");
  const std::string rp = w.header("Referrer-Policy");
  const std::string pp = w.header("Permissions-Policy");
  const std::string server = w.header("Server");
  const std::string xpb = w.header("X-Powered-By");
  const std::string acao = w.header("Access-Control-Allow-Origin");

  if (https && hsts.empty()) {
    add(Severity::Medium, "Missing Strict-Transport-Security",
        "header:Strict-Transport-Security",
        "The site is served over HTTPS but does not send HSTS. A visitor "
        "who types the domain, or follows a plain http:// link, can be "
        "downgraded to an unencrypted connection by an attacker on the "
        "path (SSL-stripping).",
        "Send 'Strict-Transport-Security: max-age=31536000; "
        "includeSubDomains' from all HTTPS responses; consider preload "
        "once the policy is stable.");
  } else if (https && !hsts.empty()) {
    size_t ma = to_lower(hsts).find("max-age=");
    if (ma != std::string::npos) {
      long age = std::strtol(hsts.c_str() + ma + 8, nullptr, 10);
      if (age > 0 && age < 15552000) {
        add(Severity::Low, "Weak HSTS max-age",
            "header:Strict-Transport-Security",
            "HSTS is present but max-age is below the recommended 180 "
            "days, which weakens downgrade protection for infrequent "
            "visitors.",
            "Raise max-age to at least 15552000 (180 days) once you are "
            "confident all subdomains serve HTTPS.",
            hsts);
      }
    }
  }

  if (csp.empty()) {
    add(Severity::Medium, "Missing Content-Security-Policy",
        "header:Content-Security-Policy",
        "No Content-Security-Policy was sent. CSP is the main second line "
        "of defence against cross-site scripting: without it, any injected "
        "script runs with full page privileges.",
        "Deploy a CSP, starting in report-only mode: 'Content-Security-"
        "Policy-Report-Only: default-src 'self''. Tighten gradually and "
        "switch to enforcing.");
  }

  if (!iequals(xcto, "nosniff")) {
    add(Severity::Low, "X-Content-Type-Options missing or wrong",
        "header:X-Content-Type-Options",
        "The response does not enforce 'nosniff', so browsers may "
        "mime-sniff user-supplied content and execute it as script or "
        "style.",
        "Send 'X-Content-Type-Options: nosniff' on every response.");
  }

  if (xfo.empty() && csp.find("frame-ancestors") == std::string::npos) {
    add(Severity::Low, "No clickjacking protection",
        "header:X-Frame-Options",
        "Neither X-Frame-Options nor a CSP frame-ancestors directive was "
        "found, so the page can be framed by third-party sites (clickjacking "
        "and UI-redress attacks).",
        "Send 'X-Frame-Options: DENY' (or SAMEORIGIN) and/or add a "
        "frame-ancestors directive to the CSP.");
  }

  if (rp.empty()) {
    add(Severity::Low, "Missing Referrer-Policy",
        "header:Referrer-Policy",
        "Without a Referrer-Policy the default referrer (often the full "
        "URL) leaks internal paths, session identifiers in URLs, and "
        "intranet hostnames to third parties.",
        "Send 'Referrer-Policy: strict-origin-when-cross-origin' (or "
        "'no-referrer' for sensitive apps).");
  }

  if (pp.empty()) {
    add(Severity::Info, "Missing Permissions-Policy",
        "header:Permissions-Policy",
        "No Permissions-Policy header was sent; the browser will allow "
        "powerful features (camera, microphone, geolocation) on embedded "
        "frames by default.",
        "Declare the features you actually use, e.g. 'Permissions-Policy: "
        "camera=(), microphone=(), geolocation=()'.");
  }

  // палево версий
  if (!server.empty()) {
    bool has_version = false;
    for (size_t i = 0; i + 1 < server.size(); ++i)
      if (std::isdigit(static_cast<unsigned char>(server[i])) &&
          server[i + 1] == '.')
        has_version = true;
    if (has_version) {
      add(Severity::Low, "Server version disclosure",
          "header:Server",
          "The Server header advertises the exact software version. This "
          "lets an attacker pick matching exploits without probing.",
          "Suppress or generalise the version (e.g. server_tokens off in "
          "nginx, ServerTokens Prod in Apache).",
          server);
    }
  }
  if (!xpb.empty()) {
    add(Severity::Low, "X-Powered-By disclosure",
        "header:X-Powered-By",
        "The application framework is disclosed via X-Powered-By, which "
        "simplifies fingerprinting for attackers.",
        "Remove the X-Powered-By header (e.g. expose_php=Off, "
        "app.disable('x-powered-by')).",
        xpb);
  }

  // cors
  if (acao == "*") {
    bool creds = iequals(w.header("Access-Control-Allow-Credentials"), "true");
    add(creds ? Severity::Medium : Severity::Info,
        "Permissive CORS policy", "header:Access-Control-Allow-Origin",
        creds
            ? "Access-Control-Allow-Origin: * combined with Allow-Credentials "
              "is an invalid and dangerous combination; any origin is invited "
              "to interact with authenticated endpoints."
            : "The site allows any origin to read responses. This is "
              "acceptable for public data, but risky if any endpoint returns "
              "user-specific content.",
        "Reflect an explicit allow-list of origins instead of '*', and "
        "never combine '*' with credentials.",
        acao);
  }

  // куки
  int cookie_findings = 0;
  for (const std::string& cookie : w.headers_all("Set-Cookie")) {
    if (cookie_findings >= 5) break;
    size_t eq = cookie.find('=');
    std::string name = eq == std::string::npos ? cookie : cookie.substr(0, eq);
    name = trim(name);
    CookieFlags flags = parse_cookie_flags(cookie);
    if (flags.secure && flags.httponly && flags.samesite) continue;
    ++cookie_findings;
    std::string missing;
    Severity sev = Severity::Low;
    if (https && !flags.secure) {
      missing += "Secure; ";
      sev = Severity::Medium;
    }
    if (!flags.httponly) missing += "HttpOnly; ";
    if (!flags.samesite) missing += "SameSite; ";
    add(sev, "Cookie without protective flags: " + name, "header:Set-Cookie",
        "The cookie '" + name + "' is missing the following flags: " +
            missing +
            ". Without them the cookie can travel over plaintext links, be "
            "read by scripts, or be sent on cross-site requests (CSRF).",
        "Set 'Secure; HttpOnly; SameSite=Lax' (or Strict) on session "
        "cookies.",
        truncate_ellipsis(cookie, 300));
  }

  if (!https && w.status == 200) {
    add(Severity::Info, "HTTP serves content without redirect to HTTPS",
        "response",
        "The site responds over plain HTTP with 200 and does not redirect "
        "to HTTPS; any content and credentials submitted here travel "
        "unencrypted.",
        "Redirect all HTTP traffic (301/308) to the HTTPS host and enable "
        "HSTS.");
  }
  return out;
}

// модуль

namespace {

class HeadersModule : public IModule {
 public:
  std::string name() const override { return "headers"; }
  std::string description() const override {
    return "security headers and cookie flags analysis (HSTS, CSP, XCTO, cookies, disclosure)";
  }
  Maturity maturity() const override { return Maturity::Reference; }
  std::vector<std::string> depends() const override { return {"ports"}; }

  bool run(ModuleContext& ctx) override {
    size_t n = 0;
    for (const auto& t : ctx.cfg.targets) {
      const HostResult* hr = ctx.result.find_host(t.host);
      n += urls_for_target(t, hr).size();
    }
    ctx.pstage("headers", "analysing responses", n);
    // собираем реф-лист один раз
    std::vector<UrlRef> refs;
    for (const auto& t : ctx.cfg.targets) {
      const HostResult* hr = ctx.result.find_host(t.host);
      auto rs = urls_for_target(t, hr);
      refs.insert(refs.end(), rs.begin(), rs.end());
    }
    // сеть в пуле, находки применяет главный поток в исходном порядке
    std::vector<std::vector<Finding>> per_ref(refs.size());
    ctx.parallel(refs.size(), [&](size_t ri) {
      const UrlRef& ref = refs[ri];
      ctx.ptick();
      HttpOptions opt;
      opt.timeout_s = ctx.cfg.http_timeout_s;
      opt.user_agent = ctx.cfg.user_agent;
      WebResult& w = ctx.fetch_web(ref.url, opt);
      if (w.fetched && w.status > 0 && w.status < 500) {
        HeaderCheckInput in{ref.url, ref.host, ref.port, ref.https};
        per_ref[ri] = analyze_security_headers(in, w);
      }
    });
    for (auto& fs : per_ref)
      for (auto& f : fs) ctx.result.add_finding(std::move(f));
    ctx.pdone();
    return true;
  }
};

}  // namespace

std::unique_ptr<IModule> make_headers_module() {
  return std::make_unique<HeadersModule>();
}

}  // namespace mikto
