// mikto — ключи в контенте, только точные паттерны, шумные правила режем
#include "modules.hpp"

#include <algorithm>
#include <cstdlib>
#include <regex>
#include <set>
#include <vector>

#include "mikto/rate_limiter.hpp"
#include "mikto/util.hpp"

namespace mikto {

// чистый скан паттернов

void scan_body_for_secrets(const std::string& url, const std::string& body,
                           std::vector<Finding>& out) {
  struct SecretPattern {
    const char* name;
    std::regex re;
    Severity sev;
    const char* what;
  };
  static const std::vector<SecretPattern> kPatterns = {
      {"AWS access key id",
       std::regex(R"(\b(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b)"),
       Severity::High, "an AWS access key id"},
      {"Google API key", std::regex(R"(\bAIza[0-9A-Za-z_\-]{35}\b)"),
       Severity::High, "a Google API key"},
      {"Slack token", std::regex(R"(\bxox[abprs]-[A-Za-z0-9\-]{10,}\b)"),
       Severity::High, "a Slack token"},
      {"Private key block",
       std::regex(R"(-----BEGIN [A-Z ]*PRIVATE KEY( BLOCK)?-----)"),
       Severity::Critical, "a private key block"},
  };

  bool https = starts_with(url, "https://");
  std::string rest = url.substr(https ? 8 : 7);
  size_t slash = rest.find('/');
  if (slash != std::string::npos) rest = rest.substr(0, slash);
  std::string host;
  int port = https ? 443 : 80;
  size_t colon = rest.rfind(':');
  if (colon != std::string::npos && rest.find(':') == colon) {
    host = rest.substr(0, colon);
    port = std::atoi(rest.substr(colon + 1).c_str());
  } else {
    host = rest;
  }

  for (const auto& pat : kPatterns) {
    auto begin = std::sregex_iterator(body.begin(), body.end(), pat.re);
    auto end = std::sregex_iterator();
    int hits = 0;
    for (auto it = begin; it != end && hits < 3; ++it, ++hits) {
      std::string match = it->str();
      std::string redacted = match.substr(0, 6) + "...(redacted)";
      Finding f;
      f.severity = pat.sev;
      f.module = "secrets";
      f.host = host;
      f.port = port;
      f.service = "web";
      f.location = url;
      f.title = std::string(pat.name) + " in served content";
      f.detail = std::string("A string matching ") + pat.what + " (" +
                 pat.name +
                 ") is served at this URL. This is a pattern match, not a "
                 "confirmed live credential — verify manually before acting.";
      f.recommendation =
          "Rotate the credential immediately, remove it from source code "
          "and git history, and move secrets to a secret manager; do not "
          "serve internal JS to unauthenticated visitors.";
      f.evidence = redacted;
      out.push_back(std::move(f));
    }
  }
}

// js своего домена

namespace {

std::set<std::string> collect_same_origin_js(const std::string& body,
                                             const std::string& base_url,
                                             size_t cap) {
  std::set<std::string> out;
  std::string lower = to_lower(body);
  size_t pos = 0;
  while (out.size() < cap) {
    size_t src = lower.find("src", pos);
    if (src == std::string::npos) break;
    pos = src + 3;
    size_t eq = body.find('=', pos);
    if (eq == std::string::npos || eq - pos > 4) continue;
    pos = eq + 1;
    while (pos < body.size() &&
           std::isspace(static_cast<unsigned char>(body[pos])))
      ++pos;
    if (pos >= body.size() || (body[pos] != '"' && body[pos] != '\'')) continue;
    char q = body[pos];
    size_t end = body.find(q, pos + 1);
    if (end == std::string::npos) break;
    std::string url = body.substr(pos + 1, end - pos - 1);
    pos = end + 1;
    if (url.empty() || !ends_with(to_lower(url), ".js")) continue;

    std::string resolved;
    if (starts_with(url, "//"))
      resolved = (starts_with(base_url, "https://") ? "https:" : "http:") + url;
    else if (starts_with(url, "http://") || starts_with(url, "https://"))
      resolved = url;
    else if (!url.empty() && url[0] == '/') {
      size_t auth_end = base_url.find('/', base_url.find("//") + 2);
      resolved = auth_end == std::string::npos
                     ? base_url + url
                     : base_url.substr(0, auth_end) + url;
    } else {
      continue;  // редкий случай, скип
    }
    // только свой домен
    size_t a1 = base_url.find("//") + 2;
    size_t a2 = base_url.find('/', a1);
    std::string base_auth = a2 == std::string::npos
                                ? base_url.substr(a1)
                                : base_url.substr(a1, a2 - a1);
    size_t b1 = resolved.find("//") + 2;
    size_t b2 = resolved.find('/', b1);
    std::string res_auth = b2 == std::string::npos
                               ? resolved.substr(b1)
                               : resolved.substr(b1, b2 - b1);
    if (base_auth == res_auth) out.insert(resolved);
  }
  return out;
}

class SecretsModule : public IModule {
 public:
  std::string name() const override { return "secrets"; }
  std::string description() const override {
    return "conservative credential patterns in served web content (AWS/Google/Slack keys, private key blocks)";
  }
  Maturity maturity() const override { return Maturity::Preview; }
  std::vector<std::string> depends() const override { return {"ports"}; }

  bool run(ModuleContext& ctx) override {
    // копия списка: fetch_web правит result.web
    std::vector<std::string> urls;
    for (const auto& w : ctx.result.web)
      if (w.fetched && w.status == 200 && !w.body.empty()) urls.push_back(w.url);

    // собираем js-ссылки по страницам (тела уже в кэше), тянем их пулом
    std::vector<std::vector<std::string>> js_per_page(urls.size());
    std::vector<std::string> all_js;
    for (size_t ui = 0; ui < urls.size(); ++ui) {
      const WebResult* page = find_web(ctx, urls[ui]);
      if (!page) continue;
      for (const auto& jsurl : collect_same_origin_js(page->body, urls[ui], 8)) {
        js_per_page[ui].push_back(jsurl);
        all_js.push_back(jsurl);
      }
    }
    if (!all_js.empty()) {
      HttpOptions opt;
      opt.timeout_s = ctx.cfg.http_timeout_s;
      opt.user_agent = ctx.cfg.user_agent;
      ctx.parallel(all_js.size(),
                   [&](size_t ji) { ctx.fetch_web(all_js[ji], opt); }, 16);
    }

    // скан тел последовательно в исходном порядке
    for (size_t ui = 0; ui < urls.size(); ++ui) {
      const WebResult* page = find_web(ctx, urls[ui]);
      if (!page) continue;
      scan_one(ctx, urls[ui], page->body);
      for (const auto& jsurl : js_per_page[ui]) {
        const WebResult* script = find_web(ctx, jsurl);
        if (script && script->fetched && script->status == 200 &&
            !script->body.empty())
          scan_one(ctx, jsurl, script->body);
      }
    }
    return true;
  }

 private:
  const WebResult* find_web(ModuleContext& ctx, const std::string& url) const {
    for (const auto& w : ctx.result.web)
      if (w.url == url) return &w;
    (void)ctx;
    return nullptr;
  }

  void scan_one(ModuleContext& ctx, const std::string& url,
                const std::string& body) {
    std::vector<Finding> found;
    scan_body_for_secrets(url, body, found);
    for (auto& f : found) ctx.result.add_finding(std::move(f));
  }
};

}  // namespace

std::unique_ptr<IModule> make_secrets_module() {
  return std::make_unique<SecretsModule>();
}

}  // namespace mikto
