// mikto — фингерпринт стека whatweb-style + пробы версий
#include "modules.hpp"

#include <cctype>
#include <map>
#include <set>
#include <vector>

#include "mikto/rate_limiter.hpp"
#include "mikto/util.hpp"
#include "mikto/version.hpp"
#include "web_common.hpp"

namespace mikto {

// чистый детект

namespace {

struct Marker {
  const char* needle;
  const char* product;
  const char* where;
};

const Marker kMarkers[] = {
    // серверы и прокси
    {"microsoft-iis", "IIS", "header"},
    {"nginx", "nginx", "header"},
    {"apache", "Apache", "header"},
    {"litespeed", "LiteSpeed", "header"},
    {"openresty", "OpenResty", "header"},
    {"lighttpd", "lighttpd", "header"},
    {"caddy", "Caddy", "header"},
    {"envoy", "Envoy", "header"},
    {"gunicorn", "Gunicorn", "header"},
    {"uvicorn", "Uvicorn", "header"},
    {"werkzeug", "Flask", "header"},
    {"waitress", "Waitress", "header"},
    {"hypercorn", "Hypercorn", "header"},
    {"kestrel", "ASP.NET Core", "header"},
    {" tomcat", "Tomcat", "header"},
    {"jetty", "Jetty", "header"},
    {"undertow", "Undertow", "header"},
    {"wildfly", "WildFly", "header"},
    {"varnish", "Varnish", "header"},
    {"squid", "Squid", "header"},
    {"haproxy", "HAProxy", "header"},
    {"traefik", "Traefik", "header"},
    {"cloudfront", "CloudFront", "header"},
    {"fastly", "Fastly", "header"},
    {"akamai", "Akamai", "header"},
    {"ddos-guard", "DDoS-Guard", "header"},
    {"qrator", "Qrator", "header"},
    {"x-sucuri-id", "Sucuri", "header"},
    // приложения
    {"x-powered-by: php", "PHP", "header"},
    {"x-powered-by: express", "Express", "header"},
    {"x-powered-by: next.js", "Next.js", "header"},
    {"x-powered-by: phalcon", "Phalcon", "header"},
    {"x-powered-by: js", "Node.js", "header"},
    {"x-aspnet-version", "ASP.NET", "header"},
    {"x-aspnetmvc-version", "ASP.NET MVC", "header"},
    {"x-generator", "Generator", "header"},
    {"x-redirect-by", "WordPress", "header"},
    {"x-drupal", "Drupal", "header"},
    {"x-shopify", "Shopify", "header"},
    {"x-wix", "Wix", "header"},
    {"x-bitrix", "Bitrix", "header"},
    {"x-tilda", "Tilda", "header"},
    {"x-modx", "MODX", "header"},
    {"x-litespeed-cache", "LiteSpeed", "header"},
    {"cf-ray", "Cloudflare", "header"},
    {"x-vercel-id", "Vercel", "header"},
    {"x-amz-cf-id", "CloudFront", "header"},
    {"x-github-request-id", "GitHub Pages", "header"},
    {"x-netlify", "Netlify", "header"},
    {"x-drupal-cache", "Drupal", "header"},
    {"x-xss-protection: 1; mode=block", "", "header"},
    // куки
    {"phpsessid", "PHP", "cookie"},
    {"jsessionid", "Java", "cookie"},
    {"asp.net_sessionid", "ASP.NET", "cookie"},
    {"__requestverificationtoken", "ASP.NET MVC", "cookie"},
    {"laravel_session", "Laravel", "cookie"},
    {"xsrf-token", "Laravel", "cookie"},
    {"csrftoken", "Django", "cookie"},
    {"django_language", "Django", "cookie"},
    {"rack.session", "Ruby/Rack", "cookie"},
    {"connect.sid", "Express", "cookie"},
    {"wordpress_logged_in", "WordPress", "cookie"},
    {"wordpress_test_cookie", "WordPress", "cookie"},
    {"bitrix_", "Bitrix", "cookie"},
    {"PHPSESSID", "PHP", "cookie"},
    {"route", "ASP.NET", "cookie"},
    {"cf_clearance", "Cloudflare", "cookie"},
    {"__cf_bm", "Cloudflare", "cookie"},
    {"bigipserver", "F5 BIG-IP", "cookie"},
    {"incap_ses", "Imperva", "cookie"},
    {"visid_incap", "Imperva", "cookie"},
    {"_ym_uid", "Yandex.Metrika", "cookie"},
    // cms
    {"wp-content", "WordPress", "body"},
    {"wp-includes", "WordPress", "body"},
    {"wp-json", "WordPress", "body"},
    {"/media/jui/", "Joomla", "body"},
    {"joomla!", "Joomla", "body"},
    {"com_content", "Joomla", "body"},
    {"drupal.js", "Drupal", "body"},
    {"drupal.settings", "Drupal", "body"},
    {"drupal.min.js", "Drupal", "body"},
    {"/bitrix/", "Bitrix", "body"},
    {"bitrix_js", "Bitrix", "body"},
    {"bx-core", "Bitrix", "body"},
    {"index.php?route=", "OpenCart", "body"},
    {"mage/cookies", "Magento", "body"},
    {"magento", "Magento", "body"},
    {"cdn.shopify.com", "Shopify", "body"},
    {"shopify.theme", "Shopify", "body"},
    {"prestashop", "PrestaShop", "body"},
    {"modx", "MODX", "body"},
    {"ucoz", "uCoz", "body"},
    {"umi.cms", "UMI.CMS", "body"},
    {"netcat", "NetCat", "body"},
    {"insales", "InSales", "body"},
    {"squarespace", "Squarespace", "body"},
    {"__next_data__", "Next.js", "body"},
    {"__nuxt", "Nuxt", "body"},
    {"___gatsby", "Gatsby", "body"},
    {"svelte-", "Svelte", "body"},
    // js либы
    {"data-reactroot", "React", "body"},
    {"react.production.min.js", "React", "body"},
    {"react-dom.production.min.js", "React", "body"},
    {"_reactlistening", "React", "body"},
    {"data-v-app", "Vue", "body"},
    {"vue.runtime.min.js", "Vue", "body"},
    {"vue.global.prod.js", "Vue", "body"},
    {"vue.min.js", "Vue", "body"},
    {"ng-version", "Angular", "body"},
    {"ng-app", "AngularJS", "body"},
    {"angular.min.js", "AngularJS", "body"},
    {"jquery", "jQuery", "body"},
    {"jquery.min.js", "jQuery", "body"},
    {"bootstrap.min.css", "Bootstrap", "body"},
    {"bootstrap.bundle.min.js", "Bootstrap", "body"},
    {"popper.min.js", "Popper", "body"},
    {"lodash", "Lodash", "body"},
    {"axios", "Axios", "body"},
    {"alpinejs", "Alpine.js", "body"},
    {"alpine.min.js", "Alpine.js", "body"},
    {"htmx", "htmx", "body"},
    {"sweetalert2", "SweetAlert2", "body"},
    {"chart.js", "Chart.js", "body"},
    {"swiper", "Swiper", "body"},
    {"font-awesome", "Font Awesome", "body"},
    {"fontawesome", "Font Awesome", "body"},
    {"material-icons", "Material Icons", "body"},
    {"webpackJsonp", "Webpack", "body"},
    // аналитика и сервисы
    {"tildacdn.com", "Tilda", "body"},
    {"static.wixstatic.com", "Wix", "body"},
    {"googletagmanager.com", "Google Tag Manager", "body"},
    {"googletag.com/gtag/js", "Google Analytics", "body"},
    {"mc.yandex.ru/watch", "Yandex.Metrika", "body"},
    {"top-fwz1.mail.ru", "Mail.ru Counter", "body"},
    {"r.mail.ru", "Mail.ru Counter", "body"},
    {"vk.com/js/api/openapi.js", "VK API", "body"},
    {"connect.facebook.net", "Facebook Pixel", "body"},
    {"clarity.ms", "Microsoft Clarity", "body"},
    {"hotjar", "Hotjar", "body"},
    {"cdn.sentry.io", "Sentry", "body"},
    {"recaptcha/api.js", "reCAPTCHA", "body"},
    {"hcaptcha.com", "hCaptcha", "body"},
    {"smartcaptcha.yandex.net", "Yandex SmartCaptcha", "body"},
    // панели и утилиты
    {"phpmyadmin", "phpMyAdmin", "body"},
    {"adminer", "Adminer", "body"},
    {"apache tomcat", "Tomcat", "body"},
    {"/jenkins/", "Jenkins", "body"},
    {"grafana", "Grafana", "body"},
    {"gitlab", "GitLab", "body"},
    {"gitea", "Gitea", "body"},
    {"nextcloud", "Nextcloud", "body"},
    {"owncloud", "ownCloud", "body"},
    {"cpanel", "cPanel", "body"},
    {"plesk", "Plesk", "body"},
    {"ispmanager", "ISPmanager", "body"},
    {"aapanel", "aaPanel", "body"},
    {"bt-panel", "BT Panel", "body"},
    {"webmin", "Webmin", "body"},
    {"directadmin", "DirectAdmin", "body"},
    {"kibana", "Kibana", "body"},
    {"portainer", "Portainer", "body"},
};

// sql ошибки: игла + продукт
struct DbSig {
  const char* needle;
  const char* product;
};
const DbSig kDbSignatures[] = {
    {"you have an error in your sql syntax", "MySQL"},
    {"mysqli_", "MySQL"},
    {"mysql_num_rows", "MySQL"},
    {"mysql_fetch", "MySQL"},
    {"mariadb", "MariaDB"},
    {"warning: mysql", "MySQL"},
    {"pg_query", "PostgreSQL"},
    {"postgresql query failed", "PostgreSQL"},
    {"psql:", "PostgreSQL"},
    {"microsoft ole db provider for sql server", "MSSQL"},
    {"microsoft sql server", "MSSQL"},
    {"sqlserver jdbc", "MSSQL"},
    {"sqlite3::", "SQLite"},
    {"sqlite_master", "SQLite"},
    {"sqlstate[hy000]", "SQL (generic)"},
    {"mongodb", "MongoDB"},
    {"couchdb", "CouchDB"},
    {"oracle error", "Oracle DB"},
    {"ora-0", "Oracle DB"},
};

}  // namespace

// версия сразу после имени, ищем case-insensitive
static std::string version_after(const std::string& hay,
                                 const std::string& name) {
  std::string lh = to_lower(hay);
  std::string ln = to_lower(name);
  size_t p = lh.find(ln);
  while (p != std::string::npos) {
    size_t i = p + ln.size();
    if (i < hay.size() && (hay[i] == '/' || hay[i] == ' ' || hay[i] == '_' ||
                           hay[i] == '-'))
      ++i;
    std::string ver;
    while (i < hay.size() &&
           (std::isdigit(static_cast<unsigned char>(hay[i])) ||
            hay[i] == '.' || hay[i] == 'p' || hay[i] == 'b'))
      ver.push_back(hay[i++]);
    // хвостовая точка от .min.js
    while (!ver.empty() && ver.back() == '.') ver.pop_back();
    // версия начинается с цифры
    if (!ver.empty() && std::isdigit(static_cast<unsigned char>(ver[0])) &&
        ver.find('.') != std::string::npos)
      return ver;
    p = lh.find(ln, p + 1);
  }
  return "";
}

std::vector<TechHit> detect_technologies(const WebResult& w) {
  std::vector<TechHit> out;
  auto add = [&](const std::string& name, const std::string& ver,
                 const std::string& src) {
    if (name.empty()) return;
    for (auto& h : out)
      if (iequals(h.name, name)) {
        if (h.version.empty() && !ver.empty()) h.version = ver;
        return;
      }
    TechHit t;
    t.name = name;
    t.version = ver;
    t.source = src;
    out.push_back(std::move(t));
  };

  auto scan_header_value = [&](const std::string& hname,
                               const std::string& value) {
    std::string lv = to_lower(value);
    if (lv.empty()) return;
    for (const auto& m : kMarkers) {
      if (std::string(m.where) != "header") continue;
      std::string hay = to_lower(hname) + ": " + lv;
      if (hay.find(m.needle) != std::string::npos) {
        std::string ver = version_after(value, m.product);
        add(m.product, ver, "header:" + hname);
      }
    }
  };

  for (const auto& kv : w.headers) {
    if (iequals(kv.first, "Set-Cookie")) {
      std::string lc = to_lower(kv.second);
      for (const auto& m : kMarkers) {
        if (std::string(m.where) != "cookie") continue;
        if (lc.find(to_lower(m.needle)) != std::string::npos) {
          add(m.product, "", "cookie:" + kv.second.substr(0, kv.second.find('=')));
        }
      }
      continue;
    }
    scan_header_value(kv.first, kv.second);
  }

  const std::string body = to_lower(w.body);
  // короткие иглы требуют границ слова, длинные и так точные
  auto marker_in_body = [&](const std::string& needle) {
    size_t p = body.find(needle);
    while (p != std::string::npos) {
      if (needle.size() < 6) {
        char before = p > 0 ? body[p - 1] : ' ';
        char after = p + needle.size() < body.size()
                         ? body[p + needle.size()]
                         : ' ';
        bool b_ok = !std::isalnum(static_cast<unsigned char>(before));
        bool a_ok = !std::isalnum(static_cast<unsigned char>(after));
        if (b_ok && a_ok) return true;
      } else {
        return true;
      }
      p = body.find(needle, p + 1);
    }
    return false;
  };
  for (const auto& m : kMarkers) {
    if (std::string(m.where) != "body") continue;
    if (marker_in_body(m.needle)) {
      std::string ver = version_after(body, std::string(m.needle) + "-");
      if (ver.empty()) ver = version_after(body, std::string(m.needle) + "/");
      if (ver.empty()) ver = version_after(body, std::string(m.needle) + ".js?v=");
      add(m.product, ver, "body:" + std::string(m.needle));
    }
  }

  std::string gen;
  size_t g = body.find("name=\"generator\"");
  if (g == std::string::npos) g = body.find("name='generator'");
  if (g != std::string::npos) {
    size_t c1 = body.find("content=\"", g);
    if (c1 != std::string::npos) {
      size_t cs = c1 + 9;
      size_t ce = body.find('"', cs);
      if (ce != std::string::npos) gen = w.body.substr(cs, ce - cs);
    }
  }
  if (!gen.empty()) {
    struct GenMap {
      const char* needle;
      const char* product;
    };
    const GenMap gens[] = {
        {"wordpress", "WordPress"}, {"joomla", "Joomla"}, {"drupal", "Drupal"},
        {"opencart", "OpenCart"},   {"magento", "Magento"}, {"ghost", "Ghost"},
        {"wix", "Wix"},             {"tilda", "Tilda"},   {"next.js", "Next.js"},
        {"gatsby", "Gatsby"},       {"modx", "MODX"},     {"bitrix", "Bitrix"},
        {"prestashop", "PrestaShop"}, {"django", "Django"},
        {"sitecore", "Sitecore"},
    };
    std::string lgen = to_lower(gen);
    for (const auto& gm : gens) {
      if (lgen.find(gm.needle) != std::string::npos) {
        std::string ver = version_after(gen, std::string(gm.needle) + " ");
        if (ver.empty()) ver = version_after(gen, std::string(gm.needle) + "/");
        add(gm.product, ver, "generator");
      }
    }
  }

  // версии часто в имени скрипта или в ver=
  size_t sp = 0;
  while (out.size() < 40 && (sp = body.find(".js", sp)) != std::string::npos) {
    size_t s = body.rfind('/', sp);
    s = s == std::string::npos ? 0 : s + 1;
    std::string file = body.substr(s, std::min(sp + 3, body.size()) - s);
    if (file.size() < 64) {
      std::string base = file.substr(0, file.find(".js"));
      struct LibPat {
        const char* pat;
        const char* product;
      };
      static const LibPat pats[] = {
          {"jquery", "jQuery"},     {"bootstrap", "Bootstrap"},
          {"vue", "Vue"},           {"react", "React"},
          {"angular", "AngularJS"}, {"lodash", "Lodash"},
          {"moment", "Moment.js"},  {"swiper", "Swiper"},
          {"aos", "AOS"},           {"masonry", "Masonry"},
          {"slick", "Slick"},       {"select2", "Select2"},
          {"lightbox", "Lightbox"},
      };
      for (const auto& lp : pats) {
        if (base.find(lp.pat) == std::string::npos) continue;
        std::string ver = version_after(base, lp.pat);
        if (!ver.empty()) add(lp.product, ver, "script:" + file);
        break;
      }
    }
    sp += 3;
  }

  // ver= после wp-content это версии плагинов
  size_t wp = body.find("/wp-content/plugins/");
  int plugins_found = 0;
  while (wp != std::string::npos && plugins_found < 12 && out.size() < 46) {
    size_t slash = body.find('/', wp + 21);
    size_t slash2 = slash == std::string::npos ? std::string::npos
                                               : body.find('/', slash + 1);
    if (slash != std::string::npos && slash2 != std::string::npos) {
      std::string plugin = body.substr(slash + 1, slash2 - slash - 1);
      if (plugin.size() > 2 && plugin.size() < 64) {
        add("WordPress plugin: " + plugin, "", "body:wp-plugins");
        ++plugins_found;
      }
    }
    wp = body.find("/wp-content/plugins/", wp + 21);
  }

  return out;
}

std::vector<TechHit> detect_databases(const WebResult& w,
                                      const std::vector<PortInfo>& ports) {
  std::vector<TechHit> out;
  auto add = [&](const std::string& name, const std::string& src) {
    for (auto& h : out)
      if (iequals(h.name, name)) return;
    TechHit t;
    t.name = name;
    t.source = src;
    out.push_back(std::move(t));
  };

  std::string body = to_lower(w.body);
  for (const auto& sig : kDbSignatures) {
    std::string needle = to_lower(sig.needle);
    if (body.find(needle) != std::string::npos) add(sig.product, "error-signature");
  }
  // админка => база где-то рядом
  if (body.find("phpmyadmin") != std::string::npos) add("MySQL", "phpMyAdmin");
  if (body.find("adminer") != std::string::npos) add("SQL (generic)", "Adminer");

  for (const auto& p : ports) {
    if (!p.open) continue;
    switch (p.port) {
      case 3306: add(p.product.empty() ? "MySQL" : p.product, "port:3306"); break;
      case 5432: add("PostgreSQL", "port:5432"); break;
      case 1433: add("MSSQL", "port:1433"); break;
      case 1521: add("Oracle DB", "port:1521"); break;
      case 27017: case 27018: add("MongoDB", "port:" + std::to_string(p.port)); break;
      case 6379: add("Redis", "port:6379"); break;
      case 9200: add("Elasticsearch", "port:9200"); break;
      case 11211: add("Memcached", "port:11211"); break;
      default: break;
    }
  }
  return out;
}

std::string guess_os_from_banners(const std::vector<std::string>& clues) {
  std::string hay;
  for (const auto& c : clues) {
    hay += to_lower(c);
    hay += " | ";
  }
  auto has = [&](const char* s) { return hay.find(s) != std::string::npos; };
  if (has("ubuntu")) return "Linux (Ubuntu)";
  if (has("debian")) return "Linux (Debian)";
  if (has("centos")) return "Linux (CentOS)";
  if (has("redhat") || has("rhel")) return "Linux (RHEL)";
  if (has("alpine")) return "Linux (Alpine)";
  if (has("suse")) return "Linux (SUSE)";
  if (has("freebsd")) return "FreeBSD";
  if (has("openbsd")) return "OpenBSD";
  if (has("netbsd")) return "NetBSD";
  if (has("microsoft-iis") || has("iis/") || has("win64") || has("windows") ||
      has("filezilla server"))
    return "Windows";
  if (has("darwin")) return "macOS";
  if (has("linux")) return "Linux";
  return "";
}

// модуль

namespace {

std::string tech_label(const std::vector<TechHit>& hits) {
  std::string out;
  for (size_t i = 0; i < hits.size() && i < 6; ++i) {
    if (i) out += ", ";
    out += hits[i].name;
    if (!hits[i].version.empty()) out += " " + hits[i].version;
  }
  return out;
}

bool hit_has(const std::vector<TechHit>& hits, const std::string& name) {
  for (const auto& h : hits)
    if (iequals(h.name, name)) return true;
  return false;
}

struct ProbeResult {
  bool fetched = false;
  long status = 0;
  std::string body;
};

class TechModule : public IModule {
 public:
  std::string name() const override { return "tech"; }
  std::string description() const override {
    return "web technology fingerprinting (CMS, languages, frameworks, JS libs, databases, panels, CDN/WAF — WhatWeb style) + version probes";
  }
  Maturity maturity() const override { return Maturity::Preview; }
  std::vector<std::string> depends() const override { return {"ports"}; }

  bool run(ModuleContext& ctx) override {
    std::vector<UrlRef> refs;
    for (const auto& t : ctx.cfg.targets) {
      const HostResult* hr = ctx.result.find_host(t.host);
      for (const auto& r : urls_for_target(t, hr)) refs.push_back(r);
    }
    ctx.pstage("tech", "fingerprinting stack", refs.size());

    // сеть в пуле потоков, результат применяем в исходном порядке
    struct TechOut {
      std::vector<TechHit> hits;
      std::vector<Finding> findings;
    };
    std::vector<TechOut> per_ref(refs.size());
    ctx.parallel(refs.size(), [&](size_t ri) {
      const UrlRef& ref = refs[ri];
      TechOut& out = per_ref[ri];
      ctx.ptick();
      HttpOptions opt;
      opt.timeout_s = ctx.cfg.http_timeout_s;
      opt.user_agent = ctx.cfg.user_agent;
      WebResult& w = ctx.fetch_web(ref.url, opt);
      if (!w.fetched || w.status == 0 || w.status >= 500) return;

      std::vector<TechHit> hits = detect_technologies(w);

      const HostResult* hr = ctx.result.find_host(ref.host);
      if (hr) {
        const PortInfo* pi = hr->port(static_cast<uint16_t>(ref.port));
        if (pi && pi->open && !pi->product.empty()) {
          if (!hit_has(hits, pi->product)) {
            TechHit t;
            t.name = pi->product;
            t.version = pi->version;
            t.source = "ports";
            hits.push_back(t);
          }
        }
        std::vector<TechHit> dbs = detect_databases(w, hr->ports);
        for (auto& d : dbs)
          if (!hit_has(hits, d.name)) hits.push_back(std::move(d));
      }

      // пробы версий, только get; находки копятся, применит главный поток
      probe_cms_versions(ctx, ref, hits, w, out.findings);

      if (hits.empty()) return;

      Finding f;
      f.severity = Severity::Info;
      f.module = "tech";
      f.host = ref.host;
      f.port = ref.port;
      f.service = "web";
      f.location = ref.url;
      f.title = "Web stack: " + tech_label(hits);
      f.detail =
          "Technologies identified from response headers, cookies, page "
          "markers and version-revealing endpoints. This inventory drives "
          "targeted version checks — verify versions before acting on them.";
      f.recommendation =
          "Minimise disclosed stack details (suppress version headers) and "
          "keep every listed component updated.";
      out.findings.push_back(std::move(f));

      // eol пороги консервативные
      for (const auto& h : hits) {
        std::string ln = to_lower(h.name);
        if (ln == "php" && !h.version.empty()) {
          if (compare_versions(h.version, "7.4") < 0) {
            Finding pf;
            pf.severity = Severity::Medium;
            pf.module = "tech";
            pf.host = ref.host;
            pf.port = ref.port;
            pf.service = "web";
            pf.location = ref.url;
            pf.title = "PHP " + h.version + " is end-of-life";
            pf.detail =
                "PHP versions below 7.4 receive no security fixes since "
                "2022. Known CVEs in the runtime are directly exploitable "
                "depending on the application.";
            pf.recommendation =
                "Upgrade to a supported PHP version (8.x) and re-test the "
                "application.";
            out.findings.push_back(std::move(pf));
          } else if (compare_versions(h.version, "8.0") < 0) {
            Finding pf;
            pf.severity = Severity::Low;
            pf.module = "tech";
            pf.host = ref.host;
            pf.port = ref.port;
            pf.service = "web";
            pf.location = ref.url;
            pf.title = "PHP " + h.version + " has ended security support";
            pf.detail =
                "PHP 7.x stopped receiving security fixes (7.4 in Nov 2022). "
                "New vulnerabilities are no longer patched for this branch.";
            pf.recommendation =
                "Plan an upgrade to PHP 8.x and verify application "
                "compatibility.";
            out.findings.push_back(std::move(pf));
          }
        }
        if (ln == "wordpress" && !h.version.empty() &&
            compare_versions(h.version, "6.0") < 0) {
          Finding pf;
          pf.severity = Severity::Low;
          pf.module = "tech";
          pf.host = ref.host;
          pf.port = ref.port;
          pf.service = "web";
          pf.location = ref.url;
          pf.title = "WordPress " + h.version + " is outdated";
          pf.detail =
              "The reported WordPress core version is behind the current "
              "6.x releases. Older versions miss both security fixes and "
              "hardening improvements.";
          pf.recommendation =
              "Update WordPress core (and plugins/themes) and enable "
              "automatic minor updates.";
          out.findings.push_back(std::move(pf));
        }
      }
      out.hits = std::move(hits);
    });

    // применяем в исходном порядке — отчёт стабилен
    for (size_t ri = 0; ri < refs.size(); ++ri) {
      TechOut& out = per_ref[ri];
      for (auto& f : out.findings) ctx.result.add_finding(std::move(f));
      if (out.hits.empty()) continue;
      HostResult& host = ctx.result.ensure_host(refs[ri].host, false);
      for (const auto& h : out.hits) {
        bool dup = false;
        for (const auto& existing : host.tech)
          if (iequals(existing.name, h.name)) dup = true;
        if (!dup) host.tech.push_back(h);
      }
    }
    ctx.pdone();
    return true;
  }

 private:
  ProbeResult probe(ModuleContext& ctx, const UrlRef& ref,
                    const std::string& path) {
    HttpOptions opt;
    opt.timeout_s = std::min(ctx.cfg.http_timeout_s, 10);
    opt.user_agent = ctx.cfg.user_agent;
    std::string url = ref.url + path;
    WebResult& w = ctx.fetch_web(url, opt);
    ProbeResult pr;
    pr.fetched = w.fetched;
    pr.status = w.status;
    pr.body = w.body;
    return pr;
  }

  // пробы только когда база намекнула на cms; находки в sink, применит главный поток
  void probe_cms_versions(ModuleContext& ctx, const UrlRef& ref,
                          std::vector<TechHit>& hits, WebResult& w,
                          std::vector<Finding>& sink) {
    std::string body = to_lower(w.body);
    bool wp = hit_has(hits, "WordPress") || body.find("wp-content") != std::string::npos;
    bool joomla = hit_has(hits, "Joomla") || body.find("joomla") != std::string::npos;
    bool drupal = hit_has(hits, "Drupal") || body.find("drupal") != std::string::npos;
    bool php = hit_has(hits, "PHP");

    auto set_version = [&](const std::string& product, const std::string& ver,
                           const std::string& src) {
      if (ver.empty()) return;
      for (auto& h : hits)
        if (iequals(h.name, product)) {
          if (h.version.empty()) h.version = ver;
          return;
        }
      TechHit t;
      t.name = product;
      t.version = ver;
      t.source = src;
      hits.push_back(std::move(t));
    };

    if (wp) {
      ProbeResult r = probe(ctx, ref, "/readme.html");
      if (r.fetched && r.status == 200) {
        std::string low = to_lower(r.body);
        size_t p = low.find("version");
        while (p != std::string::npos) {
          size_t i = p + 7;
          while (i < r.body.size() && r.body[i] != '\n' &&
                 !std::isdigit(static_cast<unsigned char>(r.body[i])))
            ++i;
          std::string ver;
          while (i < r.body.size() &&
                 (std::isdigit(static_cast<unsigned char>(r.body[i])) ||
                  r.body[i] == '.'))
            ver.push_back(r.body[i++]);
          if (ver.find('.') != std::string::npos) {
            set_version("WordPress", ver, "probe:/readme.html");
            break;
          }
          p = low.find("version", p + 1);
        }
      }
      r = probe(ctx, ref, "/feed/");
      if (r.fetched && r.status == 200) {
        std::string low = to_lower(r.body);
        size_t p = low.find("wordpress.org/?v=");
        if (p != std::string::npos) {
          std::string ver;
          size_t i = p + 17;
          while (i < r.body.size() &&
                 (std::isdigit(static_cast<unsigned char>(r.body[i])) ||
                  r.body[i] == '.'))
            ver.push_back(r.body[i++]);
          set_version("WordPress", ver, "probe:/feed/");
        }
      }
      // xmlrpc: только get, никаких постов
      r = probe(ctx, ref, "/xmlrpc.php");
      if (r.fetched && r.status == 200 &&
          to_lower(r.body).find("xmlrpc") != std::string::npos) {
        Finding f;
        f.severity = Severity::Low;
        f.module = "tech";
        f.host = ref.host;
        f.port = ref.port;
        f.service = "web";
        f.location = ref.url + "/xmlrpc.php";
        f.title = "WordPress XML-RPC enabled";
        f.detail =
            "xmlrpc.php answers. It enables credential brute-force via "
            "system.multicall (hundreds of attempts per request) and "
            "pingback abuse for DDoS reflection. Modern sites rarely need "
            "it.";
        f.recommendation =
            "Disable XML-RPC if unused (filter xmlrpc_enabled or a rule on "
            "the web server) or restrict it to known clients.";
        sink.push_back(std::move(f));
      }
    }
    if (joomla) {
      ProbeResult r = probe(ctx, ref, "/administrator/manifests/files/joomla.xml");
      if (r.fetched && r.status == 200) {
        std::string low = to_lower(r.body);
        size_t p = low.find("<version>");
        if (p != std::string::npos) {
          size_t e = low.find("</version>", p);
          if (e != std::string::npos) {
            std::string ver = trim(r.body.substr(p + 9, e - p - 9));
            set_version("Joomla", ver, "probe:joomla.xml");
          }
        }
      }
    }
    if (drupal) {
      // drupal 8+: версию берём из generator, /core только фингерпринт 403
      ProbeResult r = probe(ctx, ref, "/core/CHANGELOG.txt");
      if (r.fetched && (r.status == 403 || r.status == 404)) {
        set_version("Drupal", "", "probe:/core/CHANGELOG.txt (8+)");
      }
    }
    if (php && ctx.cfg.deep) {
      for (const char* p : {"/info.php", "/phpinfo.php"}) {
        ProbeResult r = probe(ctx, ref, p);
        if (r.fetched && r.status == 200 &&
            to_lower(r.body).find("phpinfo()") != std::string::npos) {
          std::string low = to_lower(r.body);
          size_t p2 = low.find("php version");
          if (p2 != std::string::npos) {
            std::string ver;
            size_t i = p2 + 11;
            while (i < r.body.size() &&
                   (std::isdigit(static_cast<unsigned char>(r.body[i])) ||
                    r.body[i] == '.'))
              ver.push_back(r.body[i++]);
            set_version("PHP", ver, "probe:" + std::string(p));
          }
          Finding f;
          f.severity = Severity::Medium;
          f.module = "tech";
          f.host = ref.host;
          f.port = ref.port;
          f.service = "web";
          f.location = ref.url + p;
          f.title = "phpinfo() page exposed";
          f.detail =
              "A phpinfo() output is publicly reachable. It discloses the "
              "exact PHP version, loaded extensions, environment variables, "
              "document root and often internal IPs — everything an attacker "
              "needs to pick a matching public exploit.";
          f.recommendation =
              "Delete the probe script from production and block access to "
              "phpinfo in the web-server config.";
          sink.push_back(std::move(f));
          break;
        }
      }
    }

    // в deep ещё пара проб
    if (ctx.cfg.deep) {
      if (!hit_has(hits, "WordPress") &&
          to_lower(w.body).find("wp-content") == std::string::npos) {
        ProbeResult r = probe(ctx, ref, "/wp-json/");
        if (r.fetched && r.status == 200 &&
            to_lower(r.body).find("\"namespaces\"") != std::string::npos) {
          set_version("WordPress", "", "probe:/wp-json/");
          Finding f;
          f.severity = Severity::Info;
          f.module = "tech";
          f.host = ref.host;
          f.service = "web";
          f.location = ref.url + "/wp-json/";
          f.title = "WordPress REST API root exposed";
          f.detail =
              "/wp-json/ returned the REST API index even though the front "
              "page does not look like WordPress. The API frequently leaks "
              "user slugs via /wp-json/wp/v2/users, enabling credential "
              "brute-force with valid logins.";
          f.recommendation =
              "Restrict /wp-json/wp/v2/users or block unauthenticated "
              "routes if the API is not needed.";
          sink.push_back(std::move(f));
        }
      }
    }
  }
};

}  // namespace

std::unique_ptr<IModule> make_tech_module() {
  return std::make_unique<TechModule>();
}

}  // namespace mikto
