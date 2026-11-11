// mikto — контент-дискавери: словарь + майнинг страниц/роботс/сайтмапа + рекурсия
#include "modules.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdlib>

#include <map>
#include <set>
#include <thread>
#include <vector>

#include "mikto/rate_limiter.hpp"
#include "mikto/util.hpp"
#include "web_common.hpp"

namespace mikto {

// чистые хелперы

namespace {

// safe самое нужное, deep для authorized сканов
const std::vector<std::string>& wordlist(bool deep) {
  static const std::vector<std::string> kSafe = {
      "/robots.txt",       "/sitemap.xml",      "/.well-known/security.txt",
      "/.env",             "/.git/HEAD",        "/.git/config",
      "/.DS_Store",        "/.svn/entries",     "/composer.lock",
      "/composer.json",    "/package.json",     "/.htaccess",
      "/.htpasswd",        "/phpinfo.php",      "/info.php",
      "/admin",            "/admin/",           "/administrator",
      "/adminer.php",      "/login",            "/wp-login.php",
      "/wp-admin/",        "/wp-json/",         "/wp-content/debug.log",
      "/phpmyadmin",       "/pma",              "/panel",
      "/dashboard",        "/cpanel",           "/manager/html",
      "/server-status",    "/api",              "/api/v1",
      "/swagger",          "/swagger.json",     "/api-docs",
      "/graphql",          "/actuator",         "/actuator/health",
      "/console",          "/backup",           "/backup.zip",
      "/db.sql",           "/database.sql",     "/dump.sql",
      "/xmlrpc.php",       "/readme.html",      "/install.php",
      "/setup",            "/.npmrc",           "/.dockercfg",
      "/docker-compose.yml", "/Dockerfile",     "/web.config",
      "/wp-config.php.bak", "/configuration.php", "/user/login",
      "/admin/login",      "/metrics",          "/status",
      "/.aws/credentials", "/backup.sql",       "/site.zip",
      "/old/",             "/test/",            "/dev/",
      "/staging/",         "/beta/",            "/demo/",
      "/internal/",        "/private/",         "/uploads/",
      "/files/",           "/media/",
  };
  static const std::vector<std::string> kDeep = [] {
    std::vector<std::string> v = kSafe;
    for (const char* p : {
             "/wp-config.php~",       "/config.php",          "/config.php.bak",
             "/settings.py",          "/local.settings.json", "/id_rsa",
             "/.git/logs/HEAD",       "/.hg/hgrc",            "/backup.tar.gz",
             "/site.tar.gz",          "/db_backup.sql",       "/database.sqlite",
             "/db.sqlite3",           "/admin.php",           "/manage",
             "/manage/",              "/signin",              "/host-manager",
             "/web-console",          "/solr",                "/kibana",
             "/grafana/",             "/prometheus",          "/zabbix",
             "/myadmin",              "/roundcube",           "/webmail",
             "/owa/",                 "/rdweb",               "/portal",
             "/register",             "/install",             "/upgrade.php",
             "/license.txt",          "/CHANGELOG.md",        "/CHANGELOG.txt",
             "/VERSION",              "/pom.xml",             "/build.gradle",
             "/crossdomain.xml",      "/cgi-bin/",            "/rest",
             "/rest/v1",              "/debug",               "/debug/vars",
             "/trace",                "/Thumbs.db",           "/app.config",
             "/elmah.axd",            "/server-info",
             "/actuator/env",         "/actuator/heapdump",
             "/actuator/gateway/routes", "/actuator/loggers",
             "/actuator/mappings",    "/jolokia",             "/jmx-console/",
             "/druid/index.html",     "/druid/login.html",    "/nacos",
             "/eureka/apps",          "/hystrix.stream",
             "/_profiler",            "/_debugbar/",          "/app_dev.php",
             "/laravel/telescope",    "/laravel/log",         "/telescope",
             "/horizon",
             "/wp-content/uploads/",  "/wp-content/backup/",
             "/wp-content/backups-db/", "/wp-json/wp/v2/users",
             "/wp-json/wp/v2/pages",
             "/adminer/",             "/phpliteadmin",        "/phpPgAdmin/",
             "/check_mk",             "/nagios",              "/cacti",
             "/munin",                "/icinga",              "/jenkins/",
             "/jira/",                "/confluence/",         "/gitlab/",
             "/gitea/",               "/nexus/",              "/artifactory/",
             "/harbor/",              "/portainer/",          "/rancher/",
             "/kubernetes/",          "/k8s/",
             "/.gitlab-ci.yml",       "/.github/workflows",   "/Jenkinsfile",
             "/bitbucket-pipelines.yml", "/app.py",           "/manage.py",
             "/server.js",            "/database.yml",        "/config/database.yml",
             "/logins.json",          "/logs/",               "/error_log",
             "/access.log",           "/error.log",           "/debug.log",
             "/openapi.json",         "/swagger-ui",          "/swagger-ui.html",
             "/docs",                 "/redoc",               "/api/v2",
             "/api/v3",
             "/administrator/index.php",
             "/administrator/manifests/files/joomla.xml",
             "/core/CHANGELOG.txt",   "/misc/drupal.js",
             "/sites/default/settings.php",
             "/bitrix/admin/",        "/bitrix/php_interface/dbconn.php",
             "/admin/config",         "/siteadmin",           "/webmaster",
             "/moderator",            "/staff",               "/account",
             "/auth",                 "/login.html",          "/login.php",
             "/sign-in",              "/cpanel/login",        "/plesk",
             "/ispmanager/",          "/aapanel",             "/bt-panel",
             "/webmin",               "/directadmin",         "/shell",
             "/terminal",             "/supervisor",
         }) {
      v.push_back(p);
    }
    std::set<std::string> seen;
    std::vector<std::string> out;
    for (const auto& p : v)
      if (seen.insert(p).second) out.push_back(p);
    return out;
  }();
  return deep ? kDeep : kSafe;
}

const std::vector<std::string>& dot_suffixes() {
  static const std::vector<std::string> kDot = {
      ".env",        ".git/HEAD",   ".htaccess",  ".htpasswd",
      ".DS_Store",   ".npmrc",      ".svn/entries", ".git/config",
      ".aws/credentials", ".well-known/security.txt",
  };
  return kDot;
}

// клей html/js, осмысленные слова в список не попадали специально
bool is_stop_word(const std::string& w) {
  static const std::set<std::string> kStop = {
      "get",  "set",  "put",  "post", "delete", "patch", "head", "options",
      "fetch", "ajax", "xhr",  "http", "https",  "www",   "com",  "net",
      "org",  "html", "htm",  "php",  "jsp",    "aspx",  "css",  "img",
      "image", "images", "icon", "icons", "font", "fonts", "javascript",
      "jquery", "function", "return", "window", "document", "const",
      "var",  "let",  "class", "style", "script", "title", "body", "meta",
      "link", "div",  "span", "width", "height", "color", "margin",
      "padding", "display", "flex", "center", "left", "right", "auto",
      "none", "block", "important", "undefined", "null", "true", "false",
      "name", "value", "type", "text", "content", "element", "query",
      "selector", "length", "string", "number", "object", "array", "parse",
      "error", "catch", "async", "await", "then", "export", "import",
      "default", "require", "module", "public", "src", "href", "rel",
      "alt",  "aria", "label", "input", "button", "form", "action",
      "method", "header", "footer", "main", "nav", "section", "article",
      "aside", "screen", "print", "hover", "active", "focus", "before",
      "after", "first", "last", "next", "prev", "index", "page", "site",
      "and",  "for",  "you",  "your", "with", "this", "that", "all",
      "can",  "will", "not",  "but",  "our",  "one",  "two",  "the",
      "are",  "was",  "from", "has",  "have", "had",  "they", "them",
      "their", "what", "when", "where", "who", "how", "why", "yes",
      "location", "console", "element", "listener", "event", "params",
      "app",  "web",  "use",  "user", "users", "new",  "end",  "min",
      "max",  "top",  "uid",  "pid",  "url",  "uri",  "dom",  "css2",
      "woff", "woff2", "woff", "ttf", "eot", "svg", "png", "jpg", "jpeg",
      "gif",  "ico",  "map",  "json", "xml", "utf",  "utf8", "base64",
  };
  return kStop.count(w) != 0;
}

// отрезаем query и fragment
std::string strip_query_frag(std::string p) {
  auto cut = p.find_first_of("?#");
  if (cut != std::string::npos) p = p.substr(0, cut);
  return p;
}

bool path_charset_ok(const std::string& p) {
  for (char c : p) {
    unsigned char u = static_cast<unsigned char>(c);
    if (u < 0x21 || u > 0x7e) return false;
    if (c == '<' || c == '>' || c == '"' || c == '\'' || c == '\\' ||
        c == '`' || c == '{' || c == '}' || c == '|' || c == '^')
      return false;
  }
  return true;
}

bool has_segment(const std::string& p, const char* seg) {
  const std::string needle = std::string("/") + seg;
  size_t i = 0;
  while ((i = p.find(needle, i)) != std::string::npos) {
    size_t after = i + needle.size();
    if (after == p.size() || p[after] == '/' || p[after] == '?') return true;
    i = after;
  }
  return false;
}

std::string last_segment(const std::string& p) {
  std::string t = p;
  while (!t.empty() && t.back() == '/') t.pop_back();
  size_t slash = t.find_last_of('/');
  return slash == std::string::npos ? t : t.substr(slash + 1);
}

// архив + ключевое слово или классическое имя
bool is_backup_archive(const std::string& p) {
  static const char* kArch[] = {".zip", ".tar.gz", ".tgz", ".7z", ".rar"};
  static const char* kStrong[] = {"backup", "bck", "dump", "archive", "bak_"};
  static const char* kExact[] = {"www.zip", "site.zip", "web.zip", "db.zip",
                                 "www.tar.gz", "site.tar.gz"};
  bool arch = false;
  for (const char* a : kArch)
    if (ends_with(p, a)) { arch = true; break; }
  if (!arch) return false;
  std::string last = last_segment(p);
  for (const char* w : kStrong)
    if (last.find(w) != std::string::npos) return true;
  for (const char* e : kExact)
    if (last == e) return true;
  return false;
}

// ссылка с сайта весомее словаря, меньше = приоритет
int source_priority(const char* src) {
  if (src == std::string_view{"link"}) return 0;
  if (src == std::string_view{"js"}) return 1;
  if (src == std::string_view{"robots"}) return 2;
  if (src == std::string_view{"sitemap"}) return 3;
  return 4;  // wordlist / combo
}

const char* source_phrase(const std::string& src) {
  if (src == "link") return "referenced from a fetched page";
  if (src == "js") return "string literal inside JS/CSS";
  if (src == "robots") return "robots.txt entry";
  if (src == "sitemap") return "sitemap.xml location";
  if (src == "combo") return "generated combination (directory/word x suffix)";
  return "curated wordlist";
}

}  // namespace

const std::vector<std::string>& path_wordlist(bool deep) { return wordlist(deep); }

const std::vector<std::string>& discovery_suffixes() {
  static const std::vector<std::string> kSuf = {
      "admin",       "administrator", "login",      "signin",
      "signup",      "register",      "auth",       "oauth",
      "sso",         "dashboard",     "panel",      "console",
      "manager",     "manage",        "cpanel",     "control",
      "config",      "configuration", "settings",   "setup",
      "install",     "backup",        "backups",    "dump",
      "db",          "database",      "sql",        "api",
      "v1",          "v2",            "v3",         "rest",
      "graphql",     "swagger",       "openapi",    "docs",
      "status",      "health",        "metrics",    "info",
      "debug",       "test",          "staging",    "dev",
      "beta",        "demo",          "old",        "new",
      "internal",    "intranet",      "private",    "secret",
      "secrets",     "hidden",        "temp",       "tmp",
      "cache",       "logs",          "log",        "error",
      "trace",       "cron",          "jobs",       "queue",
      "worker",      "uploads",       "upload",     "downloads",
      "download",    "files",         "media",      "assets",
      "export",      "exports",       "reports",    "analytics",
      "stats",       "account",       "accounts",   "profile",
      "customers",   "orders",        "payments",   "billing",
      "invoices",    "checkout",      "mail",       "webmail",
      "git",         "jenkins",       "deploy",     "releases",
      "builds",      "artifacts",     "keys",       "tokens",
      "jwks",        "credentials",   "env",        "actuator",
      "server-status",
  };
  return kSuf;
}

std::string url_host(const std::string& url) {
  auto pos = url.find("://");
  if (pos == std::string::npos) return "";
  std::string rest = url.substr(pos + 3);
  auto slash = rest.find_first_of("/?#");
  if (slash != std::string::npos) rest = rest.substr(0, slash);
  auto at = rest.rfind('@');
  if (at != std::string::npos) rest = rest.substr(at + 1);
  if (!rest.empty() && rest[0] == '[') {  // ipv6 литерал
    auto close = rest.find(']');
    if (close != std::string::npos) return to_lower(rest.substr(1, close - 1));
    return to_lower(rest);
  }
  auto colon = rest.find(':');
  if (colon != std::string::npos) rest = rest.substr(0, colon);
  return to_lower(rest);
}

bool same_site_host(const std::string& host, const std::string& urlhost) {
  if (urlhost.empty() || host.empty()) return false;
  if (urlhost == host) return true;
  if (urlhost == "www." + host) return true;
  if (host == "www." + urlhost) return true;
  return false;
}

std::vector<std::string> extract_page_paths(const std::string& body,
                                            const std::string& host) {
  std::vector<std::string> out;
  std::set<std::string> seen;
  auto add = [&](std::string p) {
    p = strip_query_frag(std::move(p));
    while (!p.empty() &&
           (p.back() == '.' || p.back() == ',' || p.back() == ';' ||
            p.back() == ':' || p.back() == '!' || p.back() == '?'))
      p.pop_back();  // пунктуация вокруг ссылок
    if (p.size() < 2 || p.size() > 512) return;  // "" и "/" тоже
    if (p[0] != '/') return;
    if (starts_with(p, "//")) return;  // protocol-relative = чужое
    if (p.find("..") != std::string::npos) return;
    if (!path_charset_ok(p)) return;
    if (seen.insert(p).second) out.push_back(p);
  };

  // 1) кавычки (html атрибуты, js строки, json)
  for (size_t i = 0; i + 1 < body.size(); ++i) {
    char q = body[i];
    if (q != '"' && q != '\'') continue;
    size_t j = i + 1;
    while (j < body.size() && body[j] != q) {
      if (body[j] == '\\' && j + 1 < body.size()) ++j;
      ++j;
    }
    if (j >= body.size()) break;
    std::string lit = body.substr(i + 1, j - i - 1);
    i = j;
    if (lit.size() < 2 || lit.size() > 600) continue;
    if (lit[0] == '/') {
      add(std::move(lit));
    } else if (starts_with(lit, "http://") || starts_with(lit, "https://")) {
      if (same_site_host(to_lower(host), url_host(lit))) {
        auto scheme_end = lit.find("://") + 3;
        auto slash = lit.find('/', scheme_end);
        if (slash != std::string::npos) add(lit.substr(slash));
      }
    }
  }

  // 2) css url(...)
  for (auto i = body.find("url("); i != std::string::npos;
       i = body.find("url(", i + 1)) {
    size_t s = i + 4;
    if (s < body.size() && (body[s] == '"' || body[s] == '\'')) continue;
    auto e = body.find(')', s);
    if (e == std::string::npos) break;
    add(body.substr(s, e - s));
  }

  if (out.size() > 400) out.resize(400);
  return out;
}

std::vector<std::string> extract_path_words(const std::string& body) {
  std::vector<std::string> out;
  std::set<std::string> seen;
  auto add_word = [&](const std::string& raw) {
    std::string w = to_lower(trim(raw));
    if (w.size() < 3 || w.size() > 24) return;
    for (char c : w)
      if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_' && c != '-')
        return;
    bool digits = true;
    for (char c : w)
      if (!std::isdigit(static_cast<unsigned char>(c))) digits = false;
    if (digits) return;
    if (is_stop_word(w)) return;
    if (seen.insert(w).second) out.push_back(w);
  };
  // camelCase и kebab-case расщепляем, иначе половину слов теряем
  std::string cur;
  auto add_token = [&](const std::string& tok) {
    if (tok.empty()) return;
    add_word(tok);
    std::string raw;
    auto emit_raw = [&] {
      if (raw.empty()) return;
      std::string part;
      auto emit_part = [&] {
        if (part.empty()) return;
        std::string sub;
        for (size_t k = 0; k < part.size(); ++k) {
          char c = part[k];
          if (std::isupper(static_cast<unsigned char>(c))) {
            bool prev_low_or_digit =
                !sub.empty() &&
                (std::islower(static_cast<unsigned char>(sub.back())) ||
                 std::isdigit(static_cast<unsigned char>(sub.back())));
            bool next_lower =
                k + 1 < part.size() &&
                std::islower(static_cast<unsigned char>(part[k + 1]));
            bool prev_upper =
                !sub.empty() &&
                std::isupper(static_cast<unsigned char>(sub.back()));
            if (!sub.empty() &&
                (prev_low_or_digit || (prev_upper && next_lower))) {
              add_word(sub);
              sub.clear();
            }
            sub += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
          } else {
            sub += c;
          }
        }
        if (!sub.empty()) add_word(sub);
        part.clear();
      };
      for (char c : raw) {
        if (c == '-' || c == '_')
          emit_part();
        else
          part += c;
      }
      emit_part();
      raw.clear();
    };
    for (char c : tok) {
      if (c == '-' || c == '_')
        emit_raw();
      else
        raw += c;
    }
    emit_raw();
  };
  auto flush = [&] {
    if (cur.empty()) return;
    add_token(cur);
    cur.clear();
  };
  for (char c : body) {
    if (std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_')
      cur += c;
    else
      flush();
  }
  flush();
  if (out.size() > 128) out.resize(128);
  return out;
}

std::vector<std::string> parse_robots_entries(const std::string& robots,
                                              const std::string& host) {
  std::vector<std::string> out;
  std::set<std::string> seen;
  size_t pos = 0;
  while (pos < robots.size()) {
    size_t eol = robots.find('\n', pos);
    std::string line = trim(robots.substr(
        pos, eol == std::string::npos ? std::string::npos : eol - pos));
    pos = eol == std::string::npos ? robots.size() : eol + 1;
    if (line.empty() || line[0] == '#') continue;
    auto colon = line.find(':');
    if (colon == std::string::npos) continue;
    std::string key = to_lower(trim(line.substr(0, colon)));
    std::string val = trim(line.substr(colon + 1));
    if (key == "disallow" || key == "allow") {
      if (val.empty()) continue;
      size_t b = 0;
      while (b < val.size() && val[b] == '*') ++b;  // ведущие звёздочки
      std::string p = strip_query_frag(val.substr(b));
      while (!p.empty() && p.back() == '$') p.pop_back();  // якорь
      if (p.find('*') != std::string::npos ||
          p.find('$') != std::string::npos)
        continue;  // остались wildcard/якорь
      if (p.size() < 2 || p[0] != '/') continue;
      if (seen.insert(p).second) out.push_back(p);
    } else if (key == "sitemap") {
      if (!same_site_host(to_lower(host), url_host(val))) continue;
      auto scheme_end = val.find("://");
      if (scheme_end == std::string::npos) continue;
      auto slash = val.find('/', scheme_end + 3);
      if (slash == std::string::npos) continue;
      std::string p = strip_query_frag(val.substr(slash));
      if (p.size() >= 2 && seen.insert(p).second) out.push_back(p);
    }
  }
  if (out.size() > 256) out.resize(256);
  return out;
}

std::vector<std::string> parse_sitemap_locs(const std::string& xml,
                                            const std::string& host) {
  std::vector<std::string> out;
  std::set<std::string> seen;
  std::string low = to_lower(xml);
  size_t pos = 0;
  while ((pos = low.find("<loc>", pos)) != std::string::npos) {
    size_t s = pos + 5;
    size_t e = low.find("</loc>", s);
    if (e == std::string::npos) break;
    std::string url = trim(xml.substr(s, e - s));
    pos = e;
    if (!same_site_host(to_lower(host), url_host(url))) continue;
    auto scheme_end = url.find("://");
    if (scheme_end == std::string::npos) continue;
    auto slash = url.find('/', scheme_end + 3);
    if (slash == std::string::npos) continue;
    std::string p = strip_query_frag(url.substr(slash));
    if (p.size() < 2) continue;
    if (seen.insert(p).second) out.push_back(p);
    if (out.size() >= 512) break;
  }
  return out;
}

bool is_static_asset_path(const std::string& path) {
  static const char* kExt[] = {
      ".css", ".js", ".mjs", ".cjs", ".map",  ".png", ".jpg", ".jpeg",
      ".gif", ".svg", ".ico", ".webp", ".avif", ".bmp", ".woff", ".woff2",
      ".ttf", ".otf", ".eot", ".mp3", ".mp4",  ".webm", ".ogg", ".wav",
      ".avi", ".mov", ".pdf", ".txt", ".xml",  ".rss", ".atom"};
  std::string p = to_lower(path);
  auto q = p.find('?');
  if (q != std::string::npos) p = p.substr(0, q);
  for (const char* e : kExt)
    if (ends_with(p, e)) return true;
  return false;
}

std::vector<std::string> generate_discovery_candidates(
    const std::vector<std::string>& dirs, const std::vector<std::string>& words,
    const std::vector<std::string>& suffixes, size_t max_out) {
  auto valid = [](const std::string& p) {
    return p.size() >= 2 && p.size() <= 256 && p[0] == '/' &&
           p.find("..") == std::string::npos;
  };
  // пять семей кандидатов, потом чередование чтобы у всех был бюджет
  std::vector<std::vector<std::string>> fam(5);
  for (const auto& s : suffixes)
    for (const auto& d : dirs) fam[0].push_back(d + s);
  for (const auto& s : dot_suffixes())
    for (const auto& d : dirs) fam[0].push_back(d + s);
  for (const auto& w : words) fam[1].push_back("/" + w);
  for (const auto& d : dirs)
    for (const auto& w : words) fam[2].push_back(d + w);
  for (const auto& w : words)
    for (const auto& s : dot_suffixes()) fam[3].push_back("/" + w + "/" + s);
  for (const auto& s : suffixes)
    for (const auto& w : words) fam[4].push_back("/" + w + "/" + s);
  for (auto& f : fam)
    for (auto& p : f)
      while (!p.empty() && p.back() == '/') p.pop_back();
  // dir+suffix ~55% бюджета, остальным понемногу
  static const int kPattern[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                 1, 1, 2, 2, 2, 3, 4, 4};
  const size_t PN = sizeof(kPattern) / sizeof(kPattern[0]);
  std::vector<std::string> out;
  std::set<std::string> seen;
  size_t idx[5] = {0, 0, 0, 0, 0};
  size_t pi = 0;
  bool more = true;
  while (more && out.size() < max_out) {
    more = false;
    for (size_t n = 0; n < PN && out.size() < max_out; ++n) {
      size_t k = static_cast<size_t>(kPattern[(pi + n) % PN]);
      while (idx[k] < fam[k].size()) {
        std::string p = std::move(fam[k][idx[k]]);
        ++idx[k];
        if (!valid(p)) continue;
        if (seen.insert(p).second) {
          out.push_back(std::move(p));
          more = true;
          break;
        }
      }
      if (idx[k] < fam[k].size()) more = true;
    }
    pi += PN;
  }
  return out;
}

Severity classify_path(const std::string& path, long status) {
  if (status == 0) return Severity::Info;  // транспорт сдох, скипаем
  bool ok200 = status == 200;
  bool auth = status == 401 || status == 403;

  std::string p = to_lower(path);
  auto is = [&](const char* s) { return p == s || starts_with(p, s); };

  if (ok200) {
    if (is("/.env") || is("/.git/") || is("/.svn/") || is("/.hg/") ||
        p == "/.aws/credentials" || p == "/.ssh/id_rsa" || p == "/id_rsa" ||
        p == "/.npmrc" || p == "/.dockercfg" || p == "/logins.json")
      return Severity::Critical;
    if (is("/phpinfo.php") || p == "/info.php" || p == "/debug/vars")
      return Severity::High;
    if (p == "/actuator/env" || p == "/actuator/heapdump" ||
        p == "/actuator/gateway/routes" || p == "/_profiler" ||
        p == "/_debugbar/" || p == "/app_dev.php" || p == "/database.yml" ||
        p == "/config/database.yml" || p == "/sites/default/settings.php" ||
        p == "/bitrix/php_interface/dbconn.php")
      return Severity::High;
    if (ends_with(p, ".sql") || ends_with(p, ".sqlite") ||
        ends_with(p, ".sqlite3") || p == "/backup" || p == "/backup.zip" ||
        p == "/backup.tar.gz" || p == "/site.tar.gz" ||
        p == "/wp-content/debug.log" || ends_with(p, ".bak") ||
        ends_with(p, "~") || p == "/database.sql" || p == "/db.sql" ||
        p == "/db_backup.sql" || p == "/error_log" || p == "/debug.log")
      return Severity::High;
    if (p == "/composer.lock" || p == "/package.json" ||
        p == "/docker-compose.yml" || p == "/dockerfile" ||
        p == "/web.config" || p == "/app.config" || p == "/settings.py" ||
        p == "/local.settings.json" || p == "/configuration.php" ||
        p == "/config.php" || p == "/.htaccess" || p == "/.htpasswd" ||
        p == "/.DS_Store" || p == "/.gitlab-ci.yml" ||
        p == "/Jenkinsfile" || p == "/bitbucket-pipelines.yml" ||
        p == "/app.py" || p == "/manage.py" || p == "/server.js")
      return Severity::Medium;
    if (p == "/manager/html" || p == "/host-manager" || p == "/web-console" ||
        p == "/nacos" || p == "/druid/index.html")
      return Severity::High;
    if (is("/wp-admin") || p == "/wp-login.php" || p == "/xmlrpc.php" ||
        is("/administrator") || p == "/adminer.php" || p == "/elmah.axd")
      return Severity::Medium;
    if (is("/admin") || p == "/login" || p == "/panel" || p == "/dashboard" ||
        p == "/cpanel" || p == "/console" || is("/phpmyadmin") ||
        p == "/pma" || p == "/myadmin" || is("/solr") || is("/kibana") ||
        is("/grafana") || is("/prometheus") || is("/zabbix") || p == "/owa/" ||
        p == "/rdweb" || p == "/webmail" || p == "/roundcube")
      return Severity::Medium;
    if (p == "/swagger" || p == "/swagger.json" || p == "/api-docs" ||
        p == "/openapi.json" || p == "/swagger-ui.html" ||
        p == "/graphql" || is("/actuator"))
      return Severity::Medium;
    if (p == "/robots.txt" || p == "/sitemap.xml") return Severity::Info;
    if (p == "/.well-known/security.txt") return Severity::Info;
    if (is("/register") || is("/setup") || is("/install") ||
        p == "/install.php" || p == "/upgrade.php")
      return Severity::Low;

    // найденное на любой глубине: /api/lol/admin классифицируем как /admin
    if (p.find("/.git/") != std::string::npos ||
        p.find("/.svn/") != std::string::npos ||
        p.find("/.hg/") != std::string::npos ||
        has_segment(p, ".env") || p == "/.aws/credentials" ||
        has_segment(p, ".aws"))
      return Severity::Critical;
    if (ends_with(p, ".sql") || ends_with(p, ".sqlite") ||
        ends_with(p, ".sqlite3") || ends_with(p, ".bak") || ends_with(p, "~") ||
        is_backup_archive(p))
      return Severity::High;
    if (has_segment(p, "phpinfo.php") || has_segment(p, "info.php") ||
        ends_with(p, "/debug/vars") || ends_with(p, "/elmah.axd"))
      return Severity::High;
    if (ends_with(p, "/admin") || has_segment(p, "administrator") ||
        has_segment(p, "wp-login.php") || has_segment(p, "adminer.php") ||
        has_segment(p, "phpmyadmin") || has_segment(p, "manager") ||
        has_segment(p, "dashboard") || has_segment(p, "panel") ||
        has_segment(p, "console") || has_segment(p, "cpanel") ||
        has_segment(p, "actuator") || has_segment(p, "graphql") ||
        ends_with(p, "/swagger.json") || ends_with(p, "/openapi.json") ||
        ends_with(p, "/swagger-ui.html"))
      return Severity::Medium;
    if (has_segment(p, "admin") || has_segment(p, "login") ||
        has_segment(p, "signin"))
      return Severity::Medium;
    if (has_segment(p, "config") || has_segment(p, "settings") ||
        has_segment(p, "configuration"))
      return Severity::Medium;
    // api после админ правил, иначе префикс съест сегмент
    if (is("/api")) return Severity::Low;
    if (ends_with(p, "/robots.txt") || ends_with(p, "/sitemap.xml") ||
        ends_with(p, "/security.txt") || ends_with(p, "/.well-known/security.txt"))
      return Severity::Info;
    if (has_segment(p, "hidden") || has_segment(p, "private") ||
        has_segment(p, "internal") || has_segment(p, "secret") ||
        has_segment(p, "staging") || has_segment(p, "intranet"))
      return Severity::Low;
    return Severity::Info;
  }
  if (auth) {
    // 401/403 доказывает существование
    if (is("/admin") || p == "/login" || p == "/manager/html" ||
        is("/phpmyadmin") || is("/wp-admin") || p == "/panel" ||
        p == "/dashboard" || p == "/console" || is("/grafana") ||
        is("/kibana") || is("/solr"))
      return Severity::Low;
    if (ends_with(p, "/admin") || has_segment(p, "admin") ||
        has_segment(p, "administrator") || has_segment(p, "login") ||
        has_segment(p, "panel") || has_segment(p, "dashboard") ||
        has_segment(p, "console") || has_segment(p, "manager") ||
        has_segment(p, "phpmyadmin") || has_segment(p, "cpanel"))
      return Severity::Low;
    return Severity::Info;
  }
  return Severity::Info;  // редиректы и прочее, пишем без паники
}

// антибот вставляет нонсы, сравниваем сжав пробелы
bool similar_body(const std::string& a, const std::string& b) {
  if (a.empty() || b.empty()) return false;
  long diff = static_cast<long>(a.size()) - static_cast<long>(b.size());
  if (diff < 0) diff = -diff;
  if (diff <= 64) return true;
  auto fold = [](const std::string& s) {
    std::string r;
    r.reserve(s.size());
    for (char c : s) {
      if (std::isspace(static_cast<unsigned char>(c))) continue;
      r.push_back(static_cast<char>(std::tolower(
          static_cast<unsigned char>(c))));
      if (r.size() >= 240) break;
    }
    return r;
  };
  return fold(a) == fold(b);
}

bool looks_like_soft_404(size_t baseline_len, size_t body_len) {
  if (baseline_len == 0) return false;
  long diff = static_cast<long>(body_len) - static_cast<long>(baseline_len);
  if (diff < 0) diff = -diff;
  return diff <= 16;
}

// модуль

namespace {

struct Seed {
  std::string path;
  const char* source;
};

struct RefPlan {
  UrlRef ref;
  HttpOptions opt;
  size_t baseline = 0;
  bool catch_all = false;
  long base_status = 0;
  std::string base_body;
  bool blanket_reject = false;
  size_t noise_skipped = 0;
  std::vector<Seed> seeds;
  std::set<std::string> probed;
  std::set<std::string> recorded;
  std::set<std::string> dirs;
  std::set<std::string> dirs_confirmed;
  std::set<std::string> hit_words;
  std::vector<std::string> words;
  std::vector<std::string> pending;
  size_t path_overflow = 0;
  size_t find_added = 0;
  size_t find_overflow = 0;
  size_t confirmed = 0;
  long robots_status = 0;
  size_t robots_size = 0;
  long sitemap_status = 0;
  size_t sitemap_size = 0;
  std::map<std::string, size_t> by_source;
  bool cap_warned = false;
};

class WebpathsModule : public IModule {
 public:
  std::string name() const override { return "webpaths"; }
  std::string description() const override {
    return "universal content discovery: curated wordlist + page/JS/robots/"
           "sitemap mining + recursive combination probing (GET only)";
  }
  Maturity maturity() const override { return Maturity::Reference; }
  std::vector<std::string> depends() const override { return {"ports"}; }

  bool run(ModuleContext& ctx) override {
    std::vector<UrlRef> refs;
    for (const auto& t : ctx.cfg.targets) {
      const HostResult* hr = ctx.result.find_host(t.host);
      for (const auto& r : urls_for_target(t, hr)) refs.push_back(r);
    }
    if (refs.empty()) {
      ctx.pstage("webpaths", "discovery", 0);
      ctx.pdone();
      return true;
    }

    const bool deep = ctx.cfg.deep;
    const auto& base_list = path_wordlist(deep);
    const auto& suffixes = discovery_suffixes();
    const size_t max_assets = deep ? 6 : 3;
    const size_t max_words = deep ? 160 : 80;
    const size_t max_dirs = deep ? 96 : 64;
    const size_t max_round[2] = {deep ? 1200u : 800u, deep ? 800u : 500u};
    const size_t paths_cap = 600;
    const size_t findings_cap = 100;
    const size_t max_nested_sitemaps = 2;

    std::vector<RefPlan> plans(refs.size());

    auto collect_prefix_dirs = [&](const std::string& path,
                                   std::set<std::string>& out) {
      if (path.empty() || path[0] != '/') return;
      size_t pos = 1;
      int depth = 0;
      while (pos < path.size() && depth < 3) {
        size_t slash = path.find('/', pos);
        if (slash == std::string::npos) break;
        out.insert(path.substr(0, slash + 1));
        pos = slash + 1;
        ++depth;
      }
    };

    // этап 1: сиды (пул потоков, каждый реф работает со своим планом)
    ctx.pstage("webpaths", "discovery: mining page, JS, robots, sitemaps",
               refs.size() * 4);
    // rand() не потокобезопасен — базовые пути генерим заранее
    std::vector<std::string> rnds(refs.size());
    for (auto& r : rnds)
      r = "/" + std::to_string(rand()) + "-" + std::to_string(rand()) +
          ".miktobase";
    ctx.parallel(refs.size(), [&](size_t ri) {
      RefPlan& P = plans[ri];
      P.ref = refs[ri];
      P.opt.timeout_s = ctx.cfg.http_timeout_s;
      P.opt.user_agent = ctx.cfg.user_agent;
      P.opt.max_body_bytes = 512 * 1024;
      const std::string& base = P.ref.url;
      const std::string& host = P.ref.host;

      // случайный путь задаёт шумовую сигнатуру
      const std::string& rnd = rnds[ri];
      HttpResponse rb = ctx.get(base + rnd, P.opt);
      ctx.ptick();
      if (rb.ok_network() && rb.status != 404 && rb.status != 410) {
        P.base_status = rb.status;
        P.baseline = rb.body.size();
        P.base_body = rb.body;
        P.catch_all = P.baseline > 128;
        P.blanket_reject =
            P.catch_all &&
            (rb.status == 403 || rb.status == 406 || rb.status == 429 ||
             rb.status == 501 || rb.status == 503);
      }
      P.probed.insert(rnd);

      // главная уже в кэше от tech
      std::string home_body;
      {
        WebResult& home = ctx.fetch_web(base, P.opt);
        ctx.ptick();
        if (home.fetched) home_body = home.body;
      }

    
      std::string words_src = home_body;
      {
        HttpResponse r = ctx.get(base + "/robots.txt", P.opt);
        ctx.ptick();
        if (r.ok_network() && r.status == 200) {
          P.robots_status = r.status;
          P.robots_size = r.body.size();
          for (const auto& p : parse_robots_entries(r.body, host))
            P.seeds.push_back({p, "robots"});
          words_src += "\n" + r.body;
        }
      }

      // sitemap.xml + один уровень индексов
      {
        HttpResponse r = ctx.get(base + "/sitemap.xml", P.opt);
        ctx.ptick();
        if (r.ok_network() && r.status == 200) {
          P.sitemap_status = r.status;
          P.sitemap_size = r.body.size();
          for (const auto& p : parse_sitemap_locs(r.body, host))
            P.seeds.push_back({p, "sitemap"});
          size_t nested = 0;
          for (const auto& p : parse_sitemap_locs(r.body, host)) {
            if (nested >= max_nested_sitemaps) break;
            std::string lp = to_lower(p);
            if (!ends_with(lp, ".xml") ||
                lp.find("sitemap") == std::string::npos)
              continue;
            // total растёт до запроса — счётчик не переполняется
            ctx.pgrow();
            HttpResponse r2 = ctx.get(base + p, P.opt);
            ctx.ptick();
            if (r2.ok_network() && r2.status == 200) {
              for (const auto& q : parse_sitemap_locs(r2.body, host))
                P.seeds.push_back({q, "sitemap"});
              ++nested;
            }
          }
        }
      }

      //Homepage HTML -> ссылки, js/css в майнинг
      std::vector<std::string> link_paths = extract_page_paths(home_body, host);
      std::vector<std::string> mine_now;
      for (const auto& p : link_paths) {
        std::string lp = to_lower(p);
        if ((ends_with(lp, ".js") || ends_with(lp, ".mjs") ||
             ends_with(lp, ".css")) &&
            mine_now.size() < max_assets)
          mine_now.push_back(p);
      }
      ctx.pgrow(mine_now.size());
      for (const auto& p : mine_now) {
        HttpResponse r = ctx.get(base + p, P.opt);
        ctx.ptick();
        if (!r.ok_network() || r.status != 200) continue;
        for (const auto& q : extract_page_paths(r.body, host))
          P.seeds.push_back({q, "js"});
        words_src += "\n" + r.body;
      }
      for (const auto& p : link_paths)
        if (!is_static_asset_path(p)) P.seeds.push_back({p, "link"});

      // словарь
      for (const auto& p : base_list) P.seeds.push_back({p, "wordlist"});

      // слова + префикс-директории из всего что видели
      P.words = extract_path_words(words_src);
      if (P.words.size() > max_words) P.words.resize(max_words);
      for (const auto& s : P.seeds) collect_prefix_dirs(s.path, P.dirs);
    });
    ctx.pdone();

    // запись и проба

    auto record = [&](RefPlan& P, const std::string& path, long status,
                      size_t blen, const char* src) {
      if (!P.recorded.insert(path).second) return;
      ++P.confirmed;
      ++P.by_source[src];
      HostResult& hr = ctx.result.ensure_host(P.ref.host, false);
      if (hr.paths.size() < paths_cap) {
        PathHit hit;
        hit.path = path;
        hit.status = status;
        hit.size = blen;
        hit.source = src;
        hr.paths.push_back(hit);
      } else {
        ++P.path_overflow;
        if (!P.cap_warned) {
          P.cap_warned = true;
          ctx.warn("webpaths: " + P.ref.url +
                   " has more than " + std::to_string(paths_cap) +
                   " confirmed paths — the report lists the first " +
                   std::to_string(paths_cap) + "; the exact overflow is "
                   "counted below");
        }
      }
      Severity sev = classify_path(path, status);
      if (static_cast<int>(sev) < static_cast<int>(Severity::Low)) return;
      if (P.find_added < findings_cap) {
        ++P.find_added;
        Finding f;
        f.severity = sev;
        f.module = "webpaths";
        f.host = P.ref.host;
        f.port = P.ref.port;
        f.service = "web";
        f.location = P.ref.url + path;
        f.title = describe_path(path, status);
        f.detail = "The path " + path + " answered HTTP " +
                   std::to_string(status) + " with " + std::to_string(blen) +
                   " bytes of content (found via " + source_phrase(src) +
                   "). Existence of this surface widens the attack area; "
                   "review whether it must be public.";
        f.recommendation = recommend_for_path(path);
        f.evidence = "HTTP " + std::to_string(status) + " (" +
                     std::to_string(blen) + " bytes; via " + src + ")";
        ctx.result.add_finding(std::move(f));
      } else {
        ++P.find_overflow;
      }
    };

    // robots/sitemap из этапа 1 тоже в инвентарь
    for (auto& P : plans) {
      if (P.robots_status == 200)
        record(P, "/robots.txt", P.robots_status, P.robots_size, "wordlist");
      if (P.sitemap_status == 200)
        record(P, "/sitemap.xml", P.sitemap_status, P.sitemap_size, "wordlist");
    }

    // проба: дедуп и применение — последовательно, GET — пулом потоков
    struct WebJob {
      RefPlan* P;
      std::string path;
      const char* src;
    };

    auto take = [&](RefPlan& P, const std::string& path) -> bool {
      if (path.size() < 2 || path[0] != '/') return false;
      if (P.probed.count(path) || P.recorded.count(path)) return false;
      P.probed.insert(path);
      return true;
    };

    auto apply = [&](RefPlan& P, const std::string& path, const char* src,
                     const HttpResponse& resp) {
      if (!resp.ok_network()) return;
      if (resp.status == 404 || resp.status == 410) return;
      size_t blen = resp.body.size();
      // тот же статус и то же тело = шум
      if (P.catch_all && resp.status == P.base_status &&
          (looks_like_soft_404(P.baseline, blen) ||
           similar_body(P.base_body, resp.body))) {
        ++P.noise_skipped;
        return;
      }
      if (resp.status == 200 && P.catch_all &&
          looks_like_soft_404(P.baseline, blen))
        return;
      record(P, path, resp.status, blen, src);
      if (resp.status == 200) note_hit(P, path);
    };

    auto probe_many = [&](std::vector<WebJob>& jobs) {
      std::vector<WebJob> live;
      live.reserve(jobs.size());
      for (auto& j : jobs)
        if (take(*j.P, j.path)) live.push_back(std::move(j));
      if (live.empty()) return;
      // пул не по ядрам: скан i/o-bound (как в ports)
      int cap = ctx.cfg.deep ? 64 : 32;
      int nth = std::min<int>(std::max(1, ctx.cfg.concurrency), cap);
      nth = std::min<int>(nth, static_cast<int>(live.size()));
      std::vector<HttpResponse> outs(live.size());
      ctx.parallel(live.size(),
                   [&](size_t i) {
                     outs[i] = ctx.get(live[i].P->ref.url + live[i].path,
                                       live[i].P->opt);
                     ctx.ptick();
                   },
                   nth);
      // применение в исходном порядке — отчёт стабилен
      for (size_t i = 0; i < live.size(); ++i)
        apply(*live[i].P, live[i].path, live[i].src, outs[i]);
    };

    // этап 2: пробы сидов
    // страница-отказ на всё: скипаем честно вместо сотен джанка
    size_t total_seeds = 0;
    for (auto& P : plans) {
      if (P.blanket_reject) {
        HostResult& hr = ctx.result.ensure_host(P.ref.host, false);
        if (hr.scan_visibility.empty()) hr.scan_visibility = "degraded";
        std::string note =
            "content discovery skipped: a blanket rejection page (HTTP " +
            std::to_string(P.base_status) + ", " +
            std::to_string(P.baseline) + " B) answers every path — path "
            "probing cannot distinguish real surfaces behind it";
        if (std::find(hr.visibility_notes.begin(), hr.visibility_notes.end(),
                      note) == hr.visibility_notes.end())
          hr.visibility_notes.push_back(note);
        Finding f;
        f.severity = Severity::Info;
        f.module = "webpaths";
        f.host = P.ref.host;
        f.port = P.ref.port;
        f.service = "web";
        f.location = P.ref.url;
        f.title = "Content discovery skipped: blanket rejection page";
        f.detail =
            "A request to a random non-existent path answered HTTP " +
            std::to_string(P.base_status) + " with a " +
            std::to_string(P.baseline) + "-byte page (typically an anti-bot "
            "challenge or WAF block page). The same page answers other "
            "paths, so path probing cannot tell real surfaces from noise. "
            "The path inventory for this host is limited to robots.txt / "
            "sitemap.xml mining; treat the absence of findings as limited "
            "visibility, not as the absence of surfaces.";
        f.recommendation =
            "Re-scan from an allow-listed network position, or verify "
            "surface visibility manually behind the challenge.";
        f.evidence = "HTTP " + std::to_string(P.base_status) + ", " +
                     std::to_string(P.baseline) + " bytes on " +
                     "/<random>.miktobase";
        ctx.result.add_finding(std::move(f));
        ctx.warn("webpaths: " + P.ref.url + " — blanket rejection (HTTP " +
                 std::to_string(P.base_status) + ") answers every path; "
                 "probing skipped");
        continue;
      }
      std::stable_sort(P.seeds.begin(), P.seeds.end(),
                       [](const Seed& a, const Seed& b) {
                         return source_priority(a.source) <
                                source_priority(b.source);
                       });
      std::set<std::string> seen_seed;
      std::vector<Seed> uniq;
      for (auto& s : P.seeds) {
        if (s.path.size() < 2) continue;
        if (!seen_seed.insert(s.path).second) continue;
        // статику не щупаем, она и так видна
        if ((s.source == std::string_view{"link"} ||
             s.source == std::string_view{"js"}) &&
            is_static_asset_path(s.path))
          continue;
        uniq.push_back(s);
      }
      P.seeds.swap(uniq);
      total_seeds += P.seeds.size();
    }
    if (total_seeds > 0) {
      ctx.pstage("webpaths", "discovery: probing mined & curated paths",
                 total_seeds);
      std::vector<WebJob> seed_jobs;
      for (auto& P : plans) {
        if (P.blanket_reject) continue;
        for (const auto& s : P.seeds)
          seed_jobs.push_back({&P, s.path, s.source});
      }
      probe_many(seed_jobs);
      ctx.pdone();
    }

    // этап 3: два раунда комбинаций
    for (int round = 0; round < 2; ++round) {
      for (auto& P : plans) {
        for (const auto& w : P.hit_words)
          if (std::find(P.words.begin(), P.words.end(), w) == P.words.end())
            P.words.push_back(w);
        if (P.words.size() > max_words + 32) P.words.resize(max_words + 32);
      }
      // слепым не строим кандидатов
      std::vector<std::vector<std::string>> cands(plans.size());
      size_t total_c = 0;
      for (size_t i = 0; i < plans.size(); ++i) {
        RefPlan& P = plans[i];
        if (P.blanket_reject) continue;
        std::vector<std::string> dirs(P.dirs_confirmed.begin(),
                                      P.dirs_confirmed.end());
        for (const auto& d : P.dirs)
          if (!P.dirs_confirmed.count(d)) dirs.push_back(d);
        std::stable_sort(dirs.begin(), dirs.end(),
                         [](const std::string& a, const std::string& b) {
                           return a.size() < b.size();
                         });  // мелкие первыми
        if (dirs.size() > max_dirs) dirs.resize(max_dirs);
        for (const auto& c :
             generate_discovery_candidates(dirs, P.words, suffixes,
                                           max_round[round]))
          if (!P.probed.count(c) && !P.recorded.count(c))
            cands[i].push_back(c);
        total_c += cands[i].size();
      }
      if (total_c == 0) break;
      ctx.pstage("webpaths",
                 round == 0
                     ? "discovery: combination round 1 (dirs/words x suffixes)"
                     : "discovery: combination round 2 (recursive)",
                 total_c);
      std::vector<WebJob> combo_jobs;
      for (size_t i = 0; i < plans.size(); ++i) {
        RefPlan& P = plans[i];
        if (P.blanket_reject) continue;
        for (const auto& c : cands[i])
          combo_jobs.push_back({&P, c, "combo"});
      }
      probe_many(combo_jobs);
      // этап комбинаций закрыт ровно на total_c; майнинг и ссылки —
      // отдельные этапы, иначе счётчик уезжает за total (done > total)
      ctx.pdone();

      // майним тела новеньких страниц — тотал известен заранее
      struct MineTask {
        RefPlan* P;
        std::string path;
      };
      std::vector<MineTask> mine_tasks;
      for (auto& P : plans) {
        size_t taken = 0;
        std::vector<PathHit> snap =
            ctx.result.ensure_host(P.ref.host, false).paths;
        for (const auto& hit : snap) {
          if (taken >= 3) break;
          if (hit.status != 200) continue;
          if (is_static_asset_path(hit.path)) continue;
          if (P.probed.count("!" + hit.path)) continue;  // маркер майнинга
          P.probed.insert("!" + hit.path);
          mine_tasks.push_back({&P, hit.path});
          ++taken;
        }
      }
      if (!mine_tasks.empty()) {
        ctx.pstage("webpaths", "discovery: mining new pages",
                   mine_tasks.size());
        std::vector<HttpResponse> outs(mine_tasks.size());
        ctx.parallel(mine_tasks.size(),
                     [&](size_t i) {
                       outs[i] = ctx.get(mine_tasks[i].P->ref.url +
                                             mine_tasks[i].path,
                                         mine_tasks[i].P->opt);
                       ctx.ptick();
                     },
                     16);
        for (size_t i = 0; i < mine_tasks.size(); ++i) {
          const HttpResponse& r = outs[i];
          MineTask& mt = mine_tasks[i];
          if (!r.ok_network() || r.status != 200 || r.body.empty()) continue;
          for (const auto& q : extract_page_paths(r.body, mt.P->ref.host))
            if (!mt.P->probed.count(q) && !mt.P->recorded.count(q) &&
                !is_static_asset_path(q))
              mt.P->pending.push_back(q);
          for (const auto& w : extract_path_words(r.body))
            mt.P->hit_words.insert(w);
        }
        ctx.pdone();
      }

      // пробы накопленных ссылок — свой этап с точным тоталом
      size_t link_total = 0;
      for (auto& P : plans) link_total += P.pending.size();
      if (link_total > 0) {
        ctx.pstage("webpaths", "discovery: probing mined links", link_total);
        std::vector<WebJob> link_jobs;
        for (auto& P : plans) {
          for (const auto& q : P.pending)
            link_jobs.push_back({&P, q, "link"});
          P.pending.clear();
        }
        probe_many(link_jobs);
        ctx.pdone();
      }
    }

    // переливы за капы + итог
    for (auto& P : plans) {
      if (P.ref.host.empty()) continue;
      if (P.path_overflow > 0)
        ctx.warn("webpaths: " + P.ref.url + " — " +
                 std::to_string(P.path_overflow) +
                 " confirmed paths beyond the " + std::to_string(paths_cap) +
                 "-path inventory cap are counted but not listed");
      if (P.find_overflow > 0)
        ctx.warn("webpaths: " + P.ref.url + " — " +
                 std::to_string(P.find_overflow) +
                 " low/medium/high findings beyond the console cap are in the "
                 "Web paths inventory of the JSON/HTML report");
      if (P.confirmed == 0) continue;
      Finding f;
      f.severity = Severity::Info;
      f.module = "webpaths";
      f.host = P.ref.host;
      f.port = P.ref.port;
      f.service = "web";
      f.location = P.ref.url;
      f.title = "Content discovery confirmed " + std::to_string(P.confirmed) +
                " surfaces on " + P.ref.url;
      std::string detail =
          "The discovery engine probed the curated list plus paths mined from "
          "the homepage HTML, fetched scripts, robots.txt and sitemap.xml, "
          "then ran recursive combination rounds over the discovered "
          "directories and words. Confirmed " +
          std::to_string(P.confirmed) + " paths (";
      bool first = true;
      for (const auto& [src, n] : P.by_source) {
        if (!first) detail += ", ";
        detail += src + ": " + std::to_string(n);
        first = false;
      }
      detail += "). Every confirmed path — including informational ones — is "
                "listed in the host's Web paths inventory; nothing is omitted.";
      f.detail = detail;
      f.recommendation =
          "Review the full Web paths inventory in the report; hide, restrict "
          "or remove any surface that must not be public.";
      f.evidence = std::to_string(P.confirmed) + " confirmed paths";
      ctx.result.add_finding(std::move(f));
      ctx.log("webpaths: " + P.ref.url + " — " +
              std::to_string(P.confirmed) + " paths confirmed");
    }
    return true;
  }

 private:
  // подтверждённый путь кормит след раунд
  static void note_hit(RefPlan& P, const std::string& path) {
    std::string p = path;
    if (!p.empty() && p.back() == '/') {
      if (p.size() > 1) P.dirs_confirmed.insert(p);
    } else {
      size_t slash = p.find_last_of('/');
      std::string last = slash == std::string::npos ? p : p.substr(slash + 1);
      if (last.find('.') == std::string::npos && p.size() < 200)
        P.dirs_confirmed.insert(p + "/");
    }
    size_t start = 0;
    while (start < p.size()) {
      size_t slash = p.find('/', start);
      std::string seg =
          p.substr(start, slash == std::string::npos ? std::string::npos
                                                     : slash - start);
      if (seg.size() >= 3 && seg.size() <= 24 &&
          seg.find('.') == std::string::npos)
        P.hit_words.insert(to_lower(seg));
      if (slash == std::string::npos) break;
      start = slash + 1;
    }
  }

  static std::string describe_path(const std::string& p, long status) {
    std::string lp = to_lower(p);
    if (lp == "/.env" || ends_with(lp, ".sql") || ends_with(lp, ".sqlite") ||
        starts_with(lp, "/.git/") || lp == "/.git/HEAD" ||
        lp == "/.aws/credentials" || lp == "/.ssh/id_rsa" ||
        ends_with(lp, ".bak") || has_segment(lp, ".env") ||
        lp.find("/.git/") != std::string::npos)
      return "Source/secret file exposed: " + p;
    if (lp == "/phpinfo.php" || lp == "/info.php" || lp == "/debug/vars" ||
        has_segment(lp, "phpinfo.php"))
      return "Debug endpoint exposed: " + p;
    if (starts_with(lp, "/actuator/") && lp != "/actuator/health")
      return "Spring Boot actuator endpoint exposed: " + p;
    if (lp == "/_profiler" || lp == "/_debugbar/" || lp == "/app_dev.php")
      return "Debug toolbar exposed: " + p;
    if (lp == "/manager/html" || lp == "/host-manager" || lp == "/web-console")
      return "Server management console exposed: " + p;
    if (lp == "/wp-login.php" || starts_with(lp, "/wp-admin"))
      return "WordPress admin surface: " + p;
    if (lp == "/xmlrpc.php") return "WordPress XML-RPC enabled: " + p;
    if (has_segment(lp, "admin") || has_segment(lp, "administrator") ||
        has_segment(lp, "phpmyadmin") || has_segment(lp, "cpanel") ||
        lp == "/login" || lp == "/panel" || lp == "/dashboard" ||
        lp == "/console")
      return "Admin surface found: " + p + " (HTTP " + std::to_string(status) +
             ")";
    if (lp == "/swagger" || lp == "/swagger.json" || lp == "/api-docs" ||
        lp == "/openapi.json" || lp == "/swagger-ui.html" || lp == "/graphql" ||
        lp == "/actuator" || ends_with(lp, "/swagger.json") ||
        ends_with(lp, "/openapi.json"))
      return "API documentation/actuator exposed: " + p;
    if (has_segment(lp, "login") || has_segment(lp, "signin") ||
        has_segment(lp, "manager") || has_segment(lp, "panel") ||
        has_segment(lp, "dashboard") || has_segment(lp, "console"))
      return "Protected surface found: " + p + " (HTTP " +
             std::to_string(status) + ")";
    if (ends_with(lp, ".sql") || ends_with(lp, ".zip") || ends_with(lp, ".tgz"))
      return "Backup or database dump exposed: " + p;
    return "Path exists: " + p;
  }

  static std::string recommend_for_path(const std::string& p) {
    std::string lp = to_lower(p);
    if (starts_with(lp, "/.git") || lp == "/.env" || has_segment(lp, ".env") ||
        ends_with(lp, ".sql") || ends_with(lp, ".bak"))
      return "Remove the file from the web root, purge it from deployments, "
             "and block serving dotfiles/backups at the web server level. "
             "Rotate any credentials found inside.";
    if (lp == "/phpinfo.php" || lp == "/info.php" || lp == "/debug/vars" ||
        has_segment(lp, "phpinfo.php"))
      return "Remove debug endpoints from production; they disclose paths, "
             "env variables and configuration.";
    if (lp == "/wp-login.php" || starts_with(lp, "/wp-admin"))
      return "Restrict /wp-admin to trusted IPs, enforce strong passwords "
             "and 2FA; consider disabling xmlrpc.php if unused.";
    if (has_segment(lp, "admin") || lp == "/login" || lp == "/panel" ||
        lp == "/dashboard" || has_segment(lp, "phpmyadmin"))
      return "Put authentication in front of the panel (SSO/VPN/IP allow-list) "
             "and disable default credentials.";
    return "Verify the surface must be public; restrict or remove it if not, "
           "and keep the underlying software updated.";
  }
};

}  // namespace

std::unique_ptr<IModule> make_webpaths_module() {
  return std::make_unique<WebpathsModule>();
}

}  // namespace mikto
