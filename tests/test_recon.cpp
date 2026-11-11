// тесты recon: tech, пути, субдомены, почта, os
#include "test_fw.hpp"

#include <set>

#include "mikto/finding.hpp"
#include "mikto/scan_result.hpp"
#include "mikto/types.hpp"
#include "mikto/util.hpp"
#include "modules/modules.hpp"

namespace {

using namespace mikto;

WebResult make_web(std::string url, std::string server, std::string body) {
  WebResult w;
  w.url = std::move(url);
  w.status = 200;
  w.server = std::move(server);
  w.body = std::move(body);
  w.fetched = true;
  if (!w.server.empty()) w.headers.push_back({"Server", w.server});
  return w;
}

}  // namespace

// tech

MIKTO_TEST(tech_wordpress_and_php) {
  WebResult w = make_web("http://a.example/", "nginx/1.24.0",
                         "<html><head><meta name=\"generator\" "
                         "content=\"WordPress 6.4.2\"></head>"
                         "<body><link href=\"/wp-content/themes/x/style.css\">"
                         "</body></html>");
  w.headers.push_back({"X-Powered-By", "PHP/7.4.33"});
  w.headers.push_back({"Set-Cookie",
                       "PHPSESSID=abc; path=/; HttpOnly"});

  std::vector<TechHit> hits = detect_technologies(w);
  auto find = [&](const char* name) -> const TechHit* {
    for (const auto& h : hits)
      if (iequals(h.name, name)) return &h;
    return nullptr;
  };
  const TechHit* wp = find("WordPress");
  CHECK(wp != nullptr);
  if (wp) CHECK_EQ(wp->version, std::string("6.4.2"));
  const TechHit* php = find("PHP");
  CHECK(php != nullptr);
  if (php) CHECK_EQ(php->version, std::string("7.4.33"));
  const TechHit* ngx = find("nginx");
  CHECK(ngx != nullptr);
  if (ngx) CHECK_EQ(ngx->version, std::string("1.24.0"));
}

MIKTO_TEST(tech_frontend_frameworks) {
  WebResult w = make_web("http://b.example/", "nginx",
                         "<div id=\"app\" data-v-app=\"\"><script "
                         "src=\"/assets/index-abc.js\"></script>"
                         "<script src=\"/js/jquery-3.7.1.min.js\"></script>"
                         "</div>");
  std::vector<TechHit> hits = detect_technologies(w);
  auto find = [&](const char* name) -> const TechHit* {
    for (const auto& h : hits)
      if (iequals(h.name, name)) return &h;
    return nullptr;
  };
  const TechHit* vue = find("Vue");
  CHECK(vue != nullptr);
  const TechHit* jq = find("jQuery");
  CHECK(jq != nullptr);
  if (jq) CHECK_EQ(jq->version, std::string("3.7.1"));
}

MIKTO_TEST(tech_cookie_markers) {
  WebResult w = make_web("http://c.example/", "microsoft-iis/10.0", "<html></html>");
  w.headers.push_back({"Set-Cookie", "ASP.NET_SessionId=xyz; path=/"});
  std::vector<TechHit> hits = detect_technologies(w);
  bool aspnet = false, iis = false;
  for (const auto& h : hits) {
    if (iequals(h.name, "ASP.NET")) aspnet = true;
    if (iequals(h.name, "IIS")) iis = true;
  }
  CHECK(aspnet);
  CHECK(iis);
}

MIKTO_TEST(tech_no_false_hits_on_empty) {
  WebResult w = make_web("http://d.example/", "", "hello world");
  std::vector<TechHit> hits = detect_technologies(w);
  CHECK(hits.empty());
}

// os guess

MIKTO_TEST(os_guess_banners) {
  CHECK_EQ(guess_os_from_banners({"OpenSSH/9.6p1",
                                  "SSH-2.0-OpenSSH_9.6p1 Ubuntu-4ubuntu0.5"}),
           std::string("Linux (Ubuntu)"));
  CHECK_EQ(guess_os_from_banners({"IIS/10.0", "microsoft-iis"}),
           std::string("Windows"));
  CHECK_EQ(guess_os_from_banners({"Apache/2.4.41 (Debian)"}),
           std::string("Linux (Debian)"));
  CHECK_EQ(guess_os_from_banners({"nginx/1.25.3"}), std::string(""));
  CHECK_EQ(guess_os_from_banners({}), std::string(""));
}

// пути

MIKTO_TEST(path_classification) {
  CHECK_EQ(classify_path("/.env", 200), Severity::Critical);
  CHECK_EQ(classify_path("/.git/HEAD", 200), Severity::Critical);
  CHECK_EQ(classify_path("/phpinfo.php", 200), Severity::High);
  CHECK_EQ(classify_path("/dump.sql", 200), Severity::High);
  CHECK_EQ(classify_path("/manager/html", 200), Severity::High);
  CHECK_EQ(classify_path("/wp-login.php", 200), Severity::Medium);
  CHECK_EQ(classify_path("/admin", 200), Severity::Medium);
  CHECK_EQ(classify_path("/admin", 403), Severity::Low);
  CHECK_EQ(classify_path("/admin", 404), Severity::Info);
  CHECK_EQ(classify_path("/robots.txt", 200), Severity::Info);
  CHECK_EQ(classify_path("/swagger.json", 200), Severity::Medium);
  CHECK_EQ(classify_path("/actuator/health", 200), Severity::Medium);
}

MIKTO_TEST(path_soft404) {
  CHECK(looks_like_soft_404(1200, 1210));
  CHECK(!looks_like_soft_404(1200, 200));
  CHECK(!looks_like_soft_404(0, 100));
}

MIKTO_TEST(path_wordlist_grows_in_deep) {
  const std::vector<std::string>& safe = path_wordlist(false);
  const std::vector<std::string>& deep = path_wordlist(true);
  CHECK(safe.size() >= 30);
  CHECK(deep.size() > safe.size());
  bool has_env = false;
  for (const auto& p : safe)
    if (p == "/.env") has_env = true;
  CHECK(has_env);
}

// дискавери путей

MIKTO_TEST(url_host_and_same_site) {
  CHECK_EQ(url_host("https://api.Ex.com:8443/x"), std::string("api.ex.com"));
  CHECK_EQ(url_host("http://USER@Site.example"), std::string("site.example"));
  CHECK_EQ(url_host("http://[2001:db8::1]:8080/a"), std::string("2001:db8::1"));
  CHECK_EQ(url_host("/relative/path"), std::string(""));
  CHECK(same_site_host("example.com", "example.com"));
  CHECK(same_site_host("example.com", "www.example.com"));
  CHECK(same_site_host("www.example.com", "example.com"));
  CHECK(!same_site_host("example.com", "evil-example.com"));
  CHECK(!same_site_host("example.com", ""));
}

MIKTO_TEST(extract_page_paths_finds_hidden_routes) {
  std::string body =
      "<a href=\"/admin\">a</a>"
      "<script>fetch(\"/api/lol/admin\");</script>"
      "<img src='/media/logo.png'>"
      "<style>body{background:url(/img/bg.png)}</style>"
      "<a href=\"/search?q=1#top\">s</a>"
      "<a href=\"https://site.example/images/a.png\">abs</a>"
      "<a href=\"https://cdn.other.com/lib.js\">foreign</a>"
      "<a href=\"//proto.example/rel\">proto-rel</a>"
      "<a href=\"/v1.0/config.\">dot</a>";
  auto paths = extract_page_paths(body, "site.example");
  auto has = [&](const char* p) {
    return std::find(paths.begin(), paths.end(), std::string(p)) != paths.end();
  };
  CHECK(has("/admin"));
  CHECK(has("/api/lol/admin"));         // the hidden route inside JS
  CHECK(has("/media/logo.png"));
  CHECK(has("/img/bg.png"));            // unquoted CSS url()
  CHECK(has("/search"));                // query/fragment stripped
  CHECK(has("/images/a.png"));
  CHECK(!has("https://cdn.other.com/lib.js"));
  CHECK(!has("/rel"));                  // protocol-relative = foreign
  CHECK(has("/v1.0/config"));           // trailing punctuation trimmed
  for (const auto& p : paths)
    CHECK(p[0] == '/' && p.find("..") == std::string::npos);
}

MIKTO_TEST(extract_path_words_mines_sections) {
  auto words = extract_path_words(
      "var adminPanel={}; function doLoad(){window.location='/api/v2/users';} "
      "const LOADER_URL='/staging-config'; z={'2fa':true}");
  auto has = [&](const char* w) {
    return std::find(words.begin(), words.end(), std::string(w)) != words.end();
  };
  CHECK(has("admin"));                  // camelCase split
  CHECK(has("panel"));
  CHECK(has("staging"));
  CHECK(has("config"));
  CHECK(has("2fa"));
  CHECK(!has("function"));              // мусорные слова отфильтрованы
  CHECK(!has("window"));
  CHECK(!has("location"));
}

MIKTO_TEST(parse_robots_and_sitemap) {
  std::string robots =
      "# comment\n"
      "User-agent: *\n"
      "Disallow: /secret/admin/\n"
      "Disallow: */private\n"
      "Disallow: /*.php$\n"
      "Allow: /public/\n"
      "Sitemap: https://site.example/sitemap_index.xml\n"
      "Sitemap: https://other.example/sitemap.xml\n";
  auto entries = parse_robots_entries(robots, "site.example");
  auto has = [&](const char* p) {
    return std::find(entries.begin(), entries.end(), std::string(p)) !=
           entries.end();
  };
  CHECK(has("/secret/admin/"));
  CHECK(has("/private"));               // ведущая звёздочка снята
  CHECK(has("/public/"));
  CHECK(has("/sitemap_index.xml"));
  CHECK(!has("/sitemap.xml"));          // чужой sitemap выброшен
  CHECK(!has("/*.php$"));               // wildcard в середине пути выброшен

  std::string xml =
      "<urlset><url><loc>https://SITE.example/page1</loc></url>"
      "<url><loc>https://site.example/blog/post-2?q=x</loc></url>"
      "<url><loc>https://cdn.other.example/nope</loc></url></urlset>";
  auto locs = parse_sitemap_locs(xml, "site.example");
  CHECK_EQ(locs.size(), size_t(2));
  CHECK_EQ(locs[0], std::string("/page1"));
  CHECK_EQ(locs[1], std::string("/blog/post-2"));
}

MIKTO_TEST(discovery_candidate_generation) {
  std::vector<std::string> dirs = {"/api/"};
  std::vector<std::string> words = {"lol", "wp"};
  const auto& suffixes = discovery_suffixes();
  auto cands = generate_discovery_candidates(dirs, words, suffixes, 10000);
  auto has = [&](const char* p) {
    return std::find(cands.begin(), cands.end(), std::string(p)) != cands.end();
  };
  CHECK(has("/api/admin"));
  CHECK(has("/api/.env"));
  CHECK(has("/lol"));
  CHECK(has("/api/lol"));
  CHECK(has("/lol/.git/HEAD"));
  CHECK(has("/lol/admin"));
  std::set<std::string> uniq(cands.begin(), cands.end());
  CHECK_EQ(uniq.size(), cands.size());
  for (const auto& c : cands) {
    CHECK(c.size() >= 2 && c[0] == '/' && c.back() != '/');
    CHECK(c.find("..") == std::string::npos);
  }
  CHECK(generate_discovery_candidates(dirs, words, suffixes, 7).size() == 7);
  CHECK(generate_discovery_candidates({}, {}, suffixes, 7).empty());
}

MIKTO_TEST(classify_discovered_paths_any_depth) {
  // классификация по последнему сегменту
  CHECK_EQ(classify_path("/api/lol/admin", 200), Severity::Medium);
  CHECK_EQ(classify_path("/nested/deep/admin", 403), Severity::Low);
  CHECK_EQ(classify_path("/x/y/.env", 200), Severity::Critical);
  CHECK_EQ(classify_path("/api/v2/.git/HEAD", 200), Severity::Critical);
  CHECK_EQ(classify_path("/backup/db.sql", 200), Severity::High);
  CHECK_EQ(classify_path("/old/site.zip", 200), Severity::High);
  CHECK_EQ(classify_path("/deep/nested/phpinfo.php", 200), Severity::High);
  CHECK_EQ(classify_path("/a/b/dashboard", 200), Severity::Medium);
  CHECK_EQ(classify_path("/a/b/login", 200), Severity::Medium);
  CHECK_EQ(classify_path("/hidden-panel/config", 200), Severity::Medium);
  CHECK_EQ(classify_path("/obsidian-portal", 200), Severity::Info);
  CHECK_EQ(classify_path("/internal/tools/", 200), Severity::Low);
  CHECK_EQ(classify_path("/sub/robots.txt", 200), Severity::Info);
  CHECK_EQ(classify_path("/totally/unknown/section", 200), Severity::Info);
  CHECK_EQ(classify_path("/totally/unknown/section", 404), Severity::Info);
}

MIKTO_TEST(static_asset_filter) {
  CHECK(is_static_asset_path("/js/app.js"));
  CHECK(is_static_asset_path("/IMG/logo.PNG"));
  CHECK(is_static_asset_path("/css/site.css?ver=2"));
  CHECK(is_static_asset_path("/fonts/a.woff2"));
  CHECK(is_static_asset_path("/feed.xml"));
  CHECK(!is_static_asset_path("/admin"));
  CHECK(!is_static_asset_path("/api/lol/admin"));
  CHECK(!is_static_asset_path("/package.json"));
  CHECK(!is_static_asset_path("/backup/db.sql"));
}

// субдомены

MIKTO_TEST(subdom_extraction) {
  std::string crt = R"({"name_value":"dev.example.com\n*.wild.example.com\nexample.com"},
                     {"name_value":"api.example.com"})";
  std::vector<std::string> out;
  extract_hostnames(crt, "example.com", out);
  std::set<std::string> s(out.begin(), out.end());
  CHECK(s.count("dev.example.com"));
  CHECK(s.count("api.example.com"));
  CHECK(!s.count("example.com"));       // apex not a subdomain
  CHECK(!s.count("*.wild.example.com"));
  CHECK(!s.count("notexample.com"));     // только настоящие субдомены
}

MIKTO_TEST(subdom_extraction_urls_and_decoys) {
  std::string text =
      "https://stage.app.example.com/login https://evil.example.com.evil.io/x "
      "mail.staging.example.com";
  std::vector<std::string> out;
  extract_hostnames(text, "example.com", out);
  std::set<std::string> s(out.begin(), out.end());
  CHECK(s.count("stage.app.example.com"));
  CHECK(s.count("mail.staging.example.com"));
  // чужой домен не извлекается
  CHECK(!s.count("evil.example.com.evil.io"));
}

// почта

MIKTO_TEST(emails_extraction) {
  std::string body =
      "Contact us: <a href='mailto:info@example.com'>info@example.com</a> "
      "or john.doe@example.com, sales@example.com. "
      "Other vendor: someone@vendor.org is out of scope. "
      "Junk: 1.2.3@example.com image@2x.png noreply@sentry.io";
  std::vector<std::string> out;
  extract_emails(body, "example.com", out);
  std::set<std::string> s(out.begin(), out.end());
  CHECK(s.count("info@example.com"));
  CHECK(s.count("john.doe@example.com"));
  CHECK(s.count("sales@example.com"));
  CHECK(!s.count("someone@vendor.org"));
  CHECK(!s.count("1.2.3@example.com"));
  CHECK(!s.count("image@2x.png"));
  CHECK(!s.count("noreply@sentry.io"));
}

// cvelist v5

MIKTO_TEST(cvelist_v5_parse) {
  std::string body = R"({
    "containers": {
      "cna": {
        "descriptions": [{"lang": "en", "value": "A bad bug in widget."}],
        "metrics": [{"cvssV3_1": [{"baseScore": 9.8, "baseSeverity": "CRITICAL"}]}]
      }
    }
  })";
  std::string cvss, sev, desc;
  parse_cvelist_v5(body, cvss, sev, desc);
  CHECK_EQ(cvss, std::string("9.8"));
  CHECK_EQ(sev, std::string("CRITICAL"));
  CHECK(desc.find("bad bug") != std::string::npos);
}

MIKTO_TEST(cvelist_v5_invalid) {
  std::string cvss = "keep", sev, desc;
  parse_cvelist_v5("not json", cvss, sev, desc);
  CHECK_EQ(cvss, std::string("keep"));
  CHECK(sev.empty());
}
