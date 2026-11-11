// тесты security-заголовков
#include "test_fw.hpp"

#include "modules/modules.hpp"

using namespace mikto;

namespace {

HeaderCheckInput https_input() {
  return HeaderCheckInput{"https://x.example", "x.example", 443, true};
}

}  // namespace

MIKTO_TEST(headers_all_present_zero_findings) {
  WebResult w;
  w.status = 200;
  w.headers = {
      {"Strict-Transport-Security", "max-age=31536000; includeSubDomains"},
      {"Content-Security-Policy", "default-src 'self'"},
      {"X-Content-Type-Options", "nosniff"},
      {"X-Frame-Options", "DENY"},
      {"Referrer-Policy", "strict-origin-when-cross-origin"},
      {"Permissions-Policy", "camera=()"},
      {"Server", "nginx"},
      {"Set-Cookie",
       "sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax"},
  };
  auto fs = analyze_security_headers(https_input(), w);
  CHECK_EQ(fs.size(), size_t(0));
}

MIKTO_TEST(headers_missing_basics) {
  WebResult w;
  w.status = 200;
  w.headers = {{"Server", "nginx/1.25.3"}};
  auto fs = analyze_security_headers(https_input(), w);
  bool hsts = false, csp = false, xcto = false, frame = false, referrer = false,
       disclosure = false;
  for (const auto& f : fs) {
    if (f.title.find("Strict-Transport-Security") != std::string::npos)
      hsts = true;
    if (f.title.find("Content-Security-Policy") != std::string::npos)
      csp = true;
    if (f.title.find("X-Content-Type-Options") != std::string::npos)
      xcto = true;
    if (f.title.find("clickjacking") != std::string::npos) frame = true;
    if (f.title.find("Referrer-Policy") != std::string::npos) referrer = true;
    if (f.title.find("Server version disclosure") != std::string::npos)
      disclosure = true;
    CHECK(!f.recommendation.empty());
  }
  CHECK(hsts);
  CHECK(csp);
  CHECK(xcto);
  CHECK(frame);
  CHECK(referrer);
  CHECK(disclosure);
  for (const auto& f : fs) {
    if (f.title.find("Strict-Transport-Security") != std::string::npos)
      CHECK(f.severity == Severity::Medium);
    if (f.title.find("Content-Security-Policy") != std::string::npos)
      CHECK(f.severity == Severity::Medium);
    if (f.title.find("Server version disclosure") != std::string::npos)
      CHECK(f.severity == Severity::Low);
  }
}

MIKTO_TEST(headers_insecure_cookie) {
  WebResult w;
  w.status = 200;
  w.headers = {{"Set-Cookie", "session=xyz; Path=/"}};
  auto fs = analyze_security_headers(https_input(), w);
  bool cookie = false;
  for (const auto& f : fs) {
    if (f.title.find("Cookie without protective flags") != std::string::npos) {
      cookie = true;
      CHECK(f.severity == Severity::Medium);
      CHECK(f.detail.find("Secure") != std::string::npos);
    }
  }
  CHECK(cookie);
}

MIKTO_TEST(headers_hsts_weak_max_age) {
  WebResult w;
  w.status = 200;
  w.headers = {
      {"Strict-Transport-Security", "max-age=86400"},
      {"Content-Security-Policy", "default-src 'self'"},
      {"X-Content-Type-Options", "nosniff"},
      {"X-Frame-Options", "SAMEORIGIN"},
      {"Referrer-Policy", "no-referrer"},
      {"Permissions-Policy", "camera=()"},
  };
  auto fs = analyze_security_headers(https_input(), w);
  bool weak = false;
  for (const auto& f : fs)
    if (f.title.find("Weak HSTS") != std::string::npos) weak = true;
  CHECK(weak);
}

MIKTO_TEST(headers_plain_http_note) {
  WebResult w;
  w.status = 200;
  w.headers = {{"Content-Security-Policy", "default-src 'self'"}};
  HeaderCheckInput in{"http://x.example", "x.example", 80, false};
  auto fs = analyze_security_headers(in, w);
  bool note = false;
  for (const auto& f : fs)
    if (f.title.find("redirect to HTTPS") != std::string::npos) note = true;
  CHECK(note);
}

MIKTO_TEST(cookie_flags_exact_tokens) {
  auto ok = parse_cookie_flags("sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax");
  CHECK(ok.secure);
  CHECK(ok.httponly);
  CHECK(ok.samesite);

  auto ci = parse_cookie_flags("SID=abc; secure; HTTPONLY; samesite=strict");
  CHECK(ci.secure);
  CHECK(ci.httponly);
  CHECK(ci.samesite);

  // "secure" в значении куки не атрибут
  auto tricky = parse_cookie_flags("theme=secure-dark; Path=/");
  CHECK(!tricky.secure);
  CHECK(!tricky.httponly);
  CHECK(!tricky.samesite);

  auto tricky2 = parse_cookie_flags("securesession=1; samesitepolicy=strict");
  CHECK(!tricky2.secure);
  CHECK(!tricky2.samesite);
}

MIKTO_TEST(cookie_flags_missing_flags_reported) {
  // "secure" только в значении: находка всё равно срабатывает
  WebResult w;
  w.status = 200;
  w.headers = {{"Set-Cookie", "sid=secure-value-only; Path=/"}};
  auto fs = analyze_security_headers(https_input(), w);
  bool cookie_finding = false;
  for (const auto& f : fs)
    if (f.title.find("Cookie without protective flags") != std::string::npos)
      cookie_finding = true;
  CHECK(cookie_finding);
}
