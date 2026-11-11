// тесты детекта: баннеры, waf, honeypot
#include "test_fw.hpp"

#include <string>
#include <vector>

#include "mikto/scan_result.hpp"
#include "mikto/util.hpp"
#include "modules/modules.hpp"

namespace {

using namespace mikto;

// протоколы по портам

MIKTO_TEST(expected_protocol_map) {
  CHECK_EQ(std::string(expected_protocol_for_port(22)), "ssh");
  CHECK_EQ(std::string(expected_protocol_for_port(80)), "http");
  CHECK_EQ(std::string(expected_protocol_for_port(443)), "https");
  CHECK_EQ(std::string(expected_protocol_for_port(3306)), "mysql");
  CHECK_EQ(std::string(expected_protocol_for_port(6379)), "redis");
  CHECK_EQ(std::string(expected_protocol_for_port(27017)), "mongodb");
  CHECK_EQ(std::string(expected_protocol_for_port(5900)), "vnc");
  CHECK_EQ(std::string(expected_protocol_for_port(3000)), "");
  CHECK_EQ(std::string(expected_protocol_for_port(31337)), "");
}

// баннеры

MIKTO_TEST(banner_ssh_with_os_suffix) {
  ServiceGuess g = detect_from_banner("SSH-2.0-OpenSSH_9.6p1 Debian-2ubuntu3\r\n", 22);
  CHECK_EQ(g.service, std::string("ssh"));
  CHECK_EQ(g.product, std::string("OpenSSH"));
  CHECK_EQ(g.version, std::string("9.6p1"));
  CHECK_EQ(g.os_clue, std::string("ubuntu"));  // дебиан-таг значит ubuntu
  CHECK(g.confidence == 3);
}

MIKTO_TEST(banner_vnc_rfb) {
  ServiceGuess g = detect_from_banner("RFB 003.008\n", 5900);
  CHECK_EQ(g.service, std::string("vnc"));
  CHECK_EQ(g.product, std::string("RFB"));
  CHECK_EQ(g.version, std::string("003.008"));
  CHECK(g.confidence == 3);
}

MIKTO_TEST(banner_mysql_greeting) {
  // магические байты mysql
  std::string b;
  b += std::string("\x2a\x00\x00\x00\x0a", 5);
  b += "8.0.34\x00rest";
  ServiceGuess g = detect_from_banner(b, 3306);
  CHECK_EQ(g.service, std::string("mysql"));
  CHECK_EQ(g.product, std::string("MySQL"));
  CHECK_EQ(g.version, std::string("8.0.34"));
  CHECK(g.confidence == 3);
}

MIKTO_TEST(banner_mariadb_greeting) {
  std::string b;
  b += std::string("\x2a\x00\x00\x00\x0a", 5);
  b += "10.11.5-MariaDB\x00";
  ServiceGuess g = detect_from_banner(b, 3306);
  CHECK_EQ(g.product, std::string("MariaDB"));
  CHECK_EQ(g.version, std::string("10.11.5"));
}

MIKTO_TEST(banner_empty_is_guess) {
  ServiceGuess g = detect_from_banner("", 12345);
  CHECK(g.confidence == 0);
  CHECK(g.service.empty());
}

MIKTO_TEST(banner_ftp_greeting) {
  ServiceGuess g = detect_from_banner("220 (vsFTPd 3.0.5)", 21);
  CHECK_EQ(g.service, std::string("ftp"));
  CHECK_EQ(g.product, std::string("vsftpd"));
  CHECK_EQ(g.version, std::string("3.0.5"));
  CHECK(g.confidence == 3);
}

// парс Server

MIKTO_TEST(server_header_multi_product) {
  auto out = parse_server_products("Apache/2.4.41 (Unix) OpenSSL/1.1.1d");
  CHECK(out.size() == 2);
  CHECK_EQ(out[0].product, std::string("Apache"));
  CHECK_EQ(out[0].version, std::string("2.4.41"));
  CHECK_EQ(out[0].os_clue, std::string("Unix"));
  CHECK(out[0].confidence == 2);
  CHECK_EQ(out[1].product, std::string("OpenSSL"));
  CHECK_EQ(out[1].version, std::string("1.1.1d"));
}

MIKTO_TEST(server_header_nginx_ubuntu) {
  auto out = parse_server_products("nginx/1.24.0 (Ubuntu)");
  CHECK(out.size() == 1);
  CHECK_EQ(out[0].product, std::string("nginx"));
  CHECK_EQ(out[0].version, std::string("1.24.0"));
  CHECK_EQ(out[0].os_clue, std::string("Ubuntu"));
}

MIKTO_TEST(server_header_iis_normalization) {
  auto out = parse_server_products("Microsoft-IIS/10.0");
  CHECK(out.size() == 1);
  CHECK_EQ(out[0].product, std::string("IIS"));
  CHECK_EQ(out[0].version, std::string("10.0"));
}

MIKTO_TEST(server_header_cdn_token_is_not_product) {
  auto out = parse_server_products("cloudflare");
  CHECK(out.empty());
}

MIKTO_TEST(server_header_empty) {
  CHECK(parse_server_products("").empty());
  CHECK(parse_server_products("   ").empty());
}

// прокси-ответы

MIKTO_TEST(proxy_response_squid_407) {
  std::string resp =
      "HTTP/1.1 407 Proxy Authentication Required\r\n"
      "Proxy-Authenticate: Basic realm=\"squid\"\r\n\r\n";
  CHECK(looks_like_proxy_response(resp));
}

MIKTO_TEST(proxy_response_via_header) {
  std::string resp =
      "HTTP/1.1 200 OK\r\nVia: 1.1 proxy.internal\r\nContent-Length: 0\r\n\r\n";
  CHECK(looks_like_proxy_response(resp));
}

MIKTO_TEST(proxy_response_squid_error) {
  std::string resp =
      "HTTP/1.1 503 Service Unavailable\r\nX-Squid-Error: ERR_CONNECT_FAIL 111\r\n\r\n";
  CHECK(looks_like_proxy_response(resp));
}

MIKTO_TEST(origin_response_is_not_proxy) {
  std::string resp =
      "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html\r\n\r\nhi";
  CHECK(!looks_like_proxy_response(resp));
  CHECK(!looks_like_proxy_response("not http at all"));
}

// honeypot

MIKTO_TEST(honeypot_signatures) {
  CHECK_EQ(std::string(honeypot_banner_hit("Welcome to Cowrie SSH honeypot")),
           "Cowrie");
  CHECK_EQ(std::string(honeypot_banner_hit("KIPPO sensor ready")), "Kippo");
  CHECK_EQ(std::string(honeypot_banner_hit("OpenCanary sshd")), "OpenCanary");
  CHECK_EQ(std::string(honeypot_banner_hit("SSH-2.0-OpenSSH_9.6p1")), "");
}

// синкхолы

MIKTO_TEST(sinkhole_grouping) {
  std::vector<std::pair<uint16_t, std::string>> sigs = {
      {80, "http:aaa"}, {8080, "http:aaa"}, {8000, "http:aaa"},
      {22, "banner:ssh"}, {443, "http:bbb"},
  };
  auto groups = sinkhole_groups(sigs, 3);
  CHECK(groups.size() == 1);
  CHECK(groups[0].size() == 3);
  std::vector<std::pair<uint16_t, std::string>> two = {
      {80, "x"}, {8080, "x"}, {443, "y"}, {8443, "y"}};
  CHECK(sinkhole_groups(two, 3).empty());
}

// блок-страницы

MIKTO_TEST(block_pages) {
  CHECK_EQ(std::string(classify_block_page(
               "<html>Attention Required! | Cloudflare</html>", 403)),
           "Cloudflare");
  CHECK_EQ(std::string(classify_block_page(
               "Request unsuccessful. Incapsula incident ID: 123", 403)),
           "Imperva/Incapsula");
  CHECK_EQ(std::string(classify_block_page(
               "<title>Sucuri WebSite Firewall - Access Denied</title>", 403)),
           "Sucuri");
  CHECK_EQ(std::string(classify_block_page("ModSecurity 406 body", 406)),
           "ModSecurity");
  // вендор-needle на 200 тоже считается
  CHECK_EQ(std::string(classify_block_page("cf-error-details page", 200)),
           "Cloudflare");
  CHECK_EQ(std::string(classify_block_page("<html>normal page</html>", 403)),
           "");
}

MIKTO_TEST(antibot_challenges) {
  CHECK_EQ(std::string(classify_antibot_challenge(
               "Just a moment... enable JavaScript and Cloudflare")),
           "Cloudflare");
  CHECK_EQ(std::string(classify_antibot_challenge(
               "challenge-platform/scripts/jsd/main.js")),
           "Cloudflare");
  CHECK_EQ(std::string(classify_antibot_challenge("px-captcha window")),
           "PerimeterX/HUMAN");
  CHECK_EQ(std::string(classify_antibot_challenge("<html>hello</html>")), "");
}

MIKTO_TEST(header_waf_hints) {
  std::vector<std::pair<std::string, std::string>> h1 = {
      {"Server", "cloudflare"}};
  CHECK_EQ(std::string(header_waf_hint(h1)), "Cloudflare");
  std::vector<std::pair<std::string, std::string>> h2 = {
      {"Set-Cookie", "__cf_bm=abc123; path=/"}};
  CHECK_EQ(std::string(header_waf_hint(h2)), "Cloudflare");
  std::vector<std::pair<std::string, std::string>> h3 = {
      {"X-Sucuri-ID", "15009"}};
  CHECK_EQ(std::string(header_waf_hint(h3)), "Sucuri");
  std::vector<std::pair<std::string, std::string>> h4 = {
      {"Server", "nginx/1.24.0"}};
  CHECK_EQ(std::string(header_waf_hint(h4)), "");
}

MIKTO_TEST(geo_block_bodies) {
  CHECK(looks_like_geo_block("Access from your country is blocked"));
  CHECK(looks_like_geo_block("This service is NOT AVAILABLE IN YOUR REGION."));
  CHECK(!looks_like_geo_block("Welcome to our shop"));
}

// лейблы уверенности

MIKTO_TEST(confidence_labels) {
  PortInfo p;
  p.confidence = 3;
  CHECK_EQ(std::string(p.confidence_label()), "confirmed");
  p.confidence = 2;
  CHECK_EQ(std::string(p.confidence_label()), "header");
  p.confidence = 1;
  CHECK_EQ(std::string(p.confidence_label()), "banner");
  p.confidence = 0;
  CHECK_EQ(std::string(p.confidence_label()), "guess");
}

MIKTO_TEST(ssh_banner_suspicious_versions) {
  // дефолтный баннер cowrie
  ServiceGuess g = detect_from_banner("SSH-2.0-OpenSSH_4.3", 2222);
  CHECK_EQ(g.product, std::string("OpenSSH"));
  CHECK_EQ(g.version, std::string("4.3"));
  ServiceGuess modern = detect_from_banner("SSH-2.0-OpenSSH_9.6p1", 22);
  CHECK_EQ(modern.product, std::string("OpenSSH"));
  CHECK_EQ(modern.version, std::string("9.6p1"));
  CHECK(modern.confidence == 3);
}

}  // namespace
