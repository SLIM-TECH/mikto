// тесты osint: dns, whois, geo, фиды
#include "test_fw.hpp"

#include <cstring>
#include <string>
#include <vector>

#include "mikto/dns.hpp"
#include "mikto/osint.hpp"
#include "mikto/scan_result.hpp"
#include "modules/modules.hpp"   // парсер censys

using namespace mikto;

// dns wire

MIKTO_TEST(dns_encode_name_roundtrip) {
  bool ok = false;
  std::string wire = dns_encode_name("WwW.Example.COM", ok);
  CHECK(ok);
  CHECK_EQ(wire.size(), size_t{17});  // 3 www 7 example 3 com 0
  size_t off = 0;
  std::string name = dns_decode_name(
      reinterpret_cast<const uint8_t*>(wire.data()), wire.size(), off);
  CHECK_EQ(name, std::string("www.example.com"));
  CHECK_EQ(off, wire.size());
}

MIKTO_TEST(dns_encode_name_rejects_bad_labels) {
  bool ok = true;
  dns_encode_name("", ok);
  CHECK(!ok);
  ok = true;
  dns_encode_name(std::string(64, 'a') + ".example.com", ok);
  CHECK(!ok);
}

MIKTO_TEST(dns_decode_name_compression_pointer) {
  // ответ указывает на qname через pointer 0x0c.
  // хекс-эскейпы отдельными литералами: "\x07example" съест 'e' как hex-цифру
  std::string qname_bytes = std::string("\x03") + "www" + std::string("\x07") +
                            "example" + std::string("\x03") + "com" +
                            std::string("\x00", 1);
  CHECK_EQ(qname_bytes.size(), size_t{17});
  std::string pkt = std::string(12, '\0') + qname_bytes;
  pkt += std::string("\xc0\x0c", 2);
  size_t off = 12 + qname_bytes.size();
  std::string name = dns_decode_name(
      reinterpret_cast<const uint8_t*>(pkt.data()), pkt.size(), off);
  CHECK_EQ(name, std::string("www.example.com"));
  CHECK_EQ(off, size_t{12 + qname_bytes.size() + 2});
}

MIKTO_TEST(dns_type_name_mapping) {
  CHECK_EQ(dns_type_name(kDnsA), std::string("A"));
  CHECK_EQ(dns_type_name(kDnsAAAA), std::string("AAAA"));
  CHECK_EQ(dns_type_name(kDnsMX), std::string("MX"));
  CHECK_EQ(dns_type_name(kDnsCAA), std::string("CAA"));
  CHECK_EQ(dns_type_name(kDnsAXFR), std::string("AXFR"));
  CHECK_EQ(dns_type_name(999), std::string("TYPE999"));
}

MIKTO_TEST(dns_parse_response_answers) {
  std::vector<uint8_t> m;
  auto u16 = [&](uint16_t v) { m.push_back(v >> 8); m.push_back(v & 0xff); };
  auto u32 = [&](uint32_t v) {
    m.push_back(v >> 24); m.push_back((v >> 16) & 0xff);
    m.push_back((v >> 8) & 0xff); m.push_back(v & 0xff);
  };
  u16(0x1234);
  u16(0x8180);        // flags: QR RD RA
  u16(1);             // qdcount
  u16(1);             // ancount
  u16(0); u16(0);     // nscount, arcount
  // question: www.x.io A IN
  m.push_back(3); for (char c : std::string("www")) m.push_back(c);
  m.push_back(1); m.push_back('x');
  m.push_back(2); for (char c : std::string("io")) m.push_back(c);
  m.push_back(0);
  u16(1); u16(1);
  // answer: pointer to offset 12, A, IN, ttl 300, rdlen 4, 10.1.2.3
  u16(0xc00c); u16(1); u16(1); u32(300); u16(4);
  m.push_back(10); m.push_back(1); m.push_back(2); m.push_back(3);

  auto recs = dns_parse_response(m.data(), m.size());
  CHECK_EQ(recs.size(), size_t{1});
  if (recs.size() == 1) {
    CHECK_EQ(recs[0].type, std::string("A"));
    CHECK_EQ(recs[0].name, std::string("www.x.io"));
    CHECK_EQ(recs[0].value, std::string("10.1.2.3"));
    CHECK_EQ(recs[0].ttl, uint32_t{300});
  }
}

// whois

MIKTO_TEST(whois_parse_com_response) {
  const std::string raw =
      "Domain Name: EXAMPLE.COM\r\n"
      "Registry Domain ID: 2336799_DOMAIN_COM-VRSN\r\n"
      "Registrar WHOIS Server: whois.iana.org\r\n"
      "Registrar: RESERVED-Internet Assigned Numbers Authority\r\n"
      "Updated Date: 2024-08-14T07:01:31Z\r\n"
      "Creation Date: 1995-08-14T04:00:00Z\r\n"
      "Registry Expiry Date: 2025-08-13T04:00:00Z\r\n"
      "Name Server: A.IANA-SERVERS.ORG\r\n"
      "Name Server: B.IANA-SERVERS.ORG\r\n"
      "Registrant Organization: Internet Assigned Numbers Authority\r\n"
      "Registrant Email: registrant@example.com\r\n"
      "Abuse Contact Email: abuse@iana.org\r\n";
  WhoisInfo info;
  parse_whois_response(raw, info);
  CHECK(info.ok);
  CHECK(info.registrar.find("Internet Assigned") != std::string::npos);
  CHECK_EQ(info.created, std::string("1995-08-14T04:00:00Z"));
  CHECK_EQ(info.expires, std::string("2025-08-13T04:00:00Z"));
  CHECK_EQ(info.nameservers.size(), size_t{2});
  bool has_abuse = false, has_reg = false;
  for (const auto& e : info.emails) {
    if (e == "abuse@iana.org") has_abuse = true;
    if (e == "registrant@example.com") has_reg = true;
  }
  CHECK(has_abuse);
  CHECK(has_reg);
}

MIKTO_TEST(whois_parse_garbage_is_not_ok) {
  WhoisInfo info;
  parse_whois_response("Your connection limit exceeded. Please try later.",
                       info);
  CHECK(!info.ok);
}

// geo

MIKTO_TEST(geo_parse_ipwho_is_shape) {
  const std::string body = R"({"ip":"1.2.3.4","success":true,"type":"IPv4",)"
                           R"("country":"Germany","region":"Berlin",)"
                           R"("city":"Berlin","latitude":52.52,"longitude":13.4,)"
                           R"("connection":{"asn":24940,"org":"Hetzner Online GmbH"}})";
  GeoInfo g;
  parse_geo_response(body, g);
  CHECK(g.ok);
  CHECK_EQ(g.country, std::string("Germany"));
  CHECK_EQ(g.city, std::string("Berlin"));
  CHECK_EQ(g.asn, std::string("AS24940"));
  CHECK(g.org.find("Hetzner") != std::string::npos);
  CHECK(g.lat > 52.0 && g.lat < 53.0);
}

MIKTO_TEST(geo_parse_ipapi_shape) {
  const std::string body =
      R"({"status":"success","country":"Netherlands","regionName":"North Holland",)"
      R"("city":"Amsterdam","lat":52.37,"lon":4.9,"as":"AS60781 LeaseWeb",)"
      R"("org":"LeaseWeb Netherlands"})";
  GeoInfo g;
  parse_geo_response(body, g);
  CHECK(g.ok);
  CHECK_EQ(g.country, std::string("Netherlands"));
  CHECK_EQ(g.region, std::string("North Holland"));
  CHECK_EQ(g.asn, std::string("AS60781"));
  CHECK(g.org.find("LeaseWeb") != std::string::npos);
}

MIKTO_TEST(geo_parse_failure_is_not_ok) {
  GeoInfo g;
  parse_geo_response(R"({"success":false,"message":"reserved range"})", g);
  CHECK(!g.ok);
  GeoInfo g2;
  parse_geo_response(R"({"status":"fail","message":"private range"})", g2);
  CHECK(!g2.ok);
}

// exploit-db

MIKTO_TEST(extract_cve_ids_basic) {
  auto ids = extract_cve_ids(
      "WordPress Core < 5.8.3 - SQL Injection CVE-2022-21661 and cve-2022-21663");
  CHECK_EQ(ids.size(), size_t{2});
  CHECK_EQ(ids[0], std::string("CVE-2022-21661"));
  CHECK_EQ(ids[1], std::string("CVE-2022-21663"));
}

MIKTO_TEST(extract_cve_ids_empty_and_partial) {
  CHECK(extract_cve_ids("nothing here").empty());
  CHECK(extract_cve_ids("CVE-202-1234 (bad year)").empty());
  auto one = extract_cve_ids("log4shell CVE-2021-44228!");
  CHECK_EQ(one.size(), size_t{1});
}

MIKTO_TEST(exploitdb_csv_parse) {
  const std::string csv =
      "id,file,description,date_published,author,type,platform,date_verified\n"
      "50583,php/webapps/50583.txt,\"WordPress Core 5.8.2 - SQL Injection (CVE-2022-21661)\","
      "2022-01-06,Metaintel,webapps,multiple,2022-01-07\n"
      "50584,linux/remote/50584.py,\"OpenSSL 1.0.1f - Heartbleed (CVE-2014-0160)\","
      "2022-01-08,someone,remote,linux,2022-01-09\n"
      "50585,webapps/50585.txt,\"No CVE mentioned here\",2022-01-09,x,webapps,php,2022-01-10\n";
  std::map<std::string, std::vector<EdbEntry>> idx;
  parse_exploitdb_csv(csv, idx);
  CHECK_EQ(idx.size(), size_t{2});
  CHECK_EQ(idx["CVE-2022-21661"].size(), size_t{1});
  CHECK_EQ(idx["CVE-2022-21661"][0].id, std::string("50583"));
  CHECK_EQ(idx["CVE-2014-0160"][0].type, std::string("remote"));
}

// фишинг-фиды

MIKTO_TEST(openphish_parse_and_check) {
  const std::string feed_text =
      "# OpenPhish community feed\n"
      "https://www.ucsg365.vercel.app/\n"
      "https://evil.example.com:8443/login/verify\n"
      "http://user@phish.example.org/steal\n"
      "not-a-url\n";
  std::vector<PhishEntry> feed;
  parse_openphish_feed(feed_text, feed);
  CHECK_EQ(feed.size(), size_t{3});
  CHECK_EQ(feed[0].host, std::string("www.ucsg365.vercel.app"));
  CHECK_EQ(feed[1].host, std::string("evil.example.com"));
  CHECK_EQ(feed[2].host, std::string("phish.example.org"));  // userinfo dropped

  auto hits = openphish_check(feed, "evil.example.com");
  CHECK_EQ(hits.size(), size_t{1});
  CHECK(hits[0].url.find("/login/verify") != std::string::npos);
  CHECK(openphish_check(feed, "clean.example.org").empty());
}

MIKTO_TEST(feodo_parse_and_check) {
  const std::string blocklist =
      "# abuse.ch Feodo Tracker Botnet C2 IP Blocklist (recommended)  #\n"
      "# Last updated: 2026-03-04 14:28:39 UTC                        #\n"
      "50.16.16.211\n"
      "185.220.101.5\n"
      "not-an-ip\n"
      "\n";
  std::vector<std::string> ips;
  parse_feodo_blocklist(blocklist, ips);
  CHECK_EQ(ips.size(), size_t{2});
  CHECK_EQ(ips[0], std::string("50.16.16.211"));

  CHECK(feodo_check(ips, {"203.0.113.1", "50.16.16.211"}));
  CHECK(!feodo_check(ips, {"203.0.113.1"}));
  CHECK(!feodo_check(ips, {}));
}

// censys

MIKTO_TEST(censys_host_parse_full) {
  const std::string body = R"({
    "code": 200,
    "data": {
      "result": {
        "ip": "203.0.113.10",
        "services": [
          {
            "transport_protocol": "TCP",
            "extended_service_name": "HTTP",
            "service_name": "HTTP",
            "port": 443,
            "software": [
              {"vendor": "nginx", "product": "nginx", "version": "1.18.0",
               "uniform_resource_identifier": "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"},
              {"vendor": "PHP Group", "product": "PHP", "version": "7.4.3"}
            ]
          },
          {"transport_protocol": "TCP", "service_name": "SSH",
           "port": 22,
           "software": [{"vendor": "OpenBSD", "product": "OpenSSH",
                         "version": "8.9p1"}]}
        ],
        "labels": ["web", "datacenter"],
        "autonomous_system": {"asn": 64512, "description": "EXAMPLE-AS"},
        "location": {"country": "United States", "city": "Ashburn"},
        "dns": {"reverse_dns": {"names": ["host.example.com"]}}
      }
    }
  })";
  CensysHost ch;
  parse_censys_host(body, ch);
  CHECK(ch.ok);
  CHECK_EQ(ch.services.size(), size_t{2});
  CHECK_EQ(ch.services[0].port, 443);
  CHECK_EQ(ch.services[0].service_name, std::string("HTTP"));
  CHECK_EQ(ch.services[0].cpes.size(), size_t{1});
  CHECK(ch.services[0].cpes[0].find("cpe:2.3:a:nginx:nginx:1.18.0") == 0);
  CHECK_EQ(ch.services[0].software.size(), size_t{2});
  CHECK_EQ(ch.services[0].software[0], std::string("nginx/nginx 1.18.0"));
  CHECK_EQ(ch.services[1].port, 22);
  CHECK_EQ(ch.labels.size(), size_t{2});
  CHECK_EQ(ch.labels[0], std::string("web"));
  CHECK_EQ(ch.asn, std::string("AS64512"));
  CHECK_EQ(ch.asn_desc, std::string("EXAMPLE-AS"));
  CHECK_EQ(ch.country, std::string("United States"));
  CHECK_EQ(ch.city, std::string("Ashburn"));
  CHECK_EQ(ch.rdns, std::string("host.example.com"));
}

MIKTO_TEST(censys_host_parse_malformed_and_minimal) {
  CensysHost ch;
  parse_censys_host("", ch);
  CHECK(!ch.ok);
  parse_censys_host("not json at all", ch);
  CHECK(!ch.ok);
  parse_censys_host("{}", ch);  // negative-cache shape
  CHECK(!ch.ok);
  parse_censys_host(R"({"code":200,"data":{}})", ch);
  CHECK(!ch.ok);  // result object missing
  parse_censys_host(R"({"code":200,"data":{"result":{"ip":"1.2.3.4"}}})",
                    ch);
  CHECK(ch.ok);  // минимальный результат парсится
  CHECK(ch.services.empty());
  CHECK(ch.labels.empty());
  CHECK(ch.asn.empty());
}

// trace

MIKTO_TEST(traffic_event_record_and_snapshot) {
  ScanResult r;
  TrafficEvent ev;
  ev.module = "tech";
  ev.kind = "http";
  ev.target = "http://example.com/";
  ev.request = "GET http://example.com/";
  ev.response = "HTTP 200";
  ev.status = 200;
  ev.sent = 100;
  ev.recv = 4200;
  ev.ms = 42.5;
  r.record_trace(ev);
  r.record_trace(ev);
  auto snap = r.traffic_snapshot();
  CHECK_EQ(snap.size(), size_t{2});
  auto counts = r.trace_counts();
  CHECK_EQ(counts["http"], 2);
}
