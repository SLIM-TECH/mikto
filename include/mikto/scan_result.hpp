#pragma once
// mikto — состояние скана, общее для модулей и репортеров
#include <algorithm>
#include <deque>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "finding.hpp"
#include "intel_graph.hpp"
#include "providers.hpp"
#include "target.hpp"
#include "tls.hpp"

namespace mikto {

// то, что отправили и что вернулось, для --trace
struct TrafficEvent {
  std::string module;   // "assets", "tech", "ports", ...
  std::string kind;     // "http", "dns", "tcp", "tls", "whois"
  std::string target;   // URL, "host:port", or DNS qname
  std::string request;  // one-line summary of what was sent
  std::string response; // one-line summary of what came back
  long status = 0;      // HTTP status / DNS RCODE-as-int when applicable
  size_t sent = 0;      // bytes sent
  size_t recv = 0;      // bytes received
  double ms = 0.0;      // round-trip time
};

// один dns-рекорд зоны
struct DnsRecord {
  std::string type;     // "A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "CAA", "PTR"
  std::string name;     // owner name
  std::string value;    // rdata, human-readable
  uint32_t ttl = 0;
};

// без ключей
struct GeoInfo {
  bool ok = false;
  std::string country, region, city;
  double lat = 0.0, lon = 0.0;
  std::string asn;      // "AS13335"
  std::string org;      // "Cloudflare, Inc."
};

struct WhoisInfo {
  bool ok = false;
  std::string registrar;
  std::string created, updated, expires;
  std::vector<std::string> emails;
  std::vector<std::string> nameservers;
};

struct PortInfo {
  uint16_t port = 0;
  std::string service;   // "https", "ssh", "redis", "unknown"
  std::string product;   // "nginx", "OpenSSH"
  std::string version;   // "1.25.3", "9.6p1"
  std::string banner;    // short raw banner (evidence)
  bool open = false;

  std::string probe;    // что реально увидели: "ssh", "http", "mysql"...
  int confidence = 0;   // 0 угадано, 1 баннер, 2 заголовок, 3 подтверждено
  std::string os_clue;  // "(Ubuntu)", "Debian" из баннера/заголовка
  // вторые пары продукт/версия из того же баннера
  std::vector<std::pair<std::string, std::string>> extra_versions;

  std::string service_label() const;       // "nginx 1.25.3" / "redis"
  const char* confidence_label() const;    // "guess"/"banner"/"header"/"confirmed"
};

struct TechHit {
  std::string name;     // "WordPress", "PHP", "jQuery"
  std::string version;  // "6.4.2", may be empty
  std::string source;   // "header:X-Powered-By", "body:wp-content"
};

struct PathHit {
  std::string path;   // "/admin", "/api/lol/admin"
  long status = 0;    // final HTTP status after redirects
  size_t size = 0;    // body bytes (approx)
  // wordlist | link | js | robots | sitemap | combo
  std::string source;
};

struct HostResult {
  std::string host;
  bool is_ip = false;
  std::vector<std::string> ips;
  std::vector<PortInfo> ports;
  std::optional<TlsInfo> tls;

  std::string os_guess;                 // "Linux (Ubuntu)", "Windows", ...
  std::vector<TechHit> tech;
  std::vector<PathHit> paths;
  std::vector<std::string> subdomains;  // только резолвящиеся, пассивно
  bool wildcard_dns = false;
  std::vector<std::string> emails;
  std::vector<std::string> neighbors;   // co-hosted на том же ip
  std::vector<std::string> infra_tags;  // shodan internetdb
  std::vector<std::string> shodan_cpes; // сырые CPE из shodan

  std::vector<DnsRecord> dns_records;
  bool dns_zone_transfer = false;       // AXFR прошёл (deep)
  GeoInfo geo;
  WhoisInfo whois;
  std::vector<std::string> reputation;  // "URLhaus: listed (malware URL)"

  // сколько скан реально увидел: full / degraded / blocked, пусто если
  // ничего не грузили (waf и лимиты портят картину)
  std::string scan_visibility;
  std::vector<std::string> visibility_notes;   // причины, человекочитаемо

  PortInfo* port(uint16_t p);
  const PortInfo* port(uint16_t p) const;
};

struct WebResult {
  std::string url;
  long status = 0;
  std::string server;
  std::string title;
  std::vector<std::pair<std::string, std::string>> headers;
  std::string body;  // обрезанная копия под сканирование секретов
  bool fetched = false;
  std::string error;

  std::string header(const std::string& name) const;
  std::vector<std::string> headers_all(const std::string& name) const;
};

struct ScanResult {
  std::string started_at;
  std::string finished_at;
  double duration_s = 0.0;
  bool deep = false;
  bool safe_mode = true;

  std::vector<Target> targets;
  // deque, а не vector: ensure_host/ensure_web зовут и из воркеров пула,
  // push_back у deque не инвалидирует ссылки на элементы — чужие
  // HostResult&/WebResult& не становятся висячими при росте контейнера
  std::deque<HostResult> hosts;
  std::deque<WebResult> web;
  std::vector<Finding> findings;
  std::vector<std::string> modules_run;
  std::map<std::string, double> module_timings;

  // здоровье внешних провайдеров за скан
  std::map<std::string, ProviderStat> provider_stats;

  // граф собирается в конце скана из всего, что выше
  IntelGraph intel;

  // лог сети (--trace); пишут воркеры из любых потоков
  std::vector<TrafficEvent> traffic;
  void record_trace(TrafficEvent ev);
  std::vector<TrafficEvent> traffic_snapshot() const;
  std::map<std::string, int> trace_counts() const;  // по kind
  // выше капа события считаем, не молчим, репортер скажет "показано N из M"
  size_t trace_dropped_count() const;
  // дубликаты давит add_finding, выжившие несут их локации в evidence
  size_t suppressed_duplicates_count() const;

  HostResult& ensure_host(const std::string& host, bool is_ip);
  WebResult& ensure_web(const std::string& url);
  void add_finding(Finding f);
  void sort_findings();  // по тяжести, потом модуль/хост
  std::map<Severity, int> counts() const;

  const HostResult* find_host(const std::string& host) const;

 private:
  mutable std::mutex trace_mu_;
  size_t trace_dropped_ = 0;  // под trace_mu_
  size_t suppressed_duplicates_ = 0;
  // hosts/web/findings пишут и воркеры (ensure_*/add_finding) — под st_mu_
  mutable std::mutex st_mu_;
};

}  // namespace mikto
