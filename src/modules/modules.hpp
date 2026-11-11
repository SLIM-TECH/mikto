#pragma once
// mikto — фабрика модулей и тестовые хелперы, не публичный api
#include <memory>
#include <string>
#include <vector>

#include "mikto/config.hpp"
#include "mikto/finding.hpp"
#include "mikto/module.hpp"

namespace mikto {

std::unique_ptr<IModule> make_assets_module();
std::unique_ptr<IModule> make_whois_module();
std::unique_ptr<IModule> make_ports_module();
std::unique_ptr<IModule> make_exposed_module();
std::unique_ptr<IModule> make_headers_module();
std::unique_ptr<IModule> make_cve_module();
std::unique_ptr<IModule> make_secrets_module();
std::unique_ptr<IModule> make_tech_module();
std::unique_ptr<IModule> make_webpaths_module();
std::unique_ptr<IModule> make_subdom_module();
std::unique_ptr<IModule> make_emails_module();
std::unique_ptr<IModule> make_emailsec_module();
std::unique_ptr<IModule> make_neighbors_module();
std::unique_ptr<IModule> make_infra_module();
std::unique_ptr<IModule> make_waf_module();

// детект сервисов по портам

struct ServiceGuess {
  std::string service;
  std::string product;
  std::string version;
  std::string os_clue;
  int confidence = 0;  // 0 догадка, 3 подтверждено
};

const char* expected_protocol_for_port(uint16_t port);

ServiceGuess detect_from_banner(const std::string& banner, uint16_t port);

std::vector<ServiceGuess> parse_server_products(const std::string& server);

bool looks_like_proxy_response(const std::string& http_response);

const char* honeypot_banner_hit(const std::string& banner);

std::vector<std::vector<uint16_t>> sinkhole_groups(
    const std::vector<std::pair<uint16_t, std::string>>& sigs,
    size_t min_members);

// waf хелперы

const char* classify_block_page(const std::string& body, long status);

const char* classify_antibot_challenge(const std::string& body);

const char* header_waf_hint(const std::vector<std::pair<std::string, std::string>>& headers);

bool looks_like_geo_block(const std::string& body);

// матчим токены атрибутов, не подстроки (value бывает со словом secure)
struct CookieFlags {
  bool secure = false;
  bool httponly = false;
  bool samesite = false;
};
CookieFlags parse_cookie_flags(const std::string& setcookie);

struct HeaderCheckInput {
  std::string url;
  std::string host;
  int port = 0;
  bool https = false;
};
std::vector<Finding> analyze_security_headers(const HeaderCheckInput& in,
                                              class WebResult& w);

void scan_body_for_secrets(const std::string& url, const std::string& body,
                           std::vector<Finding>& out);

// recon хелперы

std::vector<struct TechHit> detect_technologies(const class WebResult& w);

// базы по sql-ошибкам и открытым портам
std::vector<struct TechHit> detect_databases(const class WebResult& w,
                                             const std::vector<struct PortInfo>& ports);

std::string guess_os_from_banners(const std::vector<std::string>& clues);

const std::vector<std::string>& path_wordlist(bool deep);

// контент-дискавери

std::string url_host(const std::string& url);

bool same_site_host(const std::string& host, const std::string& urlhost);

std::vector<std::string> extract_page_paths(const std::string& body,
                                            const std::string& host);

std::vector<std::string> extract_path_words(const std::string& body);

std::vector<std::string> parse_robots_entries(const std::string& robots,
                                              const std::string& host);

std::vector<std::string> parse_sitemap_locs(const std::string& xml,
                                            const std::string& host);

std::vector<std::string> generate_discovery_candidates(
    const std::vector<std::string>& dirs, const std::vector<std::string>& words,
    const std::vector<std::string>& suffixes, size_t max_out);

const std::vector<std::string>& discovery_suffixes();

bool is_static_asset_path(const std::string& path);

Severity classify_path(const std::string& path, long status);
bool looks_like_soft_404(size_t baseline_len, size_t body_len);

void extract_hostnames(const std::string& text, const std::string& root_domain,
                       std::vector<std::string>& out);

void extract_emails(const std::string& body, const std::string& root_domain,
                    std::vector<std::string>& out);

void parse_cvelist_v5(const std::string& body, std::string& cvss,
                      std::string& severity, std::string& description);

// emailsec хелперы

struct SpfPolicy {
  bool valid = false;
  std::string all_policy;   // fail/softfail/neutral/allow_all/missing
  int lookup_count = 0;     // rfc 7208 позволяет максимум 10
  bool private_ip4 = false;
  std::vector<std::string> includes;
};
SpfPolicy evaluate_spf(const std::string& record);

struct DmarcPolicy {
  bool valid = false;
  std::string p;       // none/quarantine/reject или пусто
  std::string sp;
  int pct = 100;
  bool has_rua = false;
};
DmarcPolicy evaluate_dmarc(const std::string& record);

const std::vector<std::string>& dkim_selectors();

// censys api (если есть ключ)

struct CensysService {
  int port = 0;
  std::string transport;
  std::string service_name;
  std::vector<std::string> software;
  std::vector<std::string> cpes;
};

struct CensysHost {
  bool ok = false;
  std::vector<CensysService> services;
  std::vector<std::string> labels;
  std::string asn;
  std::string asn_desc;
  std::string country;
  std::string city;
  std::string rdns;
};

// парс ответа censys, не бросает исключений
void parse_censys_host(const std::string& body, CensysHost& out);

}  // namespace mikto
