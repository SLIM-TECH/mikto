#pragma once
// mikto — osint без ключей; urlhaus feed умер (410), юзаем openphish и feodo
#include <map>
#include <string>
#include <vector>

#include "mikto/scan_result.hpp"  // GeoInfo, WhoisInfo

namespace mikto {

// ---- whois ----

void parse_whois_response(const std::string& text, WhoisInfo& info);

// rdap как https-фолбэк, когда порт 43 не дал толку
void parse_rdap_response(const std::string& body, WhoisInfo& info);

// iana -> registrar, fd на вызов
WhoisInfo whois_lookup(const std::string& domain, int timeout_ms = 5000,
                       std::string* err = nullptr);

// ---- геолокация ----

// ест оба формата: ipwho.is и ip-api
void parse_geo_response(const std::string& body, GeoInfo& geo);

// кэш 24h, ok=false когда пусто
GeoInfo geo_lookup(const std::string& ip, const std::string& cache_dir,
                   int timeout_s = 8, std::string* err = nullptr);

// ---- exploit-db ----

struct EdbEntry {
  std::string id;          // "51234"
  std::string file;        // exploit path
  std::string description; // title
  std::string type;        // "remote", "webapps", ...
  std::string platform;
  std::string date;
};

// Extracts all CVE ids mentioned in free text ("CVE-2021-44228", ...).
std::vector<std::string> extract_cve_ids(const std::string& text);

// files_exploits.csv -> cve -> эксплойты
void parse_exploitdb_csv(const std::string& csv,
                         std::map<std::string, std::vector<EdbEntry>>& out);

// кэш 24h
bool load_exploit_index(
    const std::string& cache_dir,
    std::map<std::string, std::vector<EdbEntry>>& index, std::string& err);

// ---- openphish ----

struct PhishEntry {
  std::string url;
  std::string host;
};

void parse_openphish_feed(const std::string& text,
                          std::vector<PhishEntry>& out);

// кэш 6h
bool load_openphish_feed(const std::string& cache_dir,
                         std::vector<PhishEntry>& feed, std::string& err);

// только точное совпадение хоста
std::vector<PhishEntry> openphish_check(const std::vector<PhishEntry>& feed,
                                        const std::string& host);

// ---- feodo (abuse.ch) ----

// ip на строку, # пропускаем
void parse_feodo_blocklist(const std::string& text,
                           std::vector<std::string>& out);

// кэш 1h
bool load_feodo_feed(const std::string& cache_dir,
                     std::vector<std::string>& ips, std::string& err);

bool feodo_check(const std::vector<std::string>& blocklist,
                 const std::vector<std::string>& ips);

}  // namespace mikto
