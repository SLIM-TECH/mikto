#pragma once
// mikto — dns клиент rfc1035
#include <cstdint>
#include <string>
#include <vector>

#include "mikto/scan_result.hpp"  // DnsRecord

namespace mikto {

constexpr uint16_t kDnsA = 1, kDnsNS = 2, kDnsCNAME = 5, kDnsSOA = 6,
                   kDnsPTR = 12, kDnsMX = 15, kDnsTXT = 16, kDnsAAAA = 28,
                   kDnsDNSKEY = 48, kDnsCAA = 257, kDnsAXFR = 252;

std::string dns_type_name(uint16_t type);

// первые 3 из resolv.conf, плюс публичные
std::vector<std::string> dns_resolvers();

// пусто = nxdomain или нет ответов, транспортная ошибка в err
std::vector<DnsRecord> dns_query(const std::string& qname, uint16_t qtype,
                                 int timeout_ms, int& rcode, std::string& err);

// до 8 адресов, false если пусто
bool dns_resolve(const std::string& name, std::vector<std::string>& ips,
                 int timeout_ms = 2000);

std::string dns_reverse(const std::string& ip, int timeout_ms = 2000);

// отказы отдельных типов пропускаем, err = последняя транспортная
std::vector<DnsRecord> dns_all_records(const std::string& name,
                                       int timeout_ms = 2000,
                                       std::string* err = nullptr);

// true = зона реально передана; отказ сервера это норма, не ошибка
bool dns_axfr(const std::string& zone, const std::string& ns_host,
              std::vector<std::string>& records, int timeout_ms = 4000);

// ---- чистые парсеры, под юнит-тесты ----

std::string dns_encode_name(const std::string& qname, bool& ok);

// двигает off, "" на битом входе, max_jumps против петель
std::string dns_decode_name(const uint8_t* buf, size_t len, size_t& off,
                            int max_jumps = 32);

// только answers
std::vector<DnsRecord> dns_parse_response(const uint8_t* buf, size_t len);

// нужен и парсеру AXFR
std::string dns_format_rdata(const uint8_t* msg, size_t len, size_t rdoff,
                             size_t rdlen, uint16_t type);

}  // namespace mikto
