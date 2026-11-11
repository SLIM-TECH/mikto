#pragma once
// mikto — tls зонд на openssl, верификацию не проверяем: мы наблюдаем
#include <cstdint>
#include <string>
#include <vector>

namespace mikto {

struct TlsInfo {
  bool ok = false;
  std::string error;
  std::string protocol;   // e.g. "TLSv1.3"
  std::string cipher;
  std::string subject;    // CN=..., O=...
  std::string issuer;
  std::vector<std::string> san_dns;
  std::string not_after;  // "YYYY-MM-DD"
  int days_until_expiry = 0;
  bool self_signed = false;
};

TlsInfo tls_probe(const std::string& host, uint16_t port, int timeout_ms);

}  // namespace mikto
