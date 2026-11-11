#pragma once
// mikto — get на libcurl, tls-проверка включена
#include <string>
#include <utility>
#include <vector>

namespace mikto {

struct HttpOptions {
  int timeout_s = 10;
  int max_redirects = 3;
  std::string user_agent;
  long max_body_bytes = 2 * 1024 * 1024;  // жёсткий кап, огромные страницы не тащим
  std::string basic_auth;  // "user:password", basic auth
  int connect_timeout_ms = 5000;  // только фаза коннекта
};

struct HttpResponse {
  long status = 0;
  std::string effective_url;
  std::string body;
  std::string error;  // transport-level error; empty = transport OK
  std::vector<std::pair<std::string, std::string>> headers;  // original order
  size_t req_bytes = 0;     // total request bytes (libcurl accounting)
  size_t body_bytes = 0;    // downloaded body bytes
  double total_ms = 0.0;    // full transfer wall time

  bool ok_network() const { return error.empty() && status > 0; }
  // без учета регистра, первый матч
  std::string header(const std::string& name) const;
  std::vector<std::string> headers_all(const std::string& name) const;
};

class HttpClient {
 public:
  HttpClient();
  ~HttpClient();
  HttpClient(const HttpClient&) = delete;
  HttpClient& operator=(const HttpClient&) = delete;

  HttpResponse get(const std::string& url, const HttpOptions& opt = {});

 private:
  // CURLSH (connection/dns/ssl-session кэш), спрятан за void*,
  // чтобы curl-заголовки не лезли в каждый модуль
  void* share_ = nullptr;
  void* share_ctx_ = nullptr;  // мьютексы для lock-колбэков
};

}  // namespace mikto
