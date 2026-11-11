#include "mikto/http_client.hpp"

#include <curl/curl.h>

#include <memory>
#include <mutex>

#include "mikto/util.hpp"

namespace mikto {

namespace {

void curl_global_init_once() {
  static std::once_flag flag;
  std::call_once(flag, [] { curl_global_init(CURL_GLOBAL_DEFAULT); });
}

struct WriteCtx {
  std::string* body;
  long max_bytes;
  bool overflow = false;
};

// общий кэш соединений/dns/ssl-сессий: без него каждый запрос = новый
// tcp + tls рукопожатие, скан в разы медленнее и грубее к цели
struct ShareCtx {
  std::mutex mu[CURL_LOCK_DATA_LAST];
};

void share_lock(CURL*, curl_lock_data data, curl_lock_access, void* p) {
  static_cast<ShareCtx*>(p)->mu[data].lock();
}

void share_unlock(CURL*, curl_lock_data data, void* p) {
  static_cast<ShareCtx*>(p)->mu[data].unlock();
}

size_t write_cb(char* ptr, size_t size, size_t nmemb, void* userdata) {
  auto* ctx = static_cast<WriteCtx*>(userdata);
  size_t total = size * nmemb;
  if (static_cast<long>(ctx->body->size() + total) > ctx->max_bytes) {
    ctx->overflow = true;
    return 0;  // aborts the transfer
  }
  ctx->body->append(ptr, total);
  return total;
}

size_t header_cb(char* ptr, size_t size, size_t nmemb, void* userdata) {
  // с FOLLOWLOCATION колбэк видит хидеры каждого хопа, берём последний блок
  struct HeaderCtx {
    std::vector<std::pair<std::string, std::string>> current;
    std::vector<std::vector<std::pair<std::string, std::string>>> blocks;
  };
  auto* ctx = static_cast<HeaderCtx*>(userdata);
  std::string line(ptr, size * nmemb);
  while (!line.empty() && (line.back() == '\n' || line.back() == '\r'))
    line.pop_back();
  if (line.empty()) {
    if (!ctx->current.empty()) {
      ctx->blocks.push_back(std::move(ctx->current));
      ctx->current.clear();
    }
    return size * nmemb;
  }
  size_t pos = line.find(':');
  if (pos != std::string::npos) {
    std::string name = trim(line.substr(0, pos));
    std::string value = trim(line.substr(pos + 1));
    ctx->current.emplace_back(std::move(name), std::move(value));
  }
  return size * nmemb;
}

}  // namespace

HttpClient::HttpClient() {
  curl_global_init_once();
  CURLSH* sh = curl_share_init();
  if (sh) {
    auto* sctx = new ShareCtx();
    curl_share_setopt(sh, CURLSHOPT_SHARE, CURL_LOCK_DATA_CONNECT);
    curl_share_setopt(sh, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS);
    // переиспользование tls-сессий безопасно не во всех бэкендах libcurl
    // (gnutls/mbedtls/wolfssl ловили краши на конкурентном шаринге),
    // включаем только с openssl-семейством; keep-alive и так убирает
    // повторные рукопожатия, это лишь бонус на пересозданных соединениях
    const curl_version_info_data* vi = curl_version_info(CURLVERSION_NOW);
    if (vi && vi->ssl_version) {
      std::string ssl = to_lower(vi->ssl_version);
      if (ssl.find("openssl") != std::string::npos ||
          ssl.find("boringssl") != std::string::npos ||
          ssl.find("libressl") != std::string::npos)
        curl_share_setopt(sh, CURLSHOPT_SHARE, CURL_LOCK_DATA_SSL_SESSION);
    }
    curl_share_setopt(sh, CURLSHOPT_LOCKFUNC, share_lock);
    curl_share_setopt(sh, CURLSHOPT_UNLOCKFUNC, share_unlock);
    curl_share_setopt(sh, CURLSHOPT_USERDATA, sctx);
    share_ = sh;
    share_ctx_ = sctx;
  }
}

HttpClient::~HttpClient() {
  if (share_) curl_share_cleanup(static_cast<CURLSH*>(share_));
  delete static_cast<ShareCtx*>(share_ctx_);
}

std::string HttpResponse::header(const std::string& name) const {
  for (const auto& kv : headers)
    if (iequals(kv.first, name)) return kv.second;
  return "";
}

std::vector<std::string> HttpResponse::headers_all(
    const std::string& name) const {
  std::vector<std::string> out;
  for (const auto& kv : headers)
    if (iequals(kv.first, name)) out.push_back(kv.second);
  return out;
}

HttpResponse HttpClient::get(const std::string& url, const HttpOptions& opt) {
  curl_global_init_once();
  HttpResponse resp;

  CURL* e = curl_easy_init();
  if (!e) {
    resp.error = "curl init failed";
    return resp;
  }
  std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> guard(e,
                                                            &curl_easy_cleanup);
  // keep-alive: переиспользуем соединения из общего кэша
  if (share_) curl_easy_setopt(e, CURLOPT_SHARE, static_cast<CURLSH*>(share_));

  WriteCtx wctx{&resp.body, opt.max_body_bytes, false};
  // тот же HeaderCtx, что у колбэка
  struct HeaderCtx {
    std::vector<std::pair<std::string, std::string>> current;
    std::vector<std::vector<std::pair<std::string, std::string>>> blocks;
  };
  HeaderCtx hctx;
  char errbuf[CURL_ERROR_SIZE] = {0};

  curl_easy_setopt(e, CURLOPT_URL, url.c_str());
  curl_easy_setopt(e, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(e, CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(e, CURLOPT_MAXREDIRS, static_cast<long>(opt.max_redirects));
  curl_easy_setopt(e, CURLOPT_TIMEOUT_MS,
                   static_cast<long>(opt.timeout_s) * 1000L);
  curl_easy_setopt(e, CURLOPT_CONNECTTIMEOUT_MS,
                   static_cast<long>(opt.connect_timeout_ms));
#if LIBCURL_VERSION_NUM >= 0x075500
  curl_easy_setopt(e, CURLOPT_PROTOCOLS_STR, "http,https");
  curl_easy_setopt(e, CURLOPT_REDIR_PROTOCOLS_STR, "http,https");
#else
  curl_easy_setopt(e, CURLOPT_PROTOCOLS,
                   static_cast<long>(CURLPROTO_HTTP | CURLPROTO_HTTPS));
  curl_easy_setopt(e, CURLOPT_REDIR_PROTOCOLS,
                   static_cast<long>(CURLPROTO_HTTP | CURLPROTO_HTTPS));
#endif
  curl_easy_setopt(e, CURLOPT_USERAGENT,
                   opt.user_agent.empty() ? "mikto" : opt.user_agent.c_str());
  if (!opt.basic_auth.empty())
    curl_easy_setopt(e, CURLOPT_USERPWD, opt.basic_auth.c_str());
  curl_easy_setopt(e, CURLOPT_WRITEFUNCTION, write_cb);
  curl_easy_setopt(e, CURLOPT_WRITEDATA, &wctx);
  curl_easy_setopt(e, CURLOPT_HEADERFUNCTION, header_cb);
  curl_easy_setopt(e, CURLOPT_HEADERDATA, &hctx);
  curl_easy_setopt(e, CURLOPT_ERRORBUFFER, errbuf);
  curl_easy_setopt(e, CURLOPT_ACCEPT_ENCODING, "");
  curl_easy_setopt(e, CURLOPT_TCP_KEEPALIVE, 1L);

  CURLcode rc = curl_easy_perform(e);
  if (wctx.overflow) {
    resp.error = "response body exceeded size limit";
    return resp;
  }
  if (rc != CURLE_OK) {
    resp.error = errbuf[0] ? std::string(errbuf) : curl_easy_strerror(rc);
    return resp;
  }
  // хидеры только финального ответа
  if (!hctx.current.empty()) {
    hctx.blocks.push_back(std::move(hctx.current));
    hctx.current.clear();
  }
  if (!hctx.blocks.empty()) resp.headers = hctx.blocks.back();
  long code = 0;
  curl_easy_getinfo(e, CURLINFO_RESPONSE_CODE, &code);
  resp.status = code;
  char* eurl = nullptr;
  curl_easy_getinfo(e, CURLINFO_EFFECTIVE_URL, &eurl);
  if (eurl) resp.effective_url = eurl;
  double reqsz = 0, dlsz = 0, tot = 0;
  curl_easy_getinfo(e, CURLINFO_REQUEST_SIZE, &reqsz);
  curl_easy_getinfo(e, CURLINFO_SIZE_DOWNLOAD_T, &dlsz);
  curl_easy_getinfo(e, CURLINFO_TOTAL_TIME, &tot);
  resp.req_bytes = static_cast<size_t>(reqsz);
  resp.body_bytes = static_cast<size_t>(dlsz);
  resp.total_ms = tot * 1000.0;
  return resp;
}

}  // namespace mikto
