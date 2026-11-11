// tls зонд на openssl: сертификат и протокол
#include "mikto/tls.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <poll.h>

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <memory>

#include "mikto/net.hpp"

namespace mikto {

namespace {

struct SslDel {
  void operator()(SSL* s) const { SSL_free(s); }
};
struct CtxDel {
  void operator()(SSL_CTX* c) const { SSL_CTX_free(c); }
};
struct X509Del {
  void operator()(X509* x) const { X509_free(x); }
};

bool handshake(SSL* ssl, int fd, int timeout_ms, std::string& err) {
  auto deadline =
      std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
  while (true) {
    int rc = SSL_connect(ssl);
    if (rc == 1) return true;
    int serr = SSL_get_error(ssl, rc);
    if (serr == SSL_ERROR_WANT_READ || serr == SSL_ERROR_WANT_WRITE) {
      auto now = std::chrono::steady_clock::now();
      if (now >= deadline) {
        err = "TLS handshake timeout";
        return false;
      }
      int remain = static_cast<int>(
          std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now)
              .count());
      pollfd p{};
      p.fd = fd;
      p.events = (serr == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT;
      int pr = ::poll(&p, 1, remain);
      if (pr < 0 && errno == EINTR) continue;
      if (pr <= 0) {
        err = "TLS handshake timeout";
        return false;
      }
      continue;
    }
    unsigned long e = ERR_get_error();
    char buf[256] = {0};
    if (e) ERR_error_string_n(e, buf, sizeof buf);
    err = "TLS handshake failed: " + std::string(buf[0] ? buf : "unknown error");
    return false;
  }
}

}  // namespace

TlsInfo tls_probe(const std::string& host, uint16_t port, int timeout_ms) {
  TlsInfo info;
  std::string err;
  UniqueFd fd = tcp_connect(host, port, timeout_ms, err);
  if (!fd.valid()) {
    info.error = err;
    return info;
  }

  SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
  if (!ctx) {
    info.error = "SSL_CTX_new failed";
    return info;
  }
  std::unique_ptr<SSL_CTX, CtxDel> ctxg(ctx);
  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

  SSL* ssl = SSL_new(ctx);
  if (!ssl) {
    info.error = "SSL_new failed";
    return info;
  }
  std::unique_ptr<SSL, SslDel> sslg(ssl);
  SSL_set_fd(ssl, fd.get());
  SSL_set_tlsext_host_name(ssl, host.c_str());

  if (!handshake(ssl, fd.get(), timeout_ms, info.error)) return info;

  info.ok = true;
  info.protocol = SSL_get_version(ssl);
  const SSL_CIPHER* c = SSL_get_current_cipher(ssl);
  if (c) info.cipher = SSL_CIPHER_get_name(c);

  X509* cert = SSL_get1_peer_certificate(ssl);
  if (!cert) {
    info.error = "no peer certificate presented";
    return info;
  }
  std::unique_ptr<X509, X509Del> certg(cert);

  char cn[256] = {0};
  X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, cn,
                            sizeof cn);
  info.subject = std::string("CN=") + cn;
  char icn[256] = {0};
  X509_NAME_get_text_by_NID(X509_get_issuer_name(cert), NID_commonName, icn,
                            sizeof icn);
  info.issuer = std::string("CN=") + icn;
  info.self_signed = (info.subject == info.issuer);

  GENERAL_NAMES* names = static_cast<GENERAL_NAMES*>(
      X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));
  if (names) {
    int n = sk_GENERAL_NAME_num(names);
    for (int i = 0; i < n && info.san_dns.size() < 64; ++i) {
      GENERAL_NAME* gn = sk_GENERAL_NAME_value(names, i);
      if (gn && gn->type == GEN_DNS && gn->d.dNSName) {
        unsigned char* s = nullptr;
        int len = ASN1_STRING_to_UTF8(&s, gn->d.dNSName);
        if (len > 0 && s) {
          info.san_dns.emplace_back(reinterpret_cast<char*>(s),
                                    reinterpret_cast<char*>(s) + len);
          OPENSSL_free(s);
        }
      }
    }
    GENERAL_NAMES_free(names);
  }

  ASN1_TIME* na = X509_getm_notAfter(cert);
  tm tmv{};
  if (na && ASN1_TIME_to_tm(na, &tmv)) {
    char buf[32];
    std::snprintf(buf, sizeof buf, "%04d-%02d-%02d", tmv.tm_year + 1900,
                  tmv.tm_mon + 1, tmv.tm_mday);
    info.not_after = buf;
    time_t exp = timegm(&tmv);
    time_t now = time(nullptr);
    info.days_until_expiry = static_cast<int>((exp - now) / 86400);
  }
  return info;
}

}  // namespace mikto
