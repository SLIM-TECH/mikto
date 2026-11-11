// mikto — tcp скан + лестница проб, ловим honeypot/прокси/sinkhole обман
#include "modules.hpp"

#include <atomic>
#include <cctype>
#include <cstring>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <thread>
#include <vector>

#include "mikto/net.hpp"
#include "mikto/rate_limiter.hpp"
#include "mikto/scan_result.hpp"
#include "mikto/tls.hpp"
#include "mikto/util.hpp"
#include "mikto/version.hpp"
#include "mikto/win_compat.hpp"

namespace mikto {

namespace {
const char* service_by_port(uint16_t port);  // определение ниже
}

// тестовые хелперы

const char* expected_protocol_for_port(uint16_t port) {
  switch (port) {
    case 21: return "ftp";
    case 22: return "ssh";
    case 23: return "telnet";
    case 25: case 465: case 587: return "smtp";
    case 53: return "dns";
    case 80: case 8000: case 8008: case 8080: case 8081: case 8880:
    case 9090: case 2082: case 2086: case 2095:
      return "http";
    case 110: return "pop3";
    case 143: return "imap";
    case 443: case 8443: case 8843: case 9443: case 2083: case 2087:
    case 2096: return "https";
    case 1433: return "mssql";
    case 1521: return "oracle";
    case 3306: return "mysql";
    case 5432: return "postgresql";
    case 5900: return "vnc";
    case 5984: return "http";
    case 6379: return "redis";
    case 9200: case 9300: return "http";
    case 11211: return "memcached";
    case 27017: case 27018: return "mongodb";
    default: return "";
  }
}

ServiceGuess detect_from_banner(const std::string& banner, uint16_t port) {
  ServiceGuess g;
  g.service = service_by_port(port);
  std::string b = banner.substr(0, 256);

  // ssh: "SSH-2.0-OpenSSH_9.6p1 Debian-2ubuntu3"
  size_t ssh = b.find("SSH-");
  if (ssh != std::string::npos) {
    g.service = "ssh";
    g.confidence = 3;
    size_t dash = b.find('-', ssh + 4);
    std::string rest = (dash == std::string::npos) ? b.substr(ssh + 4)
                                                   : b.substr(dash + 1);
    size_t sp = rest.find(' ');
    std::string sw = (sp == std::string::npos) ? rest : rest.substr(0, sp);
    g.product = sw;
    size_t us = sw.find('_');
    if (us != std::string::npos) {
      g.product = sw.substr(0, us);
      g.version = sw.substr(us + 1);
    }
    std::string tail = to_lower(rest);
    for (const char* os : {"ubuntu", "debian", "centos", "rhel", "freebsd",
                           "openbsd", "alpine", "suse"})
      if (tail.find(os) != std::string::npos) {
        g.os_clue = os;
        break;
      }
    return g;
  }
  // vnc rfb: "RFB 003.008\n"
  if (starts_with(b, "RFB ")) {
    g.service = "vnc";
    g.product = "RFB";
    std::string ver;
    for (size_t i = 4; i < b.size() && (std::isdigit(static_cast<unsigned char>(b[i])) || b[i] == '.'); ++i)
      ver.push_back(b[i]);
    if (!ver.empty()) g.version = ver;
    g.confidence = 3;
    return g;
  }
  // приветствия ftp/smtp
  if (starts_with(b, "220 ")) {
    std::string lb = to_lower(b);
    if (lb.find("vsftpd") != std::string::npos) g.product = "vsftpd";
    else if (lb.find("proftpd") != std::string::npos) g.product = "ProFTPD";
    else if (lb.find("postfix") != std::string::npos) g.product = "Postfix";
    else if (lb.find("exim") != std::string::npos) g.product = "Exim";
    else if (lb.find("filezilla") != std::string::npos) g.product = "FileZilla";
    if (!g.product.empty()) {
      size_t p = lb.find(to_lower(g.product));
      if (p != std::string::npos) {
        size_t i = p + g.product.size();
        while (i < b.size() && b[i] == ' ') ++i;
        std::string ver;
        while (i < b.size() &&
               (std::isdigit(static_cast<unsigned char>(b[i])) || b[i] == '.'))
          ver.push_back(b[i++]);
        if (ver.find('.') != std::string::npos) g.version = ver;
      }
    }
    if (g.service == "ftp" || to_lower(b).find("ftp") != std::string::npos)
      g.service = "ftp";
    else g.service = "smtp";
    g.confidence = 3;
    return g;
  }
  // pop3/imap
  if (starts_with(b, "+OK")) {
    if (contains_ci(b, "dovecot")) g.product = "Dovecot";
    g.service = service_by_port(port);
    g.confidence = 3;
    return g;
  }
  // mysql бинарное приветствие
  if (b.size() > 6 && static_cast<unsigned char>(b[4]) <= 11 &&
      std::isdigit(static_cast<unsigned char>(b[5]))) {
    std::string ver;
    for (size_t i = 5; i < b.size() && b[i] != '\0' &&
         (std::isdigit(static_cast<unsigned char>(b[i])) || b[i] == '.');
         ++i)
      ver.push_back(b[i]);
    if (ver.find('.') != std::string::npos) {
      g.product = (ver.compare(0, 2, "10") == 0) ? "MariaDB" : "MySQL";
      g.version = ver;
      g.service = "mysql";
      g.confidence = 3;
      return g;
    }
  }
  if (!b.empty()) g.confidence = g.service.empty() ? 0 : 1;
  return g;
}

std::vector<ServiceGuess> parse_server_products(const std::string& server) {
  std::vector<ServiceGuess> out;
  if (trim(server).empty()) return out;

  auto version_of = [](const std::string& s, size_t slash) {
    std::string ver;
    size_t i = slash + 1;
    while (i < s.size() &&
           (std::isdigit(static_cast<unsigned char>(s[i])) || s[i] == '.'))
      ver.push_back(s[i++]);
    // хвост-буква openssl типа 1.1.1d
    if (!ver.empty() && i < s.size() &&
        std::isalpha(static_cast<unsigned char>(s[i])) &&
        !std::isdigit(static_cast<unsigned char>(s[i + 1 < s.size() ? i + 1 : i])))
      ver.push_back(s[i]);
    return ver;
  };

  std::vector<std::string> tokens;
  std::string os_clue;
  std::string cur;
  for (size_t i = 0; i <= server.size(); ++i) {
    char c = i < server.size() ? server[i] : ' ';
    if (c == ' ') {
      if (!cur.empty()) tokens.push_back(cur);
      cur.clear();
      continue;
    }
    if (c == '(') {
      size_t e = server.find(')', i);
      if (e == std::string::npos) e = server.size();
      if (os_clue.empty())
        os_clue = trim(server.substr(i + 1, e - i - 1));
      i = e;
      cur.clear();
      continue;
    }
    cur.push_back(c);
  }

  // доп продукты только те что стоят cve-мапы
  auto known_extra = [](const std::string& lp) {
    return lp == "openssl" || lp == "php" || lp == "perl" ||
           lp == "mod_perl" || lp == "mod_jk" || lp == "python";
  };

  for (size_t ti = 0; ti < tokens.size(); ++ti) {
    const std::string& tok = tokens[ti];
    size_t slash = tok.find('/');
    ServiceGuess g;
    g.os_clue = os_clue;
    g.confidence = 2;  // из заголовка
    if (slash == std::string::npos) {
      // без версии берём только первый токен
      if (ti != 0) continue;
      g.product = tok;
    } else {
      g.product = tok.substr(0, slash);
      g.version = version_of(tok, slash);
    }
    std::string lp = to_lower(g.product);
    if (lp.find("microsoft-iis") != std::string::npos ||
        lp.find("microsoft-httpapi") != std::string::npos)
      g.product = "IIS";
    else if (lp.find("apache") != std::string::npos)
      g.product = "Apache";
    else if (lp == "httpd") g.product = "Apache";

    bool primary = out.empty();
    if (!primary && !known_extra(lp)) continue;
    // cloudflare без версии не продукт
    if (g.version.empty() && primary) {
      static const char* kKnownServers[] = {
          "nginx", "apache", "iis", "litespeed", "caddy", "lighttpd",
          "openresty", "tomcat", "kestrel", "jetty", "gunicorn", "wildfly",
          "glassfish", "kong", "traefik", "haproxy", "envoy"};
      bool known = false;
      for (const char* k : kKnownServers)
        if (lp == k) {
          known = true;
          break;
        }
      if (!known) g.product.clear();
    }
    if (g.service.empty()) {
      g.service = primary ? "http" : "";
    }
    if (!g.product.empty()) out.push_back(g);
  }
  return out;
}

bool looks_like_proxy_response(const std::string& http_response) {
  if (!starts_with(http_response, "HTTP/")) return false;
  std::string lower = to_lower(http_response.substr(0, 2048));
  if (lower.find(" 407 ") != std::string::npos &&
      lower.find("proxy-authenticate:") != std::string::npos)
    return true;
  if (lower.find("\nvia:") != std::string::npos) return true;
  if (lower.find("\nx-squid-error:") != std::string::npos) return true;
  if (lower.find("\nproxy-agent:") != std::string::npos) return true;
  if (lower.find("this proxy requires authentication") != std::string::npos)
    return true;
  return false;
}

const char* honeypot_banner_hit(const std::string& banner) {
  std::string lb = to_lower(banner);
  if (lb.find("cowrie") != std::string::npos) return "Cowrie";
  if (lb.find("kippo") != std::string::npos) return "Kippo";
  if (lb.find("dionaea") != std::string::npos) return "Dionaea";
  if (lb.find("opencanary") != std::string::npos) return "OpenCanary";
  if (lb.find("honeyd") != std::string::npos) return "Honeyd";
  if (lb.find("t-pot") != std::string::npos) return "T-Pot";
  if (lb.find("honeypot") != std::string::npos) return "honeypot";
  return "";
}

std::vector<std::vector<uint16_t>> sinkhole_groups(
    const std::vector<std::pair<uint16_t, std::string>>& sigs,
    size_t min_members) {
  std::map<std::string, std::vector<uint16_t>> groups;
  for (const auto& [port, sig] : sigs)
    if (!sig.empty()) groups[sig].push_back(port);
  std::vector<std::vector<uint16_t>> out;
  for (auto& [sig, ports] : groups)
    if (ports.size() >= min_members) out.push_back(ports);
  std::sort(out.begin(), out.end(),
            [](const std::vector<uint16_t>& a, const std::vector<uint16_t>& b) {
              return a.size() > b.size();
            });
  return out;
}

// модуль

namespace {

// безопасный набор портов
const std::vector<uint16_t> kDefaultPorts = {
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587,
    636, 993, 995, 1433, 1521, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 2181,
    2375, 2376, 2379, 2380, 3000, 3306, 3389, 4200, 5000, 5432, 5555, 5601,
    5900, 5984, 6379, 6443, 8000, 8008, 8009, 8080, 8081, 8443, 8843, 8880,
    8888, 9000, 9090, 9200, 9443, 11211, 15672, 27017, 27018, 50000, 61616,
};

bool is_tls_port(uint16_t port) {
  switch (port) {
    case 443: case 465: case 563: case 636: case 853: case 989: case 990:
    case 992: case 993: case 995: case 2083: case 2087: case 2096:
    case 2376: case 4443: case 6443: case 8443: case 8843: case 9443:
    case 10443:
      return true;
    default:
      return false;
  }
}

const char* service_by_port(uint16_t port) {
  switch (port) {
    case 21: return "ftp";
    case 22: return "ssh";
    case 23: return "telnet";
    case 25: return "smtp";
    case 53: return "dns";
    case 80: return "http";
    case 110: return "pop3";
    case 111: return "rpcbind";
    case 135: return "msrpc";
    case 139: return "netbios";
    case 143: return "imap";
    case 389: return "ldap";
    case 443: return "https";
    case 445: return "smb";
    case 465: return "smtps";
    case 587: return "smtp";
    case 636: return "ldaps";
    case 993: return "imaps";
    case 995: return "pop3s";
    case 1433: return "mssql";
    case 1521: return "oracle";
    case 2049: return "nfs";
    case 2181: return "zookeeper";
    case 2375: return "docker";
    case 2376: return "docker-tls";
    case 2379: return "etcd";
    case 2380: return "etcd";
    case 3306: return "mysql";
    case 3389: return "rdp";
    case 5432: return "postgresql";
    case 5900: return "vnc";
    case 5984: return "couchdb";
    case 6379: return "redis";
    case 6443: return "kubernetes";
    case 8080: return "http";
    case 8443: return "https";
    case 9200: return "elasticsearch";
    case 11211: return "memcached";
    case 15672: return "rabbitmq-mgmt";
    case 27017: return "mongodb";
    default: return "";
  }
}

// древний ssh: или легаси или ловушка
bool ssh_banner_suspicious(const std::string& version, const std::string& banner) {
  if (banner.find("SSH-1.99") != std::string::npos ||
      banner.find("SSH-1.") != std::string::npos)
    return true;
  if (version.empty()) return false;
  static const char* kOld[] = {"1.", "2.", "3.", "4.0", "4.1", "4.2",
                               "4.3", "4.4", "4.5", "4.6"};
  for (const char* p : kOld)
    if (version.compare(0, strlen(p), p) == 0) return true;
  return false;
}

struct Outcome {
  std::string host;
  PortInfo info;
  std::optional<TlsInfo> tls;
  std::string sig;      // сигнатура для sinkhole групп
  bool proxy = false;   // ответил форвардинг-прокси
  bool tls_unexpected = false;  // tls на странном порту
  bool http_on_443 = false;     // 443 отдал чистый http
  std::string expected;         // ожидаемый протокол
  bool mismatch = false;        // нарушение строгого правила
};

class PortsModule : public IModule {
 public:
  std::string name() const override { return "ports"; }
  std::string description() const override {
    return "TCP connect scan with probe-ladder service/version detection, "
           "confidence levels, honeypot/proxy/sinkhole deception analysis";
  }
  Maturity maturity() const override { return Maturity::Reference; }

  bool run(ModuleContext& ctx) override {
    const Config& cfg = ctx.cfg;

    std::vector<uint16_t> ports;
    if (cfg.ports_explicit) {
      ports = cfg.ports;
    } else if (cfg.deep) {
      ports.reserve(65535);
      for (int p = 1; p <= 65535; ++p) ports.push_back(static_cast<uint16_t>(p));
    } else {
      ports = kDefaultPorts;
    }
    // явно указанный в урле порт всегда в скоупе
    for (const auto& t : cfg.targets) {
      if (t.port > 0 && t.port <= 65535) {
        uint16_t p = static_cast<uint16_t>(t.port);
        if (std::find(ports.begin(), ports.end(), p) == ports.end())
          ports.push_back(p);
      }
    }
    std::sort(ports.begin(), ports.end());

    struct Job {
      const Target* target;
      uint16_t port;
    };
    std::vector<Job> jobs;
    for (const auto& t : cfg.targets)
      for (uint16_t p : ports) jobs.push_back(Job{&t, p});

    std::atomic<size_t> cursor{0};
    std::mutex resmu;
    std::vector<Outcome> outcomes;
    ctx.pstage("ports", "probe-ladder scan", jobs.size());

    auto worker = [&]() {
      for (;;) {
        size_t i = cursor.fetch_add(1);
        if (i >= jobs.size()) break;
        const Job& job = jobs[i];
        ctx.limiter.acquire();
        std::string err;
        UniqueFd fd = tcp_connect(job.target->host, job.port,
                                  cfg.connect_timeout_ms, err);
        ctx.ptick();
        if (!fd.valid()) continue;

        Outcome oc;
        oc.host = job.target->host;
        oc.info.port = job.port;
        oc.info.open = true;

        // лестница проб
        // 1) пассивный баннер
        std::string banner = read_available(fd.get(), 900, 1024);
        banner.erase(std::remove_if(banner.begin(), banner.end(),
                                    [](unsigned char c) { return c == '\0'; }),
                     banner.end());
        ServiceGuess det = detect_from_banner(banner, job.port);
        oc.info.confidence = det.confidence;
        oc.info.os_clue = det.os_clue;
        if (!banner.empty()) oc.info.banner = truncate_ellipsis(banner, 400);

        bool identified = det.confidence >= 2;
        if (identified) oc.info.probe = det.service;
        bool tls_confirmed = false;

        // 2) tls: на tls-портах и на тихих в deep
        if (is_tls_port(job.port) || (cfg.deep && !identified)) {
          TlsInfo ti = tls_probe(job.target->host, job.port,
                                 std::max(cfg.connect_timeout_ms, 2500));
          if (ti.ok) {
            tls_confirmed = true;
            oc.tls = ti;
            det.service = "https";
            det.product.clear();
            det.version.clear();
            det.confidence = 3;
            det.os_clue.clear();
            oc.info.probe = "https";
            if (!is_tls_port(job.port)) oc.tls_unexpected = true;
          }
        }

        // 3) http get если порт молчал
        if (!tls_confirmed && !identified) {
          std::string req = "GET / HTTP/1.0\r\nHost: " + job.target->host +
                            "\r\nUser-Agent: " + cfg.user_agent +
                            "\r\nConnection: close\r\n\r\n";
          if (send_all(fd.get(), req, 1500)) {
            std::string resp = read_available(fd.get(), 900, 4096);
            if (starts_with(resp, "HTTP/")) {
              // прокси вместо сервиса?
              if (looks_like_proxy_response(resp)) {
                oc.proxy = true;
                det.service = "http-proxy";
                det.product.clear();
                det.version.clear();
                det.confidence = 3;
                oc.info.probe = "proxy";
              } else {
                det.service = "http";  // чистый http, даже на 443
                det.confidence = 2;
                oc.info.probe = "http";
                std::string lower = to_lower(resp);
                size_t sp = lower.find("\nserver:");
                std::string server;
                if (sp != std::string::npos) {
                  sp += 8;
                  size_t e = lower.find("\r\n", sp);
                  if (e == std::string::npos) e = lower.find('\n', sp);
                  if (e != std::string::npos)
                    server = trim(resp.substr(sp, e - sp));
                }
                auto guesses = parse_server_products(server);
                if (!guesses.empty()) {
                  det.product = guesses[0].product;
                  det.version = guesses[0].version;
                  det.os_clue = guesses[0].os_clue;
                  for (size_t gi = 1; gi < guesses.size(); ++gi)
                    if (!guesses[gi].product.empty())
                      oc.info.extra_versions.push_back(
                          {guesses[gi].product, guesses[gi].version});
                }
                // сигнатура ответа для sinkhole
                size_t body_at = lower.find("\r\n\r\n");
                std::string body =
                    body_at == std::string::npos ? "" : resp.substr(body_at + 4, 512);
                std::string first_line = resp.substr(0, resp.find('\r'));
                size_t h = std::hash<std::string>{}(first_line + "|" + server +
                                                    "|" + body);
                oc.sig = "http:" + std::to_string(h);
                // порт с чужим протоколом?
                const char* exp = expected_protocol_for_port(job.port);
                static const char* kStrong[] = {"ssh", "ftp", "pop3", "imap",
                                                "mysql", "postgresql", "redis",
                                                "mongodb", "vnc", "telnet",
                                                "memcached", "mssql", "oracle"};
                for (const char* s : kStrong)
                  if (std::strcmp(exp, s) == 0) {
                    oc.expected = exp;
                    oc.mismatch = true;
                    break;
                  }
                if (job.port == 443) oc.http_on_443 = true;
              }
              identified = true;
            }
          }
        }

        // 4) redis ping, read-only
        if (!identified && job.port == 6379) {
          if (send_all(fd.get(), "PING\r\n", 200)) {
            std::string pong = read_available(fd.get(), 500, 64);
            if (starts_with(pong, "+PONG") || starts_with(pong, "-NOAUTH")) {
              det.service = "redis";
              det.confidence = 3;
              oc.info.probe = "redis";
              identified = true;
            }
          }
        }

        if (det.service.empty()) det.service = service_by_port(job.port);
        oc.info.confidence = det.confidence;
        oc.info.service = det.service;
        oc.info.product = det.product;
        oc.info.version = det.version;
        if (oc.sig.empty() && !banner.empty())
          oc.sig = "banner:" + std::to_string(
                                  std::hash<std::string>{}(banner.substr(0, 128)));
        {
          std::lock_guard<std::mutex> g(resmu);
          outcomes.push_back(std::move(oc));
        }
      }
    };

    // пул не по ядрам: скан i/o-bound, по ядрам было 4x медленнее
    int cap = cfg.deep ? 64 : 16;
    int nthreads = std::min<int>(cfg.concurrency, static_cast<int>(cap));
    nthreads = std::max(1, nthreads);
    std::vector<mikto_thread> pool;
    for (int i = 0; i < nthreads; ++i) pool.emplace_back(worker);
    for (auto& t : pool) t.join();

    std::map<std::string, bool> ip_flag;
    for (const auto& t : cfg.targets) ip_flag[t.host] = t.is_ip;
    std::map<std::string, std::vector<std::pair<uint16_t, std::string>>> sigs;
    for (auto& oc : outcomes) {
      HostResult& hr = ctx.result.ensure_host(oc.host, ip_flag[oc.host]);
      hr.ports.push_back(oc.info);
      // tls с 443 или первый удачный
      if (oc.tls && (oc.info.port == 443 || !hr.tls || !hr.tls->ok))
        hr.tls = oc.tls;
      if (!oc.sig.empty()) sigs[oc.host].push_back({oc.info.port, oc.sig});
    }
    for (auto& h : ctx.result.hosts)
      std::sort(h.ports.begin(), h.ports.end(),
                [](const PortInfo& a, const PortInfo& b) { return a.port < b.port; });

    // ос по баннерам
    for (auto& h : ctx.result.hosts) {
      std::vector<std::string> clues;
      for (const auto& p : h.ports) {
        if (!p.open) continue;
        if (!p.product.empty()) clues.push_back(p.product + "/" + p.version);
        if (!p.banner.empty()) clues.push_back(p.banner);
        if (!p.os_clue.empty()) clues.push_back(p.os_clue);
      }
      h.os_guess = guess_os_from_banners(clues);
    }
    ctx.pdone();

    // обман и прочее
    for (const auto& h : ctx.result.hosts) {
      for (const auto& p : h.ports) {
        if (!p.open) continue;

        if (p.port == 23) {
          Finding f;
          f.severity = Severity::Low;
          f.module = "ports";
          f.host = h.host;
          f.port = 23;
          f.service = p.service_label();
          f.location = "tcp/23";
          f.title = "Telnet service exposed";
          f.detail =
              "A Telnet server is reachable on this host. Telnet transmits "
              "all traffic, including credentials, in cleartext.";
          f.recommendation =
              "Disable Telnet and use SSH with key-based authentication instead.";
          ctx.result.add_finding(std::move(f));
        }

        // honeypot баннеры
        if (!p.banner.empty()) {
          if (const char* hp = honeypot_banner_hit(p.banner); hp && *hp) {
            Finding f;
            f.severity = Severity::Medium;
            f.module = "ports";
            f.host = h.host;
            f.port = p.port;
            f.service = p.service_label();
            f.location = "tcp/" + std::to_string(p.port);
            f.title = std::string("Honeypot signature (") + hp + ") in service banner";
            f.detail =
                "The service banner contains markers associated with a "
                "low-interaction honeypot. Other findings on this port may be "
                "simulated by the honeypot, not produced by real software.";
            f.recommendation =
                "If this is your honeypot: label it in the asset inventory so "
                "auditors can tell simulated from real findings. If it is not "
                "yours, treat the surrounding network as hostile territory.";
            f.evidence = p.banner;
            ctx.result.add_finding(std::move(f));
          }
        }

        if (p.service == "ssh" &&
            ssh_banner_suspicious(p.version, p.banner)) {
          Finding f;
          f.severity = Severity::Info;
          f.module = "ports";
          f.host = h.host;
          f.port = p.port;
          f.service = p.service_label();
          f.location = "tcp/" + std::to_string(p.port);
          f.title = "SSH banner suggests a very old server or a honeypot";
          f.detail =
              "The SSH software version in the banner predates versions that "
              "are plausible on a maintained modern host (or announces the "
              "legacy SSH-1.99 protocol). This is either a genuinely unpatched "
              "legacy system or a low-interaction honeypot imitating one.";
          f.recommendation =
              "Verify the actual OpenSSH build on the host before trusting "
              "banner-derived CVE matching for this port.";
          f.evidence = p.banner;
          ctx.result.add_finding(std::move(f));
        }

      }

      // мисматчи и сюрпризы по outcomes
      for (const auto& oc : outcomes) {
        if (oc.host != h.host) continue;
        const PortInfo& p = oc.info;
        if (!p.open) continue;

        if (oc.proxy) {
          Finding f;
          f.severity = Severity::Info;
          f.module = "ports";
          f.host = h.host;
          f.port = p.port;
          f.location = "tcp/" + std::to_string(p.port);
          f.title = "Forwarding proxy answered instead of an origin service";
          f.detail =
              "The response carries forwarding-proxy markers (Via / "
              "Proxy-Authenticate / X-Squid-Error). An open forwarding proxy "
              "on this port would be a serious exposure; it may also be an "
              "internal intermediary intercepting the probe.";
          f.recommendation =
              "Confirm whether this proxy is intended to be reachable from "
              "the scanned network and restrict it if not.";
          ctx.result.add_finding(std::move(f));
        }

        if (oc.tls_unexpected) {
          Finding f;
          f.severity = Severity::Info;
          f.module = "ports";
          f.host = h.host;
          f.port = p.port;
          f.location = "tcp/" + std::to_string(p.port);
          f.title = "TLS service on an unexpected port";
          f.detail =
              "A TLS handshake succeeded on a port that is not a conventional "
              "TLS port. This is often intentional (custom services, admin "
              "UIs) but is also a common way to hide services from casual "
              "scans.";
          f.recommendation =
              "Verify this service belongs in the asset inventory and its "
              "certificate is monitored like the rest of the TLS estate.";
          ctx.result.add_finding(std::move(f));
        }

        if (oc.http_on_443) {
          Finding f;
          f.severity = Severity::Low;
          f.module = "ports";
          f.host = h.host;
          f.port = 443;
          f.location = "tcp/443";
          f.title = "Port 443 answers plain HTTP without TLS";
          f.detail =
              "The TLS handshake failed but an HTTP response arrived on "
              "tcp/443. Clients expecting https:// will fail or be redirected "
              "late; some content was served in cleartext.";
          f.recommendation =
              "Serve TLS on 443 and redirect plain-HTTP traffic to it, or "
              "close the port if the service is not meant to be public.";
          ctx.result.add_finding(std::move(f));
        }

        if (oc.mismatch) {
          Finding f;
          f.severity = Severity::Low;
          f.module = "ports";
          f.host = h.host;
          f.port = p.port;
          f.location = "tcp/" + std::to_string(p.port);
          f.title = std::string("Port answers HTTP but is normally ") +
                    oc.expected;
          f.detail =
              "An HTTP response arrived on a port reserved for a different "
              "protocol. Common explanations: a reverse proxy or load "
              "balancer catching every port, port forwarding to a web "
              "service, a honeypot fronting many services, or an "
              "administrarive mistake. The port-map based service label for "
              "this port should not be trusted.";
          f.recommendation =
              "Identify what actually serves this port and correct either "
              "the port assignment or the proxy configuration.";
          ctx.result.add_finding(std::move(f));
        }
      }

      // sinkhole: одинаковые ответы на куче портов
      auto it = sigs.find(h.host);
      if (it != sigs.end()) {
        for (const auto& group : sinkhole_groups(it->second, 3)) {
          Finding f;
          f.severity = Severity::Low;
          f.module = "ports";
          f.host = h.host;
          f.location = "tcp multi-port";
          std::string pl;
          for (size_t i = 0; i < group.size() && i < 8; ++i) {
            if (i) pl += ", ";
            pl += std::to_string(group[i]);
          }
          f.title = std::to_string(group.size()) +
                    " ports return byte-identical service responses";
          f.detail =
              "Ports " + pl +
              " answered with indistinguishable responses. That pattern "
              "belongs to a wildcard reverse proxy / load-balancer handler "
              "or a honeypot, not to N independent services. Treat the open-"
              "port list for this host with suspicion and confirm each "
              "service independently.";
          f.recommendation =
              "Check the fronting proxy/LB configuration; restrict the "
              "exposed port range to the services that actually exist.";
          f.evidence = "ports: " + pl;
          ctx.result.add_finding(std::move(f));
        }
      }
    }
    return true;
  }
};

}  // namespace

std::unique_ptr<IModule> make_ports_module() {
  return std::make_unique<PortsModule>();
}

}  // namespace mikto
