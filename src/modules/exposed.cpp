// mikto — сервисы без авторизации, пробы строго read-only
#include "modules.hpp"

#include <mutex>
#include <set>
#include <vector>

#include "mikto/net.hpp"
#include "mikto/rate_limiter.hpp"
#include "mikto/util.hpp"

namespace mikto {

namespace {

std::string i32be(int v) {
  std::string s(4, '\0');
  s[0] = static_cast<char>(v & 0xff);
  s[1] = static_cast<char>((v >> 8) & 0xff);
  s[2] = static_cast<char>((v >> 16) & 0xff);
  s[3] = static_cast<char>((v >> 24) & 0xff);
  return s;
}

std::string mongo_hello_doc() {
  std::string body;
  body += '\x10';
  body += "hello";
  body += '\0';
  body += i32be(1);
  body += '\x02';
  body += "$db";
  body += '\0';
  body += i32be(6);
  body += "admin";
  body += '\0';
  int len = static_cast<int>(4 + body.size() + 1);
  return i32be(len) + body + '\0';
}

// легаси {isMaster:1}
std::string mongo_ismaster_doc() {
  std::string body;
  body += '\x10';
  body += "isMaster";
  body += '\0';
  body += i32be(1);
  int len = static_cast<int>(4 + body.size() + 1);
  return i32be(len) + body + '\0';
}

// op_msg с hello (4.4+)
std::string mongo_op_msg_probe() {
  std::string doc = mongo_hello_doc();
  int total = static_cast<int>(16 + 4 + 1 + doc.size());
  return i32be(total) + i32be(1) + i32be(0) + i32be(2013) + i32be(0) + '\x00' +
         doc;
}

// легаси op_query на admin.$cmd (до 4.4)
std::string mongo_legacy_probe() {
  std::string doc = mongo_ismaster_doc();
  std::string coll = "admin.$cmd";
  coll.push_back('\0');
  int total = static_cast<int>(16 + 4 + coll.size() + 4 + 4 + doc.size());
  std::string msg = i32be(total) + i32be(1) + i32be(0) + i32be(2004) + i32be(0) +
                    coll + i32be(0xffffffff) + doc;
  return msg;
}

struct Probe {
  uint16_t port;
  const char* label;
};

const std::vector<Probe> kTcpProbes = {
    {6379, "redis"}, {11211, "memcached"}, {27017, "mongodb"},
};

class ExposedModule : public IModule {
 public:
  std::string name() const override { return "exposed"; }
  std::string description() const override {
    return "detect services answering without authentication (Redis, MongoDB, Memcached, Elasticsearch, Docker API, ...) — read-only probes";
  }
  Maturity maturity() const override { return Maturity::Reference; }
  std::vector<std::string> depends() const override { return {"ports"}; }

  bool run(ModuleContext& ctx) override {
    const Config& cfg = ctx.cfg;
    // задача = один открытый порт с известным сервисом; пробы в пуле
    struct Task {
      const HostResult* host;
      const PortInfo* port;
    };
    std::vector<Task> tasks;
    for (const auto& host : ctx.result.hosts)
      for (const auto& p : host.ports) {
        if (!p.open) continue;
        switch (p.port) {
          case 6379: case 11211: case 27017: case 9200: case 5984:
          case 2379: case 2375: case 2376: case 15672: case 6443:
            tasks.push_back({&host, &p});
            break;
          default: break;
        }
        (void)cfg;
      }
    ctx.parallel(tasks.size(),
                 [&](size_t i) {
                   const HostResult& host = *tasks[i].host;
                   const PortInfo& p = *tasks[i].port;
                   switch (p.port) {
                     case 6379: check_redis(ctx, host, p); break;
                     case 11211: check_memcached(ctx, host, p); break;
                     case 27017: check_mongodb(ctx, host, p); break;
                     case 9200:
                       check_http_json(ctx, host, p, "http", "/", "cluster_name",
                                       "Elasticsearch", "elasticsearch");
                       break;
                     case 5984:
                       check_http_json(ctx, host, p, "http", "/", "\"couchdb\"",
                                       "CouchDB", "couchdb");
                       break;
                     case 2379:
                       check_http_json(ctx, host, p, "http", "/version",
                                       "etcdserver", "etcd", "etcd");
                       break;
                     case 2375:
                       check_http_json(ctx, host, p, "http", "/version",
                                       "ApiVersion", "Docker API", "docker");
                       break;
                     case 2376:
                       check_http_json(ctx, host, p, "https", "/version",
                                       "ApiVersion", "Docker API (TLS)", "docker");
                       break;
                     case 15672: check_rabbitmq(ctx, host, p); break;
                     case 6443: check_kubernetes(ctx, host, p); break;
                     default: break;
                   }
                 },
                 16);
    return true;
  }

 private:
  std::mutex res_mu_;  // add_finding не потокобезопасен, пробы в пуле
  Finding base(const HostResult& host, const PortInfo& p) const {
    Finding f;
    f.module = "exposed";
    f.host = host.host;
    f.port = p.port;
    f.service = p.service_label();
    f.location = "tcp/" + std::to_string(p.port);
    return f;
  }

  void add_critical(ModuleContext& ctx, Finding f, const std::string& what,
                    const std::string& detail, const std::string& evidence) {
    f.severity = Severity::Critical;
    f.title = what + " responds without authentication";
    f.detail = detail;
    f.recommendation =
        "Enable authentication, bind the service to localhost or a private "
        "network, and restrict access with firewall rules.";
    f.evidence = truncate_ellipsis(evidence, 600);
    std::lock_guard<std::mutex> g(res_mu_);
    ctx.result.add_finding(std::move(f));
  }

  void check_redis(ModuleContext& ctx, const HostResult& host,
                   const PortInfo& p) {
    ctx.limiter.acquire();
    std::string err;
    UniqueFd fd = tcp_connect(host.host, p.port, ctx.cfg.connect_timeout_ms, err);
    if (!fd.valid()) return;
    if (!send_all(fd.get(), "PING\r\n", 1000)) return;
    std::string resp = read_available(fd.get(), 900, 64);
    if (starts_with(resp, "+PONG")) {
      Finding f = base(host, p);
      add_critical(ctx, std::move(f), "Redis",
                   "The Redis server answered PING without requiring a "
                   "password. Unauthenticated Redis is a common initial "
                   "access vector (key writes, RCE via module loading in "
                   "older versions).",
                   resp);
    }
    // -NOAUTH значит есть пароль, ок
  }

  void check_memcached(ModuleContext& ctx, const HostResult& host,
                       const PortInfo& p) {
    ctx.limiter.acquire();
    std::string err;
    UniqueFd fd = tcp_connect(host.host, p.port, ctx.cfg.connect_timeout_ms, err);
    if (!fd.valid()) return;
    if (!send_all(fd.get(), "version\r\n", 1000)) return;
    std::string resp = read_available(fd.get(), 900, 128);
    if (starts_with(resp, "VERSION")) {
      Finding f = base(host, p);
      add_critical(ctx, std::move(f), "Memcached",
                   "The Memcached server answered a version query without "
                   "authentication. Open memcached instances are routinely "
                   "abused for reflection DDoS and can leak cached data.",
                   resp);
    }
  }

  void check_mongodb(ModuleContext& ctx, const HostResult& host,
                     const PortInfo& p) {
    ctx.limiter.acquire();
    std::string err;
    UniqueFd fd = tcp_connect(host.host, p.port, ctx.cfg.connect_timeout_ms, err);
    if (!fd.valid()) return;
    if (!send_all(fd.get(), mongo_op_msg_probe(), 1000)) return;
    std::string resp = read_available(fd.get(), 1200, 4096);
    bool answered =
        resp.find("maxBsonObjectSize") != std::string::npos ||
        resp.find("logicalSessionTimeoutMinutes") != std::string::npos;
    if (!answered) {
      // старые (<4.4) говорят только op_query
      ctx.limiter.acquire();
      std::string err2;
      UniqueFd fd2 =
          tcp_connect(host.host, p.port, ctx.cfg.connect_timeout_ms, err2);
      if (!fd2.valid()) return;
      if (!send_all(fd2.get(), mongo_legacy_probe(), 1000)) return;
      resp = read_available(fd2.get(), 1200, 4096);
      answered = resp.find("ismaster") != std::string::npos ||
                 resp.find("maxBsonObjectSize") != std::string::npos;
    }
    if (answered) {
      Finding f = base(host, p);
      add_critical(ctx, std::move(f), "MongoDB",
                   "The MongoDB server answered a handshake command without "
                   "requiring credentials. Unless authentication is enforced "
                   "per database, an attacker can read and modify data.",
                   resp.substr(0, 64));
    }
  }

  void check_http_json(ModuleContext& ctx, const HostResult& host,
                       const PortInfo& p, const std::string& scheme,
                       const std::string& path, const std::string& marker,
                       const std::string& what, const std::string& svc) {
    ctx.limiter.acquire();
    HttpOptions opt;
    opt.timeout_s = std::max(3, ctx.cfg.http_timeout_s);
    opt.user_agent = ctx.cfg.user_agent;
    HttpResponse resp = ctx.get(scheme + "://" + host.host + ":" +
                                         std::to_string(p.port) + path,
                                     opt);
    if (!resp.ok_network() || resp.status != 200) return;  // 401 и т.п. = норм
    if (resp.body.find(marker) == std::string::npos) return;
    Finding f = base(host, p);
    f.severity = Severity::Critical;
    f.title = what + " responds without authentication";
    f.detail = "The " + what + " service (" + svc +
               ") answered an HTTP request without requiring authentication. "
               "Such endpoints frequently expose configuration, cluster "
               "metadata, or the full data store.";
    f.recommendation =
        "Enable authentication, bind the service to localhost or a private "
        "network, and restrict access with firewall rules.";
    f.evidence = truncate_ellipsis(resp.body, 600);
    {
      std::lock_guard<std::mutex> g(res_mu_);
      ctx.result.add_finding(std::move(f));
    }
  }

  void check_rabbitmq(ModuleContext& ctx, const HostResult& host,
                      const PortInfo& p) {
    ctx.limiter.acquire();
    HttpOptions opt;
    opt.timeout_s = std::max(3, ctx.cfg.http_timeout_s);
    opt.user_agent = ctx.cfg.user_agent;
    HttpResponse resp =
        ctx.get("http://" + host.host + ":" + std::to_string(p.port) +
                         "/api/overview",
                     opt);
    if (!resp.ok_network() || resp.status != 200) return;
    if (resp.body.find("rabbitmq") == std::string::npos) return;
    Finding f = base(host, p);
    f.severity = Severity::Critical;
    f.title = "RabbitMQ management API responds without authentication";
    f.detail =
        "The RabbitMQ management API answered /api/overview without "
        "credentials, exposing queues, exchanges and cluster statistics.";
    f.recommendation =
        "Remove the guest account, create named users with strong "
        "credentials, and restrict the management port to trusted networks.";
    f.evidence = truncate_ellipsis(resp.body, 600);
    {
      std::lock_guard<std::mutex> g(res_mu_);
      ctx.result.add_finding(std::move(f));
    }
  }

  void check_kubernetes(ModuleContext& ctx, const HostResult& host,
                        const PortInfo& p) {
    ctx.limiter.acquire();
    HttpOptions opt;
    opt.timeout_s = std::max(3, ctx.cfg.http_timeout_s);
    opt.user_agent = ctx.cfg.user_agent;
    HttpResponse resp =
        ctx.get("https://" + host.host + ":" + std::to_string(p.port) +
                         "/api",
                     opt);
    if (!resp.ok_network()) return;
    if (resp.status == 200 && resp.body.find("versions") != std::string::npos) {
      Finding f = base(host, p);
      f.severity = Severity::Critical;
      f.title = "Kubernetes API accepts anonymous requests";
      f.detail =
          "The Kubernetes API server returned API version information for an "
          "unauthenticated request to /api. Depending on RBAC configuration "
          "this may be benign, but it often accompanies a misconfigured "
          "cluster.";
      f.recommendation =
          "Verify that --anonymous-auth=false or that RBAC denies anonymous "
          "subjects; restrict the API server to trusted networks.";
      f.evidence = truncate_ellipsis(resp.body, 600);
      {
        std::lock_guard<std::mutex> g(res_mu_);
        ctx.result.add_finding(std::move(f));
      }
    }
  }
};

}  // namespace

std::unique_ptr<IModule> make_exposed_module() {
  return std::make_unique<ExposedModule>();
}

}  // namespace mikto
