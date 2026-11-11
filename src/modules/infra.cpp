// mikto — обогащение по ip: shodan internetdb, гео, фиды репутации; ключи опционально
#include "modules.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <thread>
#include <vector>

#include "mikto/osint.hpp"
#include "mikto/rate_limiter.hpp"
#include "mikto/util.hpp"
#include "mikto/version.hpp"

namespace mikto {

using nlohmann::json;

// cvelist парс

void parse_cvelist_v5(const std::string& body, std::string& cvss,
                      std::string& severity, std::string& description) {
  json j = json::parse(body, nullptr, false);
  if (j.is_discarded() || !j.is_object()) return;
  if (!j.contains("containers") || !j["containers"].is_object()) return;
  if (!j["containers"].contains("cna") || !j["containers"]["cna"].is_object())
    return;
  const json& cna = j["containers"]["cna"];

  if (cna.contains("descriptions") && cna["descriptions"].is_array()) {
    for (const auto& d : cna["descriptions"]) {
      if (d.is_object() && d.value("lang", "") == "en") {
        description = d.value("value", "");
        break;
      }
    }
  }
  // cvss: 3.1, потом 3.0, потом v2 (v2 бывает в adp)
  auto try_metrics = [&](const json& node) {
    if (!cvss.empty()) return;
    if (!node.is_object() || !node.contains("metrics")) return;
    const json& metrics = node["metrics"];
    auto check = [&](const json& m) {
      if (!cvss.empty() || !m.is_object()) return;
      for (const char* key : {"cvssV3_1", "cvssV3_0", "cvssV2_0"}) {
        if (!m.contains(key) || !m[key].is_array() || m[key].empty())
          continue;
        const json& rec = m[key][0];
        if (rec.is_object() && rec.contains("baseScore")) {
          double s = rec.value("baseScore", 0.0);
          if (s > 0) {
            char buf[16];
            std::snprintf(buf, sizeof buf, "%.1f", s);
            cvss = buf;
            severity = rec.value("baseSeverity", "");
            return;
          }
        }
      }
    };
    if (metrics.is_array()) {
      for (const auto& m : metrics) check(m);
    } else if (metrics.is_object()) {
      check(metrics);
    }
  };
  try_metrics(cna);
  if (cvss.empty() && j["containers"].contains("adp") &&
      j["containers"]["adp"].is_array()) {
    for (const auto& adp : j["containers"]["adp"]) try_metrics(adp);
  }
}

// censys парс

void parse_censys_host(const std::string& body, CensysHost& out) {
  json j = json::parse(body, nullptr, false);
  if (j.is_discarded() || !j.is_object()) return;
  if (!j.contains("data") || !j["data"].is_object()) return;
  if (!j["data"].contains("result") || !j["data"]["result"].is_object())
    return;
  const json& r = j["data"]["result"];
  out.ok = true;

  if (r.contains("services") && r["services"].is_array()) {
    for (const auto& s : r["services"]) {
      if (!s.is_object()) continue;
      CensysService svc;
      svc.port = s.value("port", 0);
      svc.transport = s.value("transport_protocol", "");
      svc.service_name = s.value("extended_service_name",
                                 s.value("service_name", ""));
      if (svc.port <= 0 && svc.service_name.empty()) continue;
      if (s.contains("software") && s["software"].is_array()) {
        for (const auto& sw : s["software"]) {
          if (!sw.is_object()) continue;
          std::string vendor = sw.value("vendor", "");
          std::string product = sw.value("product", "");
          std::string version = sw.value("version", "");
          std::string cpe = sw.value("uniform_resource_identifier", "");
          if (!vendor.empty() && !product.empty() &&
              svc.software.size() < 10) {
            std::string label = vendor + "/" + product;
            if (!version.empty()) label += " " + version;
            svc.software.push_back(std::move(label));
          }
          if (cpe.compare(0, 8, "cpe:2.3:") == 0 && svc.cpes.size() < 10)
            svc.cpes.push_back(std::move(cpe));
        }
      }
      out.services.push_back(std::move(svc));
    }
  }

  if (r.contains("labels") && r["labels"].is_array()) {
    for (const auto& l : r["labels"])
      if (l.is_string() && out.labels.size() < 10)
        out.labels.push_back(l.get<std::string>());
  }
  if (r.contains("autonomous_system") && r["autonomous_system"].is_object()) {
    const json& as = r["autonomous_system"];
    long asn = as.value("asn", 0L);
    if (asn > 0) out.asn = "AS" + std::to_string(asn);
    out.asn_desc = as.value("description", "");
  }
  if (r.contains("location") && r["location"].is_object()) {
    const json& loc = r["location"];
    out.country = loc.value("country", "");
    out.city = loc.value("city", "");
  }
  if (r.contains("dns") && r["dns"].is_object() &&
      r["dns"].contains("reverse_dns") &&
      r["dns"]["reverse_dns"].is_object()) {
    const json& rd = r["dns"]["reverse_dns"];
    if (rd.contains("names") && rd["names"].is_array() &&
        !rd["names"].empty() && rd["names"][0].is_string())
      out.rdns = rd["names"][0].get<std::string>();
  }
}

namespace {

// спим чтобы не долбить публичные api
struct ApiPacer {
  std::chrono::steady_clock::time_point last_query{};
  bool armed = false;
  std::mutex mu;

  void pace(double min_interval_s) {
    // вежливость: между запросами минимум min_interval_s; сон вне блокировки,
    // чтобы fetch одного потока не задерживал очередь других
    std::unique_lock<std::mutex> lk(mu);
    for (;;) {
      auto now = std::chrono::steady_clock::now();
      double wait = armed
                        ? min_interval_s -
                              std::chrono::duration<double>(now - last_query)
                                  .count()
                        : 0.0;
      if (wait <= 0) {
        last_query = std::chrono::steady_clock::now();
        armed = true;
        return;
      }
      lk.unlock();
      std::this_thread::sleep_for(
          std::chrono::duration_cast<std::chrono::milliseconds>(
              std::chrono::duration<double>(wait)));
      lk.lock();
    }
  }
};

void store_cache_file(const std::filesystem::path& p,
                      const std::string& body) {
  std::error_code ec;
  std::filesystem::create_directories(p.parent_path(), ec);
  std::ofstream f(p, std::ios::trunc);
  if (f) f << body;
}

// кэш с ttl, протух/нет файла -> false
bool load_cache_file(const std::filesystem::path& p, std::chrono::hours ttl,
                     std::string& body) {
  std::error_code ec;
  auto t = std::filesystem::last_write_time(p, ec);
  if (ec) return false;
  auto age = std::filesystem::file_time_type::clock::now() - t;
  if (age > ttl) return false;
  std::ifstream f(p);
  if (!f) return false;
  std::ostringstream ss;
  ss << f.rdbuf();
  body = ss.str();
  return true;
}

// internetdb клиент

class InternetDb {
 public:
  explicit InternetDb(std::string cache_dir)
      : cache_dir_(std::move(cache_dir)) {}

  bool fetch(const std::string& ip, json& out, std::string& err) {
    namespace fs = std::filesystem;
    fs::path cf = fs::path(cache_dir_) / "internetdb" / (ip + ".json");
    std::string cached;
    if (load_cache_file(cf, std::chrono::hours(24), cached)) {
      json j = json::parse(cached, nullptr, false);
      if (!j.is_discarded() && j.is_object()) {
        out = j;
        return true;
      }
    }

    pace_.pace(1.5);  // вежливость к публичному сервису
    HttpClient http;
    HttpOptions opt;
    opt.timeout_s = 15;
    opt.user_agent = std::string("mikto/") + MIKTO_VERSION;
    HttpResponse resp = http.get("https://internetdb.shodan.io/" + ip, opt);
    if (!resp.ok_network()) {
      err = resp.error.empty() ? ("HTTP " + std::to_string(resp.status))
                               : resp.error;
      return false;
    }
    if (resp.status == 404) {
      store_cache_file(cf, "{}");  // негативный кэш
      return false;
    }
    if (resp.status == 429) {
      err = "InternetDB rate limit (429) — try again later";
      return false;
    }
    if (resp.status != 200) {
      err = "InternetDB HTTP " + std::to_string(resp.status);
      return false;
    }
    store_cache_file(cf, resp.body);
    json j = json::parse(resp.body, nullptr, false);
    if (j.is_discarded() || !j.is_object()) {
      err = "InternetDB returned invalid JSON";
      return false;
    }
    out = j;
    return true;
  }

 private:
  ApiPacer pace_;
  std::string cache_dir_;
};

// censys клиент

class CensysClient {
 public:
  CensysClient(std::string cache_dir, std::string creds)
      : cache_dir_(std::move(cache_dir)), creds_(std::move(creds)) {}

  bool fetch(const std::string& ip, std::string& body, std::string& err) {
    namespace fs = std::filesystem;
    fs::path cf = fs::path(cache_dir_) / "censys" / (ip + ".json");
    std::string cached;
    if (load_cache_file(cf, std::chrono::hours(24), cached)) {
      body = cached;
      return true;
    }

    pace_.pace(1.5);  // вежливость к публичному сервису
    HttpClient http;
    HttpOptions opt;
    opt.timeout_s = 20;
    opt.user_agent = std::string("mikto/") + MIKTO_VERSION;
    opt.basic_auth = creds_;
    HttpResponse resp =
        http.get("https://search.censys.io/api/v2/hosts/" + ip, opt);
    if (!resp.ok_network()) {
      err = resp.error.empty() ? ("HTTP " + std::to_string(resp.status))
                               : resp.error;
      return false;
    }
    if (resp.status == 404) {
      store_cache_file(cf, "{}");  // негативный кэш
      return false;
    }
    if (resp.status == 401 || resp.status == 403) {
      err = "Censys rejected the credentials (HTTP " +
            std::to_string(resp.status) + ")";
      return false;
    }
    if (resp.status == 429) {
      err = "Censys rate limit (429) — daily quota may be exhausted";
      return false;
    }
    if (resp.status != 200) {
      err = "Censys HTTP " + std::to_string(resp.status);
      return false;
    }
    store_cache_file(cf, resp.body);
    body = resp.body;
    return true;
  }

 private:
  ApiPacer pace_;
  std::string cache_dir_;
  std::string creds_;
};

class InfraModule : public IModule {
 public:
  std::string name() const override { return "infra"; }
  std::string description() const override {
    return "infrastructure enrichment (keyless): Shodan InternetDB, server geolocation, OpenPhish + Feodo Tracker reputation — optional keys unlock full Shodan host data and Censys per-service software/CPEs";
  }
  Maturity maturity() const override { return Maturity::Preview; }
  std::vector<std::string> depends() const override { return {"assets"}; }

  bool run(ModuleContext& ctx) override {
    InternetDb db(ctx.cfg.cache_dir.string());
    CensysClient censys(ctx.cfg.cache_dir.string(), ctx.cfg.censys_creds);

    std::vector<std::pair<std::string, std::string>> ips;  // (ip, метка хоста)
    for (const auto& t : ctx.cfg.targets) {
      if (t.is_ip) {
        ips.push_back({t.host, t.host});
      } else {
        const HostResult* hr = ctx.result.find_host(t.host);
        if (hr)
          for (const std::string& ip : hr->ips)
            if (std::find_if(ips.begin(), ips.end(),
                             [&](const auto& p) { return p.first == ip; }) ==
                ips.end())
              ips.push_back({ip, t.host});
      }
    }
    if (ips.size() > 16) {
      ctx.warn("infra: more than 16 unique IPs — querying the first 16 only");
      ips.resize(16);
    }
    if (ips.empty()) return true;

    ctx.pstage("infra", "Shodan InternetDB", ips.size());
    std::atomic<int> enriched{0};   // инкремент из пула потоков
    std::set<std::string> reported_tags;   // per label, across IPs
    std::set<std::string> reported_extra_ports;

    // фиды один раз, кэш на диске; urlhaus умер (410), вместо него эти два
    std::vector<PhishEntry> phish_feed;
    std::string ph_err;
    bool have_phish = load_openphish_feed(ctx.cfg.cache_dir.string(),
                                          phish_feed, ph_err);
    if (!have_phish)
      ctx.log("infra: OpenPhish feed unavailable (" + ph_err + ")");
    std::vector<std::string> feodo_ips;
    std::string fe_err;
    bool have_feodo = load_feodo_feed(ctx.cfg.cache_dir.string(),
                                      feodo_ips, fe_err);
    if (!have_feodo)
      ctx.log("infra: Feodo Tracker blocklist unavailable (" + fe_err + ")");
    if (have_feodo)
      ctx.log("infra: Feodo Tracker blocklist loaded: " +
              std::to_string(feodo_ips.size()) + " C2 IPs");

    // сеть (InternetDB + гео + censys) — пулом, применяет главный поток
    struct IpIntel {
      json j;
      bool shodan_ok = false;
      std::string err;    // ошибка internetdb
      double sms = 0;
      GeoInfo geo;
      std::string gerr;
      std::string cbody, cerr;
      bool cok = false;
    };
    std::vector<IpIntel> intel(ips.size());
    ctx.parallel(ips.size(), [&](size_t ii) {
      const auto& [ip, label] = ips[ii];
      IpIntel& in = intel[ii];
      auto t0 = std::chrono::steady_clock::now();
      in.shodan_ok = db.fetch(ip, in.j, in.err);
      in.sms = std::chrono::duration<double, std::milli>(
                   std::chrono::steady_clock::now() - t0)
                   .count();
      ctx.trace("http", "https://internetdb.shodan.io/" + ip,
                "GET InternetDB " + ip,
                in.shodan_ok ? "JSON ok (ports/cpes/vulns)"
                             : ("no data" + (in.err.empty() ? "" : ": " + in.err)),
                0, 120, in.shodan_ok ? 300 : 0, in.sms);
      if (in.shodan_ok) ++enriched;

      auto g0 = std::chrono::steady_clock::now();
      in.geo = geo_lookup(ip, ctx.cfg.cache_dir.string(), 8, &in.gerr);
      ctx.trace("http", "https://ipwho.is/" + ip, "GET geolocation " + ip,
                in.geo.ok ? (in.geo.country +
                             (in.geo.asn.empty() ? "" : " / " + in.geo.asn))
                          : ("no data" +
                             (in.gerr.empty() ? "" : ": " + in.gerr)),
                0, 80, in.geo.ok ? 200 : 0,
                std::chrono::duration<double, std::milli>(
                    std::chrono::steady_clock::now() - g0)
                    .count());

      if (!ctx.cfg.censys_creds.empty()) {
        auto c0 = std::chrono::steady_clock::now();
        in.cok = censys.fetch(ip, in.cbody, in.cerr);
        ctx.trace("http", "https://search.censys.io/api/v2/hosts/" + ip,
                  "GET Censys host " + ip + " (basic auth)",
                  "fetched" + (in.cerr.empty() ? "" : ": " + in.cerr), 0, 140,
                  in.cok ? 200 : 0,
                  std::chrono::duration<double, std::milli>(
                      std::chrono::steady_clock::now() - c0)
                      .count());
      }
    });

    int enriched_n = enriched.load();

    for (size_t ii = 0; ii < ips.size(); ++ii) {
      const std::string& ip = ips[ii].first;
      const std::string& label = ips[ii].second;
      IpIntel& in = intel[ii];
      ctx.ptick();
      ctx.pitem(ip);
      if (!in.shodan_ok) {
        if (!in.err.empty()) ctx.log("infra: " + ip + ": " + in.err);
      }
      HostResult& host = ctx.result.ensure_host(label, false);
      const GeoInfo& geo = in.geo;
      const std::string& gerr = in.gerr;
      const json& j = in.j;

      if (geo.ok) {
        host.geo = geo;
        Finding f;
        f.severity = Severity::Info;
        f.module = "infra";
        f.host = label;
        f.service = "recon";
        f.location = ip;
        f.title = "Location: " + geo.country +
                  (geo.city.empty() ? "" : ", " + geo.city) +
                  (geo.asn.empty() ? "" : " — " + geo.asn);
        f.detail =
            "Network geolocation and ownership of the IP from public "
            "keyless datasets. Datacenter presence is normal for servers, "
            "but a hosting country you did not expect is worth checking "
            "against your infrastructure records.";
        f.recommendation =
            "Confirm the location/ASN matches your deployment inventory; "
            "mismatches often reveal shadow or legacy deployments.";
        std::string ev = "country: " + geo.country;
        if (!geo.region.empty()) ev += "\nregion: " + geo.region;
        if (!geo.city.empty()) ev += "\ncity: " + geo.city;
        if (geo.lat != 0 || geo.lon != 0) {
          char buf[64];
          std::snprintf(buf, sizeof buf, "%.4f, %.4f", geo.lat, geo.lon);
          ev += std::string("\ncoords: ") + buf;
        }
        if (!geo.asn.empty()) ev += "\nasn: " + geo.asn;
        if (!geo.org.empty()) ev += "\norg: " + geo.org;
        f.evidence = ev;
        ctx.result.add_finding(std::move(f));
      } else if (!gerr.empty()) {
        ctx.log("infra: geo lookup failed for " + ip + ": " + gerr);
      }

      // репутация
      {
        std::vector<std::string> notes;
        if (have_phish) {
          auto hits = openphish_check(phish_feed, label);
          if (!hits.empty()) {
            std::string n = "OpenPhish: " + hits.front().url;
            host.reputation.push_back(n);
            notes.push_back("host listed in the OpenPhish phishing feed (" +
                            std::to_string(hits.size()) + " URL(s))");
            Finding f;
            f.severity = Severity::High;
            f.module = "infra";
            f.host = label;
            f.service = "reputation";
            f.location = label;
            f.title = "Host is listed in the OpenPhish phishing feed";
            f.detail =
                "The OpenPhish community feed of active phishing URLs "
                "contains " + std::to_string(hits.size()) +
                " URL(s) on this host. The server may be hosting phishing "
                "(compromise or intentional), or shares infrastructure with "
                "one that does. Browsers and mail filters may already block "
                "it.";
            f.recommendation =
                "Investigate immediately: locate and remove the phishing "
                "content, then verify the listing disappears after cleanup.";
            f.evidence = truncate_ellipsis(hits.front().url, 300);
            f.references.push_back("https://www.openphish.com/");
            ctx.result.add_finding(std::move(f));
          }
        }
        if (have_feodo && feodo_check(feodo_ips, {ip})) {
          std::string n = "Feodo Tracker: C2 blocklist contains " + ip;
          if (host.reputation.size() < 10)
            host.reputation.push_back(n);
          notes.push_back("IP present in the Feodo Tracker botnet C2 "
                          "blocklist");
          Finding f;
          f.severity = Severity::High;
          f.module = "infra";
          f.host = label;
          f.service = "reputation";
          f.location = ip;
          f.title = "IP is listed as a botnet C2 address (Feodo Tracker)";
          f.detail =
              "The abuse.ch Feodo Tracker recommended blocklist contains "
              "this IP as a botnet command-and-control server. Traffic "
              "from/to it may already be sinkholed or blocked; hosting "
              "legitimate services here damages reputation.";
          f.recommendation =
              "Verify the host is not actually running malware infrastructure; "
              "if the IP was reassigned, request delisting via abuse.ch.";
          f.evidence = "feodotracker.abuse.ch recommended blocklist: " + ip;
          f.references.push_back(
              "https://feodotracker.abuse.ch/browse/");
          ctx.result.add_finding(std::move(f));
        }
        for (const auto& n : notes) ctx.log("infra: " + label + ": " + n);
      }

      // censys, если есть ключ — ответ предзагружен пулом выше
      if (!ctx.cfg.censys_creds.empty()) {
        CensysHost ch;
        if (in.cok) parse_censys_host(in.cbody, ch);
        if (in.cok && !ch.ok)
          ctx.log("infra: censys: unparseable response for " + ip);
        if (!in.cok && !in.cerr.empty())  // 404 молчим
          ctx.log("infra: censys: " + ip + ": " + in.cerr);

        if (ch.ok) {
          for (const auto& l : ch.labels)
            if (std::find(host.infra_tags.begin(), host.infra_tags.end(),
                          l) == host.infra_tags.end())
              host.infra_tags.push_back(l);

          // cpe в общий пул для cve
          for (const auto& svc : ch.services)
            for (const auto& cpe : svc.cpes)
              if (host.shodan_cpes.size() < 40 &&
                  std::find(host.shodan_cpes.begin(), host.shodan_cpes.end(),
                            cpe) == host.shodan_cpes.end())
                host.shodan_cpes.push_back(cpe);

          // фолбек когда бесплатное гео промолчало
          if (!host.geo.ok && !ch.country.empty()) {
            host.geo.ok = true;
            host.geo.country = ch.country;
            host.geo.city = ch.city;
            host.geo.asn = ch.asn;
            host.geo.org = ch.asn_desc;
            Finding f;
            f.severity = Severity::Info;
            f.module = "infra";
            f.host = label;
            f.service = "recon";
            f.location = ip;
            f.title = "Location (Censys): " + ch.country +
                      (ch.city.empty() ? "" : ", " + ch.city) +
                      (ch.asn.empty() ? "" : " — " + ch.asn);
            f.detail =
                "The keyless geolocation sources did not answer for this "
                "IP, so the location/ASN shown comes from the Censys "
                "internet-scan dataset. Treat it as an approximation: "
                "IP geolocation is best-effort by nature.";
            f.recommendation =
                "Cross-check the country/ASN against your infrastructure "
                "inventory.";
            f.evidence = "source: search.censys.io";
            ctx.result.add_finding(std::move(f));
          }

          std::string svclist;
          std::string softlist;
          std::set<int> censys_ports;
          for (const auto& svc : ch.services) {
            censys_ports.insert(svc.port);
            if (!svclist.empty()) svclist += ", ";
            svclist += svc.service_name + "/" + std::to_string(svc.port);
            for (const auto& sw : svc.software) {
              if (softlist.size() > 300) break;
              if (!softlist.empty()) softlist += "; ";
              softlist += svc.service_name + ": " + sw;
            }
          }
          if (!svclist.empty()) {
            Finding f;
            f.severity = Severity::Info;
            f.module = "infra";
            f.host = label;
            f.service = "recon";
            f.location = ip;
            f.title = "Censys services: " + svclist;
            f.detail =
                "Services Censys internet-wide scans observed on this IP. "
                "Historical data may lag reality: a listed service can be "
                "patched, moved or closed since the last observation. "
                "Software strings here feed the CVE matcher.";
            f.recommendation =
                "Confirm each listed service is intentional, patched and "
                "meant to be public.";
            std::string ev;
            if (!ch.asn.empty()) ev += "asn: " + ch.asn;
            if (!ch.asn_desc.empty()) ev += " " + ch.asn_desc;
            if (!ch.rdns.empty()) ev += "\nrdns: " + ch.rdns;
            if (!softlist.empty()) ev += "\nsoftware: " + softlist;
            f.evidence = ev.empty() ? "source: search.censys.io" : ev;
            f.references.push_back("https://search.censys.io/hosts/" + ip);
            ctx.result.add_finding(std::move(f));
          }

          // порты которые censys видел а мы нет
          std::set<int> our_open_local;
          for (const auto& p : host.ports)
            if (p.open) our_open_local.insert(p.port);
          std::string extra;
          int n = 0;
          for (int port : censys_ports) {
            if (our_open_local.count(port)) continue;
            ++n;
            if (extra.size() < 200) {
              if (!extra.empty()) extra += ", ";
              extra += std::to_string(port);
            }
          }
          if (n > 0) {
            Finding f;
            f.severity = Severity::Low;
            f.module = "infra";
            f.host = label;
            f.service = "recon";
            f.location = ip;
            f.title = "Censys knows " + std::to_string(n) +
                      " more open port(s): " + extra;
            f.detail =
                "Censys scans observed additional open ports that the "
                "current scan did not find. They may be dynamic, filtered "
                "today, historical, or simply outside the safe port list. "
                "Cross-check with the Shodan InternetDB finding when both "
                "sources report extras.";
            f.recommendation =
                "Run with --deep (authorized) or --ports to confirm these "
                "ports, then close those that must not be public.";
            f.evidence = "source: search.censys.io";
            ctx.result.add_finding(std::move(f));
          }
        }
      }

      bool have_shodan = j.is_object() && !j.empty();
      if (!have_shodan) continue;

      if (j.contains("tags") && j["tags"].is_array()) {
        std::vector<std::string> tag_list;
        for (const auto& tv : j["tags"]) {
          std::string tag = tv.is_string() ? tv.get<std::string>() : "";
          if (tag.empty()) continue;
          if (std::find(host.infra_tags.begin(), host.infra_tags.end(),
                        tag) == host.infra_tags.end())
            host.infra_tags.push_back(tag);
          tag_list.push_back(tag);
        }
        // internetdb даёт теги в случайном порядке, сортируем иначе дубли
        std::sort(tag_list.begin(), tag_list.end());
        std::string tags;
        for (const auto& tag : tag_list) {
          if (!tags.empty()) tags += ", ";
          tags += tag;
        }
        if (!tags.empty() && !reported_tags.count(label + "|" + tags)) {
          reported_tags.insert(label + "|" + tags);
          Finding f;
          f.severity = Severity::Info;
          f.module = "infra";
          f.host = label;
          f.service = "recon";
          f.location = ip;
          f.title = "Shodan tags: " + tags;
          f.detail =
              "Classification tags assigned to this IP by the Shodan "
              "InternetDB from historical internet-wide scans.";
          f.recommendation =
              "Review the tags; they describe what the host looks like "
              "from the outside, which may differ from your asset records.";
          ctx.result.add_finding(std::move(f));
        }
      }

      // хостнеймы с этого ip
      if (j.contains("hostnames") && j["hostnames"].is_array()) {
        for (const auto& hn : j["hostnames"]) {
          if (hn.is_string() && host.neighbors.size() < 100) {
            std::string s = hn.get<std::string>();
            if (std::find(host.neighbors.begin(), host.neighbors.end(), s) ==
                host.neighbors.end())
              host.neighbors.push_back(s);
          }
        }
      }

      // лишние порты от shodan
      std::set<int> our_open;
      for (const auto& p : host.ports)
        if (p.open) our_open.insert(p.port);
      if (j.contains("ports") && j["ports"].is_array() && !ctx.cfg.deep) {
        std::string extra;
        int n = 0;
        for (const auto& pv : j["ports"]) {
          if (!pv.is_number_integer()) continue;
          int port = pv.get<int>();
          if (our_open.count(port)) continue;
          ++n;
          if (extra.size() < 200) {
            if (!extra.empty()) extra += ", ";
            extra += std::to_string(port);
          }
        }
        if (n > 0 && !reported_extra_ports.count(label)) {
          reported_extra_ports.clear();  // одно резюме на хост
          reported_extra_ports.insert(label);
          Finding f;
          f.severity = Severity::Low;
          f.module = "infra";
          f.host = label;
          f.service = "recon";
          f.location = ip;
          f.title = "Shodan knows " + std::to_string(n) +
                    " more open port(s): " + extra;
          f.detail =
              "Historical Shodan scans observed additional open ports that "
              "the current safe-mode scan did not check. They may be "
              "dynamic, filtered today, or simply outside the safe port "
              "list.";
          f.recommendation =
              "Run with --deep (authorized) or --ports to confirm these "
              "ports, then close those that must not be public.";
          ctx.result.add_finding(std::move(f));
        }
      }

      if (j.contains("cpes") && j["cpes"].is_array()) {
        for (const auto& cv : j["cpes"]) {
          if (!cv.is_string()) continue;
          std::string cpe = cv.get<std::string>();
          if (cpe.empty()) continue;
          if (host.shodan_cpes.size() < 40) host.shodan_cpes.push_back(cpe);
        }
      }

      // shodan cve id -> находки, обогащение из cvelist
      if (j.contains("vulns") && j["vulns"].is_array()) {
        std::vector<std::string> cve_ids;
        for (const auto& vv : j["vulns"]) {
          if (vv.is_string() && vv.get<std::string>().compare(0, 4, "CVE-") == 0)
            cve_ids.push_back(vv.get<std::string>());
        }
        std::sort(cve_ids.begin(), cve_ids.end());
        cve_ids.erase(std::unique(cve_ids.begin(), cve_ids.end()),
                      cve_ids.end());
        int reported = 0;
        for (const std::string& id : cve_ids) {
          if (++reported > 25) break;
          std::string cvss, sev, desc;
          enrich_cve(ctx, id, cvss, sev, desc);
          Finding f;
          double score = cvss.empty() ? 0.0 : std::strtod(cvss.c_str(), nullptr);
          f.severity = score > 0 ? severity_from_cvss(score)
                                 : severity_from_nvd(sev.empty() ? "UNKNOWN"
                                                                 : sev);
          f.module = "infra";
          f.host = label;
          f.service = "recon";
          f.location = ip;
          f.title = id + " (Shodan InternetDB)" +
                    (score > 0 ? " — CVSS " + cvss : "");
          f.detail =
              (desc.empty()
                   ? "This CVE was observed by Shodan for this IP. The "
                     "vulnerability is known to be associated with one of "
                     "the services historically exposed here."
                   : desc) +
              " Shodan matched this IP against the vulnerability's known "
              "fingerprint; confirm exploitation is actually possible by "
              "checking the exact product version you serve.";
          f.recommendation =
              "Verify the affected component on this host, patch to the "
              "fixed version, and re-scan.";
          f.references.push_back(
              "https://nvd.nist.gov/vuln/detail/" + id);
          f.evidence = "source: internetdb.shodan.io";
          ctx.result.add_finding(std::move(f));
        }
      }

      // полный shodan по ключу
      if (!ctx.cfg.shodan_key.empty()) {
        ctx.limiter.acquire();
        HttpClient http;
        HttpOptions opt;
        opt.timeout_s = 20;
        opt.user_agent = std::string("mikto/") + MIKTO_VERSION;
        HttpResponse resp = http.get(
            "https://api.shodan.io/shodan/host/" + ip + "?key=" +
                ctx.cfg.shodan_key + "&minify=true",
            opt);
        if (resp.ok_network() && resp.status == 200) {
          json sj = json::parse(resp.body, nullptr, false);
          if (!sj.is_discarded() && sj.is_object()) {
            std::string os = sj.value("os", "");
            if (!os.empty() && host.os_guess.empty()) host.os_guess = os;
            if (sj.contains("data") && sj["data"].is_array()) {
              for (const auto& d : sj["data"]) {
                if (!d.is_object()) continue;
                if (d.contains("cpe") && d["cpe"].is_array())
                  for (const auto& c : d["cpe"])
                    if (c.is_string() && host.shodan_cpes.size() < 40)
                      host.shodan_cpes.push_back(c.get<std::string>());
              }
            }
          }
        } else {
          ctx.log("infra: shodan api lookup failed for " + ip);
        }
      }
    }
    if (enriched_n == 0)
      ctx.log("infra: no InternetDB data for any target IP");
    ctx.pdone();
    return true;
  }

 private:
  void enrich_cve(ModuleContext& ctx, const std::string& id,
                  std::string& cvss, std::string& severity,
                  std::string& desc) {
    namespace fs = std::filesystem;
    // CVE-2024-12345 -> cves/2024/1xxx/CVE-2024-12345.json
    if (id.size() < 13) return;
    std::string year = id.substr(4, 4);
    std::string seq = id.substr(9);  // "12345"
    std::string bucket = seq.substr(0, 1) + "xxx";
    std::string tail = "cves/" + year + "/" + bucket + "/" + id + ".json";

    fs::path cf = fs::path(ctx.cfg.cache_dir.string()) / "cvelist" / (id + ".json");
    std::error_code ec;
    auto t = fs::last_write_time(cf, ec);
    if (!ec) {
      auto age = fs::file_time_type::clock::now() - t;
      if (age < std::chrono::hours(24)) {
        std::ifstream f(cf);
        if (f) {
          std::ostringstream ss;
          ss << f.rdbuf();
          parse_cvelist_v5(ss.str(), cvss, severity, desc);
          desc = truncate_ellipsis(desc, 2400);
          return;
        }
      }
    }

    ctx.limiter.acquire();
    HttpClient http;
    HttpOptions opt;
    opt.timeout_s = 15;
    opt.user_agent = std::string("mikto/") + MIKTO_VERSION;
    HttpResponse resp =
        http.get("https://raw.githubusercontent.com/CVEProject/cvelistV5/main/" +
                     tail,
                 opt);
    if (!resp.ok_network() || resp.status != 200) return;
    fs::create_directories(cf.parent_path(), ec);
    std::ofstream f(cf, std::ios::trunc);
    if (f) f << resp.body;
    parse_cvelist_v5(resp.body, cvss, severity, desc);
    desc = truncate_ellipsis(desc, 2400);
  }
};

}  // namespace

std::unique_ptr<IModule> make_infra_module() {
  return std::make_unique<InfraModule>();
}

}  // namespace mikto
