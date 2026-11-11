#include "mikto/osint.hpp"

#include "mikto/win_compat.hpp"
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <thread>

#include "mikto/http_client.hpp"
#include "mikto/net.hpp"
#include <nlohmann/json.hpp>
#include "mikto/util.hpp"
#include "mikto/version.hpp"

namespace mikto {

using nlohmann::json;

namespace {

namespace fs = std::filesystem;

bool load_cache_file(const fs::path& p, std::chrono::hours ttl,
                     std::string& body) {
  std::error_code ec;
  auto t = fs::last_write_time(p, ec);
  if (ec) return false;
  auto age = fs::file_time_type::clock::now() - t;
  if (age > ttl) return false;
  std::ifstream f(p);
  if (!f) return false;
  std::ostringstream ss;
  ss << f.rdbuf();
  body = ss.str();
  return true;
}

void store_cache_file(const fs::path& p, const std::string& body) {
  std::error_code ec;
  fs::create_directories(p.parent_path(), ec);
  std::ofstream f(p, std::ios::trunc);
  if (f) f << body;
}

HttpResponse polite_get(const std::string& url, int timeout_s,
                        long max_body_bytes = 2 * 1024 * 1024) {
  HttpOptions opt;
  opt.timeout_s = timeout_s;
  opt.user_agent = std::string("mikto/") + MIKTO_VERSION;
  opt.max_body_bytes = max_body_bytes;
  HttpClient http;
  return http.get(url, opt);
}

// key: value без учета регистра
std::string whois_field(const std::string& text,
                        const std::vector<std::string>& keys) {
  std::istringstream iss(text);
  std::string line;
  while (std::getline(iss, line)) {
    size_t colon = line.find(':');
    if (colon == std::string::npos) continue;
    std::string key = to_lower(trim(line.substr(0, colon)));
    for (const auto& k : keys) {
      if (key == k) {
        std::string val = trim(line.substr(colon + 1));
        if (!val.empty()) return val;
      }
    }
  }
  return "";
}

void collect_whois_emails(const std::string& text,
                          std::vector<std::string>& out) {
  size_t i = 0;
  while (i < text.size() && out.size() < 12) {
    size_t at = text.find('@', i);
    if (at == std::string::npos || at == 0) break;
    size_t s = at;
    while (s > 0 && (std::isalnum(static_cast<unsigned char>(text[s - 1])) ||
                     text[s - 1] == '.' || text[s - 1] == '_' ||
                     text[s - 1] == '-' || text[s - 1] == '+'))
      --s;
    size_t e = at + 1;
    while (e < text.size() &&
           (std::isalnum(static_cast<unsigned char>(text[e])) ||
            text[e] == '.' || text[e] == '-' || text[e] == '_'))
      ++e;
    if (e > at + 1 && text[e - 1] != '.') {
      std::string email = to_lower(text.substr(s, e - s));
      bool plausible = email.find('.') != std::string::npos &&
                       !ends_with(email, ".jpg") && !ends_with(email, ".png");
      if (plausible &&
          std::find(out.begin(), out.end(), email) == out.end())
        out.push_back(email);
    }
    i = e;
  }
}

}  // namespace

// ---- WHOIS ------------------------------------------------------------------

void parse_whois_response(const std::string& text, WhoisInfo& info) {
  info.ok = true;
  info.registrar = whois_field(text, {"registrar",
                                      "registrar name",
                                      "registrar:",
                                      "sponsoring registrar"});
  info.created = whois_field(text, {"creation date", "created", "created on",
                                    "registered on", "domain registration date",
                                    "registration time"});
  info.updated = whois_field(text, {"updated date", "last updated",
                                    "last modified", "changed", "modified"});
  info.expires = whois_field(text, {"registry expiry date", "expiry date",
                                    "expiration date", "expires",
                                    "registrar registration expiration date",
                                    "paid-till", "expire"});
  // Nameservers.
  std::istringstream iss(text);
  std::string line;
  while (std::getline(iss, line)) {
    size_t colon = line.find(':');
    if (colon == std::string::npos) continue;
    std::string key = to_lower(trim(line.substr(0, colon)));
    std::string val = to_lower(trim(line.substr(colon + 1)));
    if ((key == "name server" || key == "nserver" || key == "nameserver" ||
         key == "name servers") &&
        val.find('.') != std::string::npos && val.size() <= 253) {
      if (std::find(info.nameservers.begin(), info.nameservers.end(), val) ==
          info.nameservers.end())
        info.nameservers.push_back(val);
    }
  }
  collect_whois_emails(text, info.emails);
  // мусорный ответ не считаем ok
  std::string low = to_lower(text);
  if (info.registrar.empty() && info.created.empty() && info.expires.empty() &&
      info.nameservers.empty() && low.find("domain") == std::string::npos)
    info.ok = false;
}

WhoisInfo whois_lookup(const std::string& domain, int timeout_ms,
                       std::string* err) {
  WhoisInfo out;
  auto query = [&](const std::string& server, const std::string& req,
                   std::string& resp) -> bool {
    std::string serr;
    UniqueFd fd = tcp_connect(server, 43, timeout_ms, serr);
    if (!fd.valid()) {
      if (err) *err = server + ": " + serr;
      return false;
    }
    if (!send_all(fd.get(), req + "\r\n", timeout_ms)) {
      if (err) *err = server + ": send failed";
      return false;
    }
    resp = read_available(fd.get(), timeout_ms, 128 * 1024);
    return !resp.empty();
  };

  // iana: шлём голое имя без "domain", refer: матчим только с начала строки
  size_t dot = domain.rfind('.');
  std::string tld = dot == std::string::npos ? "" : domain.substr(dot + 1);
  std::string server = "whois.iana.org";
  std::string resp;
  if (query("whois.iana.org", domain, resp)) {
    std::string lower = to_lower(resp);
    if (lower.find("error:") != std::string::npos) {
      resp.clear();  // rate-limit страница
    }
    size_t p = std::string::npos;
    size_t scan = 0;
    while ((scan = lower.find("refer:", scan)) != std::string::npos) {
      if (scan == 0 || lower[scan - 1] == '\n') {
        p = scan;
        break;
      }
      ++scan;
    }
    if (p != std::string::npos) {
      size_t e = lower.find('\n', p);
      std::string line = trim(resp.substr(p, e == std::string::npos
                                                 ? std::string::npos
                                                 : e - p));
      line = trim(line.substr(6));  // strip "refer:"
      if (!line.empty()) server = line;
    } else if (tld == "ru" || tld == "su" || tld == "рф" || tld == "xn--p1ai") {
      server = "whois.tcinet.ru";
    } else {
      server = "whois." + tld;
    }
  } else if (!tld.empty()) {
    // iana недоступна: фолбэки по большим реестрам
    if (tld == "ru" || tld == "su" || tld == "xn--p1ai") server = "whois.tcinet.ru";
    else if (tld == "de") server = "whois.denic.de";
    else if (tld == "uk") server = "whois.nic.uk";
    else if (tld == "io") server = "whois.nic.io";
    else server = "whois." + tld;
    resp.clear();
  }

  std::string resp2;
  std::string req = "domain " + domain;
  if (tld == "de") req = "-T dn,ace " + domain;  // DENIC syntax
  if (query(server, req, resp2)) {
    parse_whois_response(resp2, out);
  } else if (!resp.empty()) {
    parse_whois_response(resp, out);  // fall back to the IANA answer
  }

  // порт-43 часто пустой, добираем rdap
  if (out.registrar.empty() && out.created.empty() && out.expires.empty()) {
    HttpResponse r = polite_get("https://rdap.org/domain/" + domain, 20,
                                1024 * 1024);
    if (r.ok_network() && r.status == 200 && !r.body.empty())
      parse_rdap_response(r.body, out);
  }
  return out;
}

void parse_rdap_response(const std::string& body, WhoisInfo& out) {
  json j = json::parse(body, nullptr, false);
  if (j.is_discarded() || !j.is_object()) return;

  // регистратор = entity с ролью registrar, имя в vcard fn
  if (j.contains("entities") && j["entities"].is_array()) {
    for (const auto& ent : j["entities"]) {
      if (!ent.is_object()) continue;
      bool is_registrar = false, is_abuse = false;
      for (const auto& role : ent.value("roles", json::array()))
        if (role.is_string()) {
          if (role.get<std::string>() == "registrar") is_registrar = true;
          if (role.get<std::string>() == "abuse") is_abuse = true;
        }
      if (!is_registrar && !is_abuse) continue;
      if (ent.contains("vcardArray") && ent["vcardArray"].is_array() &&
          ent["vcardArray"].size() > 1 &&
          ent["vcardArray"][1].is_array()) {
        for (const auto& item : ent["vcardArray"][1]) {
          if (!item.is_array() || item.size() < 4 || !item[0].is_string())
            continue;
          std::string key = item[0].get<std::string>();
          if (key == "fn" && is_registrar && item[3].is_string() &&
              out.registrar.empty())
            out.registrar = item[3].get<std::string>();
          if (key == "email" && is_abuse && item[3].is_string()) {
            std::string e = to_lower(item[3].get<std::string>());
            if (!e.empty() &&
                std::find(out.emails.begin(), out.emails.end(), e) ==
                    out.emails.end())
              out.emails.push_back(e);
          }
        }
      }
    }
  }

  if (j.contains("events") && j["events"].is_array()) {
    for (const auto& ev : j["events"]) {
      if (!ev.is_object()) continue;
      std::string action = ev.value("eventAction", "");
      std::string date = ev.value("eventDate", "");
      if (date.size() >= 10) date = date.substr(0, 10);
      if (action == "registration" && out.created.empty())
        out.created = date;
      else if (action == "expiration" && out.expires.empty())
        out.expires = date;
      else if ((action == "last changed" || action == "last update of RDAP database") &&
               out.updated.empty())
        out.updated = date;
    }
  }

  if (j.contains("nameservers") && j["nameservers"].is_array()) {
    for (const auto& ns : j["nameservers"]) {
      if (!ns.is_object()) continue;
      std::string ldh = to_lower(ns.value("ldhName", ""));
      if (!ldh.empty() &&
          std::find(out.nameservers.begin(), out.nameservers.end(), ldh) ==
              out.nameservers.end())
        out.nameservers.push_back(ldh);
    }
  }

  if (!out.registrar.empty() || !out.created.empty() || !out.expires.empty())
    out.ok = true;
}

// ---- Geolocation --------------------------------------------------------------

void parse_geo_response(const std::string& body, GeoInfo& geo) {
  // плоский json, руками без nlohmann
  auto json_string = [&](const std::string& key) -> std::string {
    std::string pat = "\"" + key + "\"";
    size_t p = body.find(pat);
    if (p == std::string::npos) return "";
    p = body.find(':', p + pat.size());
    if (p == std::string::npos) return "";
    ++p;
    while (p < body.size() && (body[p] == ' ' || body[p] == '\t')) ++p;
    if (p >= body.size()) return "";
    if (body[p] == '"') {
      size_t e = body.find('"', p + 1);
      if (e == std::string::npos) return "";
      return body.substr(p + 1, e - p - 1);
    }
    size_t e = p;
    while (e < body.size() &&
           (std::isdigit(static_cast<unsigned char>(body[e])) || body[e] == '.' ||
            body[e] == '-' || body[e] == '+' || body[e] == 'e'))
      ++e;
    return body.substr(p, e - p);
  };

  std::string status = to_lower(json_string("status"));
  if (status == "fail") return;          // ip-api failure shape
  std::string success = json_string("success");
  if (success == "false") return;        // ipwho.is failure shape

  geo.country = json_string("country");
  geo.region = json_string("regionName").empty() ? json_string("region")
                                                 : json_string("regionName");
  geo.city = json_string("city");
  std::string lat = json_string("latitude");
  if (lat.empty()) lat = json_string("lat");
  std::string lon = json_string("longitude");
  if (lon.empty()) lon = json_string("lon");
  if (!lat.empty()) geo.lat = std::strtod(lat.c_str(), nullptr);
  if (!lon.empty()) geo.lon = std::strtod(lon.c_str(), nullptr);
  // ipwho.is: "connection":{"asn":13335,"org":"..."}; ip-api: "as":"AS13335 ..."
  std::string asn = json_string("asn");
  std::string org = json_string("org");
  std::string as = json_string("as");
  if (as.find(' ') != std::string::npos) {
    if (asn.empty()) asn = as.substr(0, as.find(' '));
    if (org.empty()) org = as.substr(as.find(' ') + 1);
  }
  if (!asn.empty() && !starts_with(to_upper(asn), "AS"))
    asn = "AS" + asn;
  geo.asn = asn;
  geo.org = org;
  geo.ok = !geo.country.empty() || !geo.asn.empty() || !geo.org.empty();
}

GeoInfo geo_lookup(const std::string& ip, const std::string& cache_dir,
                   int timeout_s, std::string* err) {
  namespace fs = std::filesystem;
  fs::path cf = fs::path(cache_dir) / "geo" / (ip + ".json");
  std::string body;
  if (load_cache_file(cf, std::chrono::hours(24), body)) {
    GeoInfo g;
    parse_geo_response(body, g);
    if (g.ok) return g;
  }
  GeoInfo g;
  std::string e;
  HttpResponse r = polite_get("https://ipwho.is/" + ip, timeout_s);
  if (r.ok_network() && r.status == 200) {
    parse_geo_response(r.body, g);
    if (g.ok) {
      store_cache_file(cf, r.body);
      return g;
    }
    e = "ipwho.is: no data";
  } else {
    e = "ipwho.is: " +
        (r.error.empty() ? "HTTP " + std::to_string(r.status) : r.error);
  }
  // ip-api: без https, зато без ключа
  HttpResponse r2 = polite_get(
      "http://ip-api.com/json/" + ip +
          "?fields=status,country,regionName,city,lat,lon,as,org",
      timeout_s);
  if (r2.ok_network() && r2.status == 200) {
    parse_geo_response(r2.body, g);
    if (g.ok) {
      store_cache_file(cf, r2.body);
      return g;
    }
  }
  if (err) *err = e;
  return g;
}

// ---- Exploit-DB ---------------------------------------------------------------

std::vector<std::string> extract_cve_ids(const std::string& text) {
  std::vector<std::string> out;
  size_t i = 0;
  while (i + 4 <= text.size()) {
    if ((text[i] == 'C' || text[i] == 'c') &&
        (text[i + 1] == 'V' || text[i + 1] == 'v') &&
        (text[i + 2] == 'E' || text[i + 2] == 'e') && text[i + 3] == '-') {
      size_t p = i + 4;
      std::string year, seq;
      while (p < text.size() &&
             std::isdigit(static_cast<unsigned char>(text[p])))
        year.push_back(text[p++]);
      if (year.size() == 4 && p < text.size() && text[p] == '-') {
        ++p;
        while (p < text.size() &&
               std::isdigit(static_cast<unsigned char>(text[p])) &&
               seq.size() < 7)
          seq.push_back(text[p++]);
        if (!seq.empty()) {
          std::string id = "CVE-" + year + "-" + seq;
          if (std::find(out.begin(), out.end(), id) == out.end())
            out.push_back(id);
        }
      }
      i += 4;
    } else {
      ++i;
    }
  }
  return out;
}

void parse_exploitdb_csv(const std::string& csv,
                         std::map<std::string, std::vector<EdbEntry>>& out) {
  // Columns: id,file,description,date_published,author,type,platform,port
  size_t pos = 0;
  // skip header line
  size_t nl = csv.find('\n');
  if (nl == std::string::npos) return;
  pos = nl + 1;

  // поле csv, кавычки учитываем
  auto next_field = [&](const std::string& line, size_t& p) -> std::string {
    if (p >= line.size()) return "";
    if (line[p] == '"') {
      std::string v;
      ++p;
      while (p < line.size()) {
        if (line[p] == '"') {
          if (p + 1 < line.size() && line[p + 1] == '"') {
            v.push_back('"');
            p += 2;
            continue;
          }
          ++p;
          break;
        }
        v.push_back(line[p++]);
      }
      if (p < line.size() && line[p] == ',') ++p;
      return v;
    }
    size_t e = line.find(',', p);
    if (e == std::string::npos) e = line.size();
    std::string v = line.substr(p, e - p);
    p = e < line.size() ? e + 1 : e;
    return v;
  };

  while (pos < csv.size()) {
    size_t eol = csv.find('\n', pos);
    if (eol == std::string::npos) eol = csv.size();
    std::string line = csv.substr(pos, eol - pos);
    pos = eol + 1;
    if (line.empty() || line[0] == '#') continue;
    size_t p = 0;
    EdbEntry e;
    e.id = next_field(line, p);
    e.file = next_field(line, p);
    e.description = next_field(line, p);
    e.date = next_field(line, p);
    next_field(line, p);   // author
    e.type = next_field(line, p);
    e.platform = next_field(line, p);
    // у gitlab-формата дальше ещё 4 колонки + codes с cve
    std::string codes;
    for (int extra = 0; extra < 4; ++extra) next_field(line, p);
    codes = next_field(line, p);
    if (e.id.empty()) continue;
    std::vector<std::string> cves = extract_cve_ids(e.description);
    for (const auto& c : extract_cve_ids(codes))
      if (std::find(cves.begin(), cves.end(), c) == cves.end())
        cves.push_back(c);
    for (const auto& cve : cves) {
      auto& list = out[cve];
      if (list.size() < 20 &&
          std::find_if(list.begin(), list.end(), [&](const EdbEntry& x) {
            return x.id == e.id;
          }) == list.end())
        list.push_back(e);
    }
  }
}

bool load_exploit_index(const std::string& cache_dir,
                        std::map<std::string, std::vector<EdbEntry>>& index,
                        std::string& err) {
  namespace fs = std::filesystem;
  fs::path cf = fs::path(cache_dir) / "exploitdb" / "files_exploits.csv";
  std::string body;
  if (load_cache_file(cf, std::chrono::hours(24), body)) {
    parse_exploitdb_csv(body, index);
    return true;
  }
  // индекс на gitlab, github пути 404; файл ~10 МБ, кап поднят
  HttpResponse r = polite_get(
      "https://gitlab.com/exploit-database/exploitdb/-/raw/main/"
      "files_exploits.csv",
      60, 64 * 1024 * 1024);
  if (!r.ok_network() || r.status != 200) {
    err = "Exploit-DB index fetch failed: " +
          (r.error.empty() ? "HTTP " + std::to_string(r.status) : r.error);
    return false;
  }
  store_cache_file(cf, r.body);
  parse_exploitdb_csv(r.body, index);
  return true;
}

// ---- OpenPhish ---------------------------------------------------------------

void parse_openphish_feed(const std::string& text,
                          std::vector<PhishEntry>& out) {
  std::istringstream iss(text);
  std::string line;
  while (std::getline(iss, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.empty() || line[0] == '#') continue;
    size_t scheme = line.find("://");
    if (scheme == std::string::npos) continue;
    size_t hs = scheme + 3;
    if (hs >= line.size()) continue;
    size_t he = line.find('/', hs);
    std::string host = line.substr(hs, he == std::string::npos
                                           ? std::string::npos
                                           : he - hs);
    size_t at = host.rfind('@');
    if (at != std::string::npos) host = host.substr(at + 1);
    size_t colon = host.find(':');
    if (colon != std::string::npos) host = host.substr(0, colon);
    host = to_lower(host);
    if (host.empty()) continue;
    PhishEntry e;
    e.url = line;
    e.host = host;
    out.push_back(std::move(e));
  }
}

bool load_openphish_feed(const std::string& cache_dir,
                         std::vector<PhishEntry>& feed, std::string& err) {
  namespace fs = std::filesystem;
  fs::path cf = fs::path(cache_dir) / "openphish" / "feed.txt";
  std::string body;
  if (load_cache_file(cf, std::chrono::hours(6), body)) {
    parse_openphish_feed(body, feed);
    return true;
  }
  // просим финальный url напрямую
  HttpResponse r = polite_get(
      "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/"
      "main/feed.txt",
      30, 8 * 1024 * 1024);
  if (!r.ok_network() || r.status != 200) {
    err = "OpenPhish feed fetch failed: " +
          (r.error.empty() ? "HTTP " + std::to_string(r.status) : r.error);
    return false;
  }
  store_cache_file(cf, r.body);
  parse_openphish_feed(r.body, feed);
  return true;
}

std::vector<PhishEntry> openphish_check(const std::vector<PhishEntry>& feed,
                                        const std::string& host) {
  std::vector<PhishEntry> out;
  std::string lh = to_lower(host);
  for (const auto& e : feed) {
    if (e.host == lh) {
      out.push_back(e);
      if (out.size() >= 10) break;
    }
  }
  return out;
}

// ---- Feodo Tracker ----------------------------------------------------------

void parse_feodo_blocklist(const std::string& text,
                           std::vector<std::string>& out) {
  std::istringstream iss(text);
  std::string line;
  while (std::getline(iss, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    line = trim(line);
    if (line.empty() || line[0] == '#') continue;
    // бывает csv, берём первое поле
    size_t comma = line.find(',');
    if (comma != std::string::npos) line = line.substr(0, comma);
    line = trim(line);
    sockaddr_in sa4{};
    sockaddr_in6 sa6{};
    if (inet_pton(AF_INET, line.c_str(), &sa4.sin_addr) == 1 ||
        inet_pton(AF_INET6, line.c_str(), &sa6.sin6_addr) == 1)
      out.push_back(line);
  }
}

bool load_feodo_feed(const std::string& cache_dir,
                     std::vector<std::string>& ips, std::string& err) {
  namespace fs = std::filesystem;
  fs::path cf = fs::path(cache_dir) / "feodo" / "ipblocklist_recommended.txt";
  std::string body;
  if (load_cache_file(cf, std::chrono::hours(1), body)) {
    parse_feodo_blocklist(body, ips);
    return true;
  }
  HttpResponse r = polite_get(
      "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
      30, 4 * 1024 * 1024);
  if (!r.ok_network() || r.status != 200) {
    err = "Feodo Tracker blocklist fetch failed: " +
          (r.error.empty() ? "HTTP " + std::to_string(r.status) : r.error);
    return false;
  }
  store_cache_file(cf, r.body);
  parse_feodo_blocklist(r.body, ips);
  return true;
}

bool feodo_check(const std::vector<std::string>& blocklist,
                 const std::vector<std::string>& ips) {
  for (const auto& ip : ips)
    if (std::find(blocklist.begin(), blocklist.end(), ip) != blocklist.end())
      return true;
  return false;
}

}  // namespace mikto
