#include "mikto/scan_result.hpp"

#include "mikto/util.hpp"

namespace mikto {

std::string PortInfo::service_label() const {
  if (!product.empty()) {
    std::string label = product;
    if (!version.empty()) label += " " + version;
    return label;
  }
  return service.empty() ? "unknown" : service;
}

const char* PortInfo::confidence_label() const {
  switch (confidence) {
    case 3: return "confirmed";
    case 2: return "header";
    case 1: return "banner";
    default: return "guess";
  }
}

PortInfo* HostResult::port(uint16_t p) {
  for (auto& pi : ports)
    if (pi.port == p) return &pi;
  return nullptr;
}

const PortInfo* HostResult::port(uint16_t p) const {
  for (const auto& pi : ports)
    if (pi.port == p) return &pi;
  return nullptr;
}

std::string WebResult::header(const std::string& name) const {
  for (const auto& kv : headers)
    if (iequals(kv.first, name)) return kv.second;
  return "";
}

std::vector<std::string> WebResult::headers_all(
    const std::string& name) const {
  std::vector<std::string> out;
  for (const auto& kv : headers)
    if (iequals(kv.first, name)) out.push_back(kv.second);
  return out;
}

HostResult& ScanResult::ensure_host(const std::string& host, bool is_ip) {
  // зовут и из воркеров пула; push_back у deque не инвалидирует ссылки,
  // но сам контейнер защищаем от одновременной записи
  std::lock_guard<std::mutex> g(st_mu_);
  for (auto& h : hosts)
    if (h.host == host) return h;
  HostResult hr;
  hr.host = host;
  hr.is_ip = is_ip;
  hosts.push_back(std::move(hr));
  return hosts.back();
}

WebResult& ScanResult::ensure_web(const std::string& url) {
  std::lock_guard<std::mutex> g(st_mu_);
  for (auto& w : web)
    if (w.url == url) return w;
  WebResult wr;
  wr.url = url;
  web.push_back(std::move(wr));
  return web.back();
}

void ScanResult::record_trace(TrafficEvent ev) {
  std::lock_guard<std::mutex> g(trace_mu_);
  // кап, чтобы deep не съел память
  if (traffic.size() < 20000) traffic.push_back(std::move(ev));
  else ++trace_dropped_;
}

size_t ScanResult::trace_dropped_count() const {
  std::lock_guard<std::mutex> g(trace_mu_);
  return trace_dropped_;
}

std::vector<TrafficEvent> ScanResult::traffic_snapshot() const {
  std::lock_guard<std::mutex> g(trace_mu_);
  return traffic;
}

std::map<std::string, int> ScanResult::trace_counts() const {
  std::lock_guard<std::mutex> g(trace_mu_);
  std::map<std::string, int> m;
  for (const auto& t : traffic) m[t.kind]++;
  return m;
}

void ScanResult::add_finding(Finding f) {
  // дублей бывает куча (одна проверка на каждый ip/путь), давим: одна выживает,
  // локации остальных идут в evidence. мьютекс: зовут из воркеров
  std::lock_guard<std::mutex> g(st_mu_);
  for (auto& e : findings) {
    if (e.module == f.module && e.host == f.host && e.title == f.title) {
      ++e.duplicates;
      if (e.duplicates <= 3 && e.evidence.size() < 500)
        e.evidence +=
            e.evidence.empty() ? "also: " + f.location
                               : " | also: " + f.location;
      ++suppressed_duplicates_;
      return;
    }
  }
  findings.push_back(std::move(f));
}

size_t ScanResult::suppressed_duplicates_count() const {
  std::lock_guard<std::mutex> g(st_mu_);
  return suppressed_duplicates_;
}

void ScanResult::sort_findings() {
  std::stable_sort(findings.begin(), findings.end(),
                   [](const Finding& a, const Finding& b) {
                     if (a.severity != b.severity)
                       return static_cast<int>(a.severity) >
                              static_cast<int>(b.severity);
                     if (a.module != b.module) return a.module < b.module;
                     if (a.host != b.host) return a.host < b.host;
                     return a.port < b.port;
                   });
}

std::map<Severity, int> ScanResult::counts() const {
  std::map<Severity, int> m;
  for (Severity s : {Severity::Info, Severity::Low, Severity::Medium,
                     Severity::High, Severity::Critical})
    m[s] = 0;
  for (const auto& f : findings) m[f.severity]++;
  return m;
}

const HostResult* ScanResult::find_host(const std::string& host) const {
  std::lock_guard<std::mutex> g(st_mu_);
  for (const auto& h : hosts)
    if (h.host == host) return &h;
  return nullptr;
}

}  // namespace mikto
