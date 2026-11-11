// тесты scan result
#include "test_fw.hpp"

#include "mikto/scan_result.hpp"
#include "mikto/win_compat.hpp"

#include <atomic>
#include <thread>
#include <vector>

using namespace mikto;

MIKTO_TEST(scan_result_ensure_host_dedup) {
  ScanResult r;
  HostResult& a = r.ensure_host("h1.example", false);
  HostResult& b = r.ensure_host("h1.example", false);
  CHECK(&a == &b);
  CHECK_EQ(r.hosts.size(), size_t(1));
  r.ensure_host("h2.example", true);
  CHECK_EQ(r.hosts.size(), size_t(2));
}

MIKTO_TEST(scan_result_port_lookup) {
  ScanResult r;
  HostResult& h = r.ensure_host("h1.example", false);
  PortInfo p;
  p.port = 443;
  p.open = true;
  p.service = "https";
  h.ports.push_back(p);
  CHECK(h.port(443) != nullptr);
  CHECK(h.port(80) == nullptr);
  CHECK_EQ(h.port(443)->service, std::string("https"));
}

MIKTO_TEST(scan_result_sort_and_counts) {
  ScanResult r;
  Finding low;
  low.severity = Severity::Low;
  low.module = "ports";
  low.host = "a";
  Finding crit;
  crit.severity = Severity::Critical;
  crit.module = "exposed";
  crit.host = "b";
  Finding med;
  med.severity = Severity::Medium;
  med.module = "headers";
  med.host = "c";
  r.add_finding(low);
  r.add_finding(crit);
  r.add_finding(med);
  r.sort_findings();
  CHECK_EQ(r.findings[0].severity, Severity::Critical);
  CHECK_EQ(r.findings[1].severity, Severity::Medium);
  CHECK_EQ(r.findings[2].severity, Severity::Low);
  auto counts = r.counts();
  CHECK_EQ(counts[Severity::Critical], 1);
  CHECK_EQ(counts[Severity::Info], 0);
  int total = 0;
  for (auto& kv : counts) total += kv.second;
  CHECK_EQ(total, 3);
}

MIKTO_TEST(port_info_label) {
  PortInfo p;
  p.product = "nginx";
  p.version = "1.25.3";
  CHECK_EQ(p.service_label(), std::string("nginx 1.25.3"));
  p.product = "";
  p.service = "redis";
  CHECK_EQ(p.service_label(), std::string("redis"));
  p.service = "";
  CHECK_EQ(p.service_label(), std::string("unknown"));
}

MIKTO_TEST(trace_drop_counter_is_honest) {
  // кап 20000: дропы считаются, а не теряются
  ScanResult r;
  for (int i = 0; i < 20005; ++i) {
    TrafficEvent ev;
    ev.kind = "http";
    ev.target = "test-" + std::to_string(i);
    r.record_trace(std::move(ev));
  }
  CHECK_EQ(r.traffic_snapshot().size(), size_t(20000));
  CHECK_EQ(r.trace_dropped_count(), size_t(5));
}

MIKTO_TEST(scan_result_thread_safety) {
  // воркеры пула зовут ensure_host/ensure_web/add_finding одновременно;
  // регресс на сегфолт: push_back в контейнер из нескольких потоков
  ScanResult r;
  constexpr int kThreads = 8;
  constexpr int kPerThread = 400;
  {
    std::vector<mikto_thread> pool;
    std::atomic<int> go{0};
    for (int t = 0; t < kThreads; ++t)
      pool.emplace_back([&r, &go, t] {
        while (go.load() == 0) {}  // стартуем синхронно, гонка честная
        for (int i = 0; i < kPerThread; ++i) {
          // 16 разных находок: дедуп давит повторы внутри и между потоками
          Finding f;
          f.severity = Severity::Low;
          f.module = "test";
          f.host = "h" + std::to_string((t * kPerThread + i) % 16);
          f.title = "dup";
          r.add_finding(std::move(f));
          r.ensure_host("host-" + std::to_string(i % 24), false);
          r.ensure_web("https://x/" + std::to_string(i % 32));
          // держим ссылку на живой элемент во время роста контейнера
          HostResult& held = r.ensure_host("host-" + std::to_string(i % 24), false);
          (void)held.host.size();
        }
      });
    go.store(1);
    for (auto& t : pool) t.join();
  }
  CHECK_EQ(r.hosts.size(), size_t(24));
  CHECK_EQ(r.web.size(), size_t(32));
  // 16 уникальных (module,host,title), остальные давятся дедупом
  CHECK_EQ(r.findings.size(), size_t(16));
  CHECK_EQ(r.suppressed_duplicates_count(),
           size_t(kThreads * kPerThread - 16));
  // сортировка не падает; выжившие находки — только уникальные
  r.sort_findings();
  CHECK_EQ(r.counts()[Severity::Low], 16);
}

MIKTO_TEST(scan_result_deque_reference_stability) {
  // deque: push_back не инвалидирует ссылки — держатель HostResult&
  // из воркера не остаётся с висячей ссылкой, когда растёт hosts
  ScanResult r;
  HostResult& first = r.ensure_host("first", false);
  const std::string* first_name = &first.host;
  for (int i = 0; i < 5000; ++i)
    r.ensure_host("growing-" + std::to_string(i), false);
  CHECK(first_name == &first.host);
  CHECK_EQ(*first_name, std::string("first"));
  CHECK_EQ(r.hosts.size(), size_t(5001));
}
