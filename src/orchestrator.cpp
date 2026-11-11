// модули по зависимостям
#include "mikto/orchestrator.hpp"

#include <atomic>
#include <chrono>
#include <iostream>
#include <set>
#include <thread>

#include "mikto/config.hpp"
#include "mikto/http_client.hpp"
#include "mikto/intel_graph.hpp"
#include "mikto/module.hpp"
#include "mikto/providers.hpp"
#include "mikto/rate_limiter.hpp"
#include "mikto/scan_result.hpp"
#include "mikto/util.hpp"
#include "mikto/win_compat.hpp"
#include "modules/modules.hpp"

namespace mikto {

// ---- ModuleContext ----

void ModuleContext::log(const std::string& msg) const {
  if (cfg.verbose)
    std::cerr << "[mikto] " << msg << "\n";
}

void ModuleContext::warn(const std::string& msg) const {
  std::cerr << "[mikto:warn] " << msg << "\n";
}

void ModuleContext::pstage(const std::string& module, const std::string& label,
                           size_t total) const {
  if (progress) progress->stage(module, label, total);
}

void ModuleContext::pgrow(size_t n) const {
  if (progress) progress->grow_total(n);
}

void ModuleContext::ptick(size_t n) const {
  if (progress) progress->tick(n);
}

void ModuleContext::pitem(const std::string& text) const {
  if (progress) progress->item(text);
}

void ModuleContext::pdone() const {
  if (progress) progress->done();
}

void ModuleContext::parallel(size_t n, const std::function<void(size_t)>& fn,
                             int cap) const {
  if (n == 0) return;
  int workers = std::min<int>(std::max(1, cfg.concurrency), std::max(1, cap));
  size_t wn = std::min<size_t>(static_cast<size_t>(workers), n);
  if (wn <= 1) {
    for (size_t i = 0; i < n; ++i) {
      try {
        fn(i);
      } catch (...) {
      }
    }
    return;
  }
  std::atomic<size_t> cursor{0};
  auto worker = [&] {
    for (;;) {
      size_t i = cursor.fetch_add(1);
      if (i >= n) break;
      try {
        fn(i);
      } catch (...) {
      }
    }
  };
  // jthread есть не везде — mikto_thread фолбэчится на обычный thread
  std::vector<mikto_thread> pool;
  pool.reserve(wn);
  for (size_t i = 0; i < wn; ++i) pool.emplace_back(worker);
  for (auto& t : pool) t.join();
}

void ModuleContext::trace(const std::string& kind, const std::string& target,
                          const std::string& request,
                          const std::string& response, long status,
                          size_t sent, size_t recv, double ms) {
  TrafficEvent ev;
  ev.module = current_module.empty() ? "scan" : current_module;
  ev.kind = kind;
  ev.target = target;
  ev.request = request;
  ev.response = response;
  ev.status = status;
  ev.sent = sent;
  ev.recv = recv;
  ev.ms = ms;
  result.record_trace(std::move(ev));
}

HttpResponse ModuleContext::get(const std::string& url,
                                const HttpOptions& opt) {
  // цели провайдерами не считаем, чужие хосты да
  std::string phost = provider_url_host(url);
  if (!phost.empty()) {
    bool is_target = false;
    for (const auto& t : cfg.targets)
      if (iequals(t.host, phost)) is_target = true;
    if (!is_target) {
      if (const ProviderInfo* pinfo = classify_provider(url, {}, phost))
        providers.set_name(phost, pinfo->name);
      int before = providers.blocked_count(phost);
      if (!providers.allow(phost)) {
        if (before == 0)
          warn("external provider '" + phost +
               "' failed too often or hit its per-scan request cap — "
               "further requests to it are skipped and affected results "
               "may be incomplete (recorded in the report)");
        HttpResponse blocked;
        blocked.error =
            "mikto provider breaker: request skipped (circuit open or "
            "per-provider request cap)";
        return blocked;
      }
    } else {
      phost.clear();  // target traffic: no provider accounting
    }
  }

  limiter.acquire();
  auto t0 = std::chrono::steady_clock::now();
  HttpResponse resp = http.get(url, opt);
  double ms =
      std::chrono::duration<double, std::milli>(
          std::chrono::steady_clock::now() - t0)
          .count();
  std::string req = "GET " + url + " (UA: " +
                    (opt.user_agent.empty() ? "default" : opt.user_agent) + ")";
  std::string resp_line =
      resp.ok_network()
          ? ("HTTP " + std::to_string(resp.status) + ", " +
             std::to_string(resp.body_bytes) + " B body")
          : ("error: " +
             (resp.error.empty() ? "status 0" : resp.error));
  trace("http", url, req, resp_line, resp.status, resp.req_bytes,
        resp.body_bytes + resp.req_bytes, ms);
  if (!phost.empty()) {
    if (resp.ok_network())
      providers.record_success(phost);
    else if (resp.status == 0 || resp.status >= 500 ||
             resp.status == 429)
      providers.record_failure(phost);  // transport / 5xx / throttling
    // прочие 4xx это живой ответ, не фейл
  }
  return resp;
}

WebResult& ModuleContext::fetch_web(const std::string& url,
                                    const HttpOptions& opt) {
  {
    std::lock_guard<std::mutex> g(web_mu_);
    auto it = web_cache_.find(url);
    if (it != web_cache_.end()) return it->second;
  }

  // сеть без блокировки: параллельные модули не должны ждать друг друга
  HttpResponse resp = get(url, opt);
  WebResult w;
  w.url = url;
  if (resp.ok_network()) {
    w.fetched = true;
    w.status = resp.status;
    w.headers = resp.headers;
    w.server = resp.header("Server");
    w.body = resp.body;
  } else {
    w.error = resp.error.empty() ? ("HTTP " + std::to_string(resp.status))
                                 : resp.error;
  }
  std::lock_guard<std::mutex> g(web_mu_);
  auto [it, inserted] = web_cache_.try_emplace(url, std::move(w));
  if (inserted) {
    // копия в result для репортеров (гонку дублирующих запросов выигрывает
    // первый, вторая копия не затирает результат)
    WebResult& stored = result.ensure_web(url);
    stored = it->second;
  }
  return it->second;
}

// ---- Orchestration ----------------------------------------------------------

int run_scan(const Config& cfg, ScanResult& result, std::string& err) {
  const auto scan_start = std::chrono::steady_clock::now();
  result.started_at = now_iso8601_utc();
  result.deep = cfg.deep;
  result.safe_mode = !cfg.deep;
  result.targets = cfg.targets;

  auto canonical = module_names();

  // план: выбор юзера + зависимости
  std::set<std::string> selected = cfg.all_modules
                                       ? std::set<std::string>(canonical.begin(),
                                                               canonical.end())
                                       : cfg.modules;
  for (const auto& name : selected) {
    if (std::find(canonical.begin(), canonical.end(), name) == canonical.end()) {
      err = "unknown module: " + name + " (run `mikto modules`)";
      return 1;
    }
  }

  std::set<std::string> plan = selected;
  for (const auto& name : selected) {
    auto mods = create_module(name);
    if (mods.empty()) continue;
    for (const auto& d : mods[0]->depends()) plan.insert(d);
  }

  HttpClient http;
  RateLimiter limiter(cfg.rate);
  ModuleContext ctx(cfg, result, http, limiter);
  Progress progress(!cfg.no_progress, !cfg.no_color);
  ctx.progress = &progress;

  for (const auto& name : plan) {
    if (std::find(selected.begin(), selected.end(), name) == selected.end())
      ctx.warn("module '" + name + "' enabled automatically as a dependency");
  }

  for (const auto& name : canonical) {
    if (!plan.count(name)) continue;
    auto mods = create_module(name);
    if (mods.empty()) continue;
    auto& module = mods[0];
    ctx.current_module = name;

    auto t0 = std::chrono::steady_clock::now();
    bool ok = false;
    try {
      ok = module->run(ctx);
    } catch (const std::exception& e) {
      ctx.warn("module '" + name + "' failed: " + e.what());
    } catch (...) {
      ctx.warn("module '" + name + "' failed: unknown exception");
    }
    double dt = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0)
                    .count();
    result.module_timings[name] = dt;
    if (ok) result.modules_run.push_back(name);
    else ctx.warn("module '" + name + "' did not complete");
  }

  result.finished_at = now_iso8601_utc();
  progress.finish();
  result.duration_s =
      std::chrono::duration<double>(std::chrono::steady_clock::now() - scan_start)
          .count();
  // граф собираем в самом конце
  ctx.current_module = "graph";
  result.intel.build(result);
  result.provider_stats = ctx.providers.snapshot();
  result.sort_findings();
  return 0;
}

}  // namespace mikto
