#pragma once
// контракт модулей: scope не расширяем, цель не меняем, вопрос = finding
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "http_client.hpp"
#include "progress.hpp"
#include "providers.hpp"
#include "scan_result.hpp"

namespace mikto {

class ScanResult;
struct Config;
class RateLimiter;

enum class Maturity { Reference, Preview };
const char* maturity_name(Maturity m);

class ModuleContext {
 public:
  ModuleContext(const Config& cfg, ScanResult& result, HttpClient& http,
                RateLimiter& limiter)
      : cfg(cfg), result(result), http(http), limiter(limiter) {}

  const Config& cfg;
  ScanResult& result;
  HttpClient& http;
  RateLimiter& limiter;
  Progress* progress = nullptr;  // владеет оркестратор, бывает null

  // аккаунтинг + breaker по внешним провайдерам
  ProviderTracker providers;

  // кто сейчас работает, ставит оркестратор
  std::string current_module;

  void log(const std::string& msg) const;   // shown with --verbose
  void warn(const std::string& msg) const;  // always shown

  // GET с лимитом, событие пишется в traffic
  HttpResponse get(const std::string& url, const HttpOptions& opt = {});

  void trace(const std::string& kind, const std::string& target,
             const std::string& request, const std::string& response,
             long status, size_t sent, size_t recv, double ms);

  void pstage(const std::string& module, const std::string& label,
              size_t total) const;
  // увеличить total текущего этапа (объём стал известен позже);
  // вызывать ДО ptick за новую работу — счётчик не переполняется
  void pgrow(size_t n = 1) const;
  void ptick(size_t n = 1) const;
  void pitem(const std::string& text) const;
  void pdone() const;

  // параллельный прогон fn(i), i in [0,n): пул min(cfg.concurrency, cap)
  // воркеров (--thread/--concurrency); n мал или cap<=1 — последовательно.
  // fn не должен бросать; исключения глотаются, работа не падает
  void parallel(size_t n, const std::function<void(size_t)>& fn,
                int cap = 64) const;

  // страница качается не чаще раза за скан, копия в result.web
  WebResult& fetch_web(const std::string& url, const HttpOptions& opt = {});

 private:
  std::map<std::string, WebResult> web_cache_;
  mutable std::mutex web_mu_;  // fetch_web зовут из пула потоков
};

class IModule {
 public:
  virtual ~IModule() = default;

  virtual std::string name() const = 0;
  virtual std::string description() const = 0;
  virtual Maturity maturity() const = 0;
  // что должно отработать раньше
  virtual std::vector<std::string> depends() const { return {}; }

  // false = модуль упал, уже залогировано
  virtual bool run(ModuleContext& ctx) = 0;
};

// реестр в modules/registry.cpp
std::vector<std::string> module_names();                  // canonical order
std::vector<std::unique_ptr<IModule>> create_module(const std::string& name);
std::string modules_help_table();  // formatted for `mikto modules`

}  // namespace mikto
