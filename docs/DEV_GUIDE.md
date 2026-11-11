# Developer guide — how mikto is put together

Everything you need to modify mikto or add your own module. Read the
[ethics contract](RESPONSIBLE_USE.md) first: modules must stay read-only and
scope-limited, that is enforced socially (code review) and architecturally
(the module interface has no scope-expanding API).

## Repository layout

```
include/mikto/   public API of the core: types, finding, target, config,
                 net (raw TCP), dns (RFC 1035 client), http_client (libcurl),
                 tls, osint (whois/geo/exploitdb/urlhaus), scan_result,
                 module (IModule + ModuleContext), progress, rate_limiter,
                 providers, intel_graph, scan_diff, cve_db, reporter,
                 orchestrator, version, win_compat
src/             implementations of the above + cli (arg parsing, banner)
src/modules/     one file per module + web_common (shared web helpers) +
                 modules.hpp (pure testable helpers) + registry.cpp
src/reporters/   console / json / html / sarif / csv; html builds one
                 self-contained page from html_report_css.inc + html_report_js.inc
tests/           dependency-free unit tests (152 tests / 1422 checks)
third_party/     vendored nlohmann/json (single header, MIT)
docs/            guides, comparison, responsible use, roadmap, audit
```

## Build, test, repeat

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/mikto_tests                     # 1422 checks in ~0.5 s
./build/mikto scan <your-target> --html r.html
```

Options: `-DMIKTO_WERROR=ON` (warnings as errors), `-DMIKTO_BUILD_TESTS=OFF`
(faster builds on CI). The test binary is plain C++, no framework — look at
`tests/test_fw.hpp` for the tiny macro set (`CHECK`, `RUN`).

## Data flow (how a scan works)

1. `cli.cpp` parses argv into `Config` (strict target validation, `--deep`
   confirmation handled in `main.cpp`).
2. `orchestrator.cpp` `run_scan()` asks the registry for module instances,
   topologically sorts them by `depends()` and runs each in a worker with
   exceptions caught per module.
3. Each module gets a `ModuleContext`: shared `HttpClient` (libcurl, single
   connection pool), shared `RateLimiter` (token bucket), `Progress` display,
   `ProviderTracker` (per-source accounting + circuit breaker).
4. Modules write structured data into `ScanResult` (hosts, ports, dns
   records, tech, paths, subdomains, emails…) and raise issues via
   `result.add_finding(...)`.
5. After the modules, the orchestrator derives the **intelligence graph**
   (`intel_graph.cpp`) from the collected data — nodes/edges with sources,
   confidence and status.
6. Reporters serialize the same `ScanResult` five ways (console/json/html/
   sarif/csv). Reporters never invent data — they render what was collected,
   including caps and accounting.

## Adding a module (the 4-file recipe)

Say you want a module `cmscheck` that checks one read-only path per target.

**1. Create `src/modules/cmscheck.cpp`:**

```cpp
// mikto — пример модуля: один read-only GET на цель
#include "modules.hpp"

#include "mikto/module.hpp"
#include "mikto/scan_result.hpp"

namespace mikto {

namespace {
class CmscheckModule : public IModule {
 public:
  std::string name() const override { return "cmscheck"; }
  std::string description() const override {
    return "one read-only probe demonstrating a custom module";
  }
  Maturity maturity() const override { return Maturity::Preview; }
  // если вашему модулю нужны DNS-записи или скачанные страницы —
  // перечислите зависимости, оркестратор отсортирует сам
  std::vector<std::string> depends() const override { return {"assets", "tech"}; }

  bool run(ModuleContext& ctx) override {
    for (const auto& h : ctx.result.hosts) {
      if (h.url.empty()) continue;                       // не веб — пропускаем
      HttpResponse r = ctx.get(h.url + "/_healthz.txt", {{"User-Agent", "mikto (+responsible use)"}});
      if (r.status == 200) {
        Finding f;
        f.severity = Severity::Info;
        f.module = name();
        f.host = h.host;
        f.location = h.url + "/_healthz.txt";
        f.title = "health marker found";
        f.detail = "the page announces a health endpoint; harmless but informative";
        f.recommendation = "nothing to fix, this is a demonstration finding";
        ctx.result.add_finding(std::move(f));
      }
    }
    return true;
  }
};
}  // namespace

std::unique_ptr<IModule> make_cmscheck_module() {
  return std::make_unique<CmscheckModule>();
}

}  // namespace mikto
```

**2. Register it in `src/modules/modules.hpp`** (declaration near the others):

```cpp
std::unique_ptr<IModule> make_cmscheck_module();
```

**3. Register it in `src/modules/registry.cpp`:**

* add `"cmscheck"` to the `module_names()` list **in the run order you want**
  (the order in this list is the canonical order);
* add a `make_cmscheck_module()` call to `create_module()`.

**4. Add the file to `CMakeLists.txt`** (`mikto_core` sources) and, if you
wrote pure helpers, a test file to `tests/` + `mikto_tests` sources.

Build and run: `cmake --build build -j && ./build/mikto modules` — your
module appears in the table and runs with the rest. `--modules cmscheck`
runs it alone.

## Module rules (enforced by review, please keep them)

* **read-only**: GET/head-like interactions only; no POST/payloads, no login
  attempts, no mutation of target state.
* **scope-locked**: interact only with hosts/targets that passed validation.
  Discoveries (subdomains, neighbours, SAN names) go to the report, not to
  the scanner.
* **honest output**: a finding must carry location, detail and
  recommendation; evidence gets redacted; unverifiable claims stay
  `unverified`/`possible`.
* **account external requests**: go through `ctx.get()` / the provider
  tracker so rate limiting, traffic log and circuit breakers see your calls.
* **degrade, don't crash**: exceptions are caught per module, but prefer
  `ctx.warn(...)` + returning `true` when a source is unavailable.

## Where to change what (common tasks)

* **Add a CLI flag** → `src/cli.hpp`/`src/cli.cpp` (`parse_cli`), wire it
  into `Config` (`include/mikto/config.hpp`), maybe re-tune deep-mode
  defaults at the bottom of `cli.cpp`.
* **Add a data source** → keyless: follow `infra.cpp` style; add the
  provider row to `src/providers.cpp` (name, endpoint, env vars, limits) so
  `mikto providers` and the health panel show it.
* **Extend fingerprinting** → `src/modules/tech.cpp` marker tables; keep
  markers passive (no probes) unless you add a documented read-only probe.
* **Extend CVE coverage** → `src/cve_db.cpp` CPE map; exact `virtualMatchString`
  prefixes, no keyword soup.
* **New report section** → reporters render what `ScanResult` carries; if
  your data needs a new home, add a field to `ScanResult`
  (`include/mikto/scan_result.hpp`) and fill it in your module.
* **HTML report JS/CSS** → `src/reporters/html_report_*.inc`; it must stay
  dependency-free and self-contained (tests check for external URLs).
* **Wordlists / caps** → `webpaths.cpp` constants; keep every cap stated in
  the report.

## Testing style

* Pure helpers live in `modules.hpp` / `modules/*.cpp` as free functions —
  test those, no network.
* Network-dependent logic gets thin seams (parse functions for WHOIS, geo,
  feeds, DNS wire format).
* `tests/test_reporters.cpp` guards HTML self-containment and XSS escaping —
  keep it green when you touch the HTML reporter.
* Add checks, not framework magic: `CHECK(cond)` + a short name in `RUN`.

## Windows notes for contributors

`include/mikto/win_compat.hpp` maps sockets/isatty between POSIX and Winsock
(`WSAPoll`, `closesocket`, `WsaInit`). New socket code should include
`win_compat.hpp` and use `sock_close / sock_errno / sock_err_str /
mikto_socklen_t / MIKTO_*` macros instead of raw POSIX names. MSVC builds
with `/utf-8` — keep source files UTF-8 and avoid non-ASCII in printf
format strings.
