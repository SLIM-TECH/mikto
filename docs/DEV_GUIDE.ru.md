# Гайд разработчика — как устроен mikto

Всё, чтобы править mikto или добавить свой модуль. Сначала прочитай
[этический контракт](RESPONSIBLE_USE.ru.md): модули обязаны оставаться
read-only и scope-ограниченными — это держится и на ревью, и архитектурно
(у интерфейса модуля нет API для расширения scope).

## Структура репозитория

```
include/mikto/   публичное API ядра: types, finding, target, config,
                 net (raw TCP), dns (RFC 1035 клиент), http_client (libcurl),
                 tls, osint (whois/geo/exploitdb/urlhaus), scan_result,
                 module (IModule + ModuleContext), progress, rate_limiter,
                 providers, intel_graph, scan_diff, cve_db, reporter,
                 orchestrator, version, win_compat
src/             реализации всего этого + cli (парсинг аргументов, баннер)
src/modules/     файл на модуль + web_common (общие веб-хелперы) +
                 modules.hpp (чистые тестируемые хелперы) + registry.cpp
src/reporters/   console / json / html / sarif / csv; html собирает один
                 самодостаточный файл из html_report_css.inc + html_report_js.inc
tests/           юнит-тесты без зависимостей (152 теста / 1422 проверки)
third_party/     vendored nlohmann/json (один заголовок, MIT)
docs/            гайды, сравнение, ответственное использование, роадмап, аудит
```

## Собрать, протестить, повторить

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/mikto_tests                     # 1422 проверки за ~0.5 с
./build/mikto scan <твоя-цель> --html r.html
```

Опции: `-DMIKTO_WERROR=ON` (предупреждения как ошибки),
`-DMIKTO_BUILD_TESTS=OFF` (быстрее на CI). Тестовый бинарник — чистый C++
без фреймворка, макросы глянь в `tests/test_fw.hpp` (`CHECK`, `RUN`).

## Поток данных (как устроен скан)

1. `cli.cpp` парсит argv в `Config` (строгая валидация целей, подтверждение
   `--deep` — в `main.cpp`).
2. `orchestrator.cpp` `run_scan()` берёт у реестра экземпляры модулей,
   топологически сортирует по `depends()` и гонит каждый в воркере с ловлей
   исключений на модуль.
3. Каждый модуль получает `ModuleContext`: общий `HttpClient` (libcurl,
   общий пул соединений), общий `RateLimiter` (token bucket), `Progress`,
   `ProviderTracker` (учёт по источникам + предохранитель).
4. Модули пишут структурированные данные в `ScanResult` (хосты, порты, DNS,
   tech, пути, субдомены, e-mail'ы…) и поднимают проблемы через
   `result.add_finding(...)`.
5. После модулей оркестратор строит **граф разведки** (`intel_graph.cpp`) из
   собранного — вершины/рёбра с источниками, уверенностью и статусом.
6. Репортеры сериализуют один и тот же `ScanResult` пятью способами
   (console/json/html/sarif/csv). Репортеры ничего не придумывают — они
   рендерят собранное, включая капы и учёт.

## Свой модуль (рецепт на 4 файла)

Пусть нужен модуль `cmscheck`, который делает один read-only GET на цель.

**1. Создай `src/modules/cmscheck.cpp`:**

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
  // если нужны DNS-записи или скачанные страницы — перечисли зависимости,
  // оркестратор сам отсортирует
  std::vector<std::string> depends() const override { return {"assets", "tech"}; }

  bool run(ModuleContext& ctx) override {
    for (const auto& h : ctx.result.hosts) {
      if (h.url.empty()) continue;                       // не веб — пропускаем
      HttpResponse r = ctx.get(h.url + "/_healthz.txt");
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

**2. Зарегистрируй в `src/modules/modules.hpp`** (декларация рядом с другими):

```cpp
std::unique_ptr<IModule> make_cmscheck_module();
```

**3. Зарегистрируй в `src/modules/registry.cpp`:**

* добавь `"cmscheck"` в список `module_names()` **в нужном порядке запуска**
  (порядок в списке = канонический порядок);
* добавь вызов `make_cmscheck_module()` в `create_module()`.

**4. Добавь файл в `CMakeLists.txt`** (исходники `mikto_core`), а если
написал чистые хелперы — и тест в `tests/` + в список `mikto_tests`.

Собери и глянь: `cmake --build build -j && ./build/mikto modules` — модуль
появится в таблице и пойдёт с остальными. `--modules cmscheck` гонит его
одного.

## Правила модулей (фиксируются на ревью, сохрани их)

* **read-only**: только GET/HEAD-подобные взаимодействия; без POST/пейлоадов,
  без попыток логина, без изменения состояния цели.
* **scope-locked**: ходим только на хосты/цели, прошедшие валидацию.
  Находки (субдомены, соседи, имена из SAN) — в отчёт, не в сканер.
* **честный вывод**: у находки должны быть location, detail и
  recommendation; evidence маскируется; непроверяемое остаётся
  `unverified`/`possible`.
* **учитывай внешние запросы**: ходи через `ctx.get()` / трекер провайдеров,
  чтобы лимитер, журнал трафика и предохранители видели твои вызовы.
* **деградируй, а не падай**: исключения ловятся на модуль, но при недоступном
  источнике лучше `ctx.warn(...)` + `return true`.

## Где что менять (частые задачи)

* **Новый CLI-флаг** → `src/cli.hpp`/`src/cli.cpp` (`parse_cli`), проводим в
  `Config` (`include/mikto/config.hpp`), при желании — дефолты deep-режима в
  низу `cli.cpp`.
* **Новый источник данных** → без ключей: по образцу `infra.cpp`; добавь
  строку провайдера в `src/providers.cpp` (имя, эндпоинт, env-переменные,
  лимиты) — тогда `mikto providers` и панель здоровья покажут его.
* **Расширить фингерпринтинг** → таблицы маркеров в `src/modules/tech.cpp`;
  маркеры пассивные (без проб), если только это не задокументированная
  read-only проба.
* **Расширить покрытие CVE** → карта CPE в `src/cve_db.cpp`; точные префиксы
  `virtualMatchString`, без ключевых слов наугад.
* **Новый раздел отчёта** → репортеры рендерят то, что несёт `ScanResult`;
  если данным нужно новое место — добавь поле в `ScanResult`
  (`include/mikto/scan_result.hpp`) и заполняй его в своём модуле.
* **JS/CSS HTML-отчёта** → `src/reporters/html_report_*.inc`; держим без
  зависимостей и самодостаточным (тесты проверяют внешние URL).
* **Словари / капы** → константы в `webpaths.cpp`; каждый кап должен быть
  помечен в отчёте.

## Стиль тестов

* Чистые хелперы живут в `modules.hpp` / `modules/*.cpp` как свободные
  функции — тестируем их, без сети.
* Сетевая логика отгрызается тонкими швами (функции парсинга WHOIS, гео,
  фидов, DNS-формата).
* `tests/test_reporters.cpp` сторожит самодостаточность HTML и
  XSS-экранирование — держи зелёным при правке HTML-репортера.
* Добавляй проверки, а не магию фреймворка: `CHECK(cond)` + короткое имя в
  `RUN`.

## Windows-заметки для контрибьюторов

`include/mikto/win_compat.hpp` маппит сокеты/isatty между POSIX и Winsock
(`WSAPoll`, `closesocket`, `WsaInit`). Новый сетевой код должен включать
`win_compat.hpp` и использовать `sock_close / sock_errno / sock_err_str /
mikto_socklen_t / MIKTO_*` вместо голых POSIX-имён. MSVC собирается с
`/utf-8` — держи исходники в UTF-8 и не клади не-ASCII в форматные строки
printf.
