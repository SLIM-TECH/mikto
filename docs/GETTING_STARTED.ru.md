# Как начать работать с mikto

От свежего клона до первого читаемого отчёта. Займёт минут пять.

## 0. Главное правило

Запускайте mikto **только на системах, которые вам разрешено проверять**.
mikto read-only и безопасен по построению, но даже вежливое
*сканирование* без разрешения незаконно почти везде. Scope записан — вы
в порядке. Не записан — сначала запишите.

## 1. Сборка

Linux / macOS:

```bash
sudo apt install build-essential cmake libcurl4-openssl-dev libssl-dev  # debian/ubuntu
# fedora: sudo dnf install gcc-c++ cmake libcurl-devel openssl-devel
# arch:   sudo pacman -S gcc cmake curl openssl

git clone https://github.com/mikto-scanner/mikto && cd mikto
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

Windows и Docker — в [BUILD.ru.md](BUILD.ru.md).

Бинарник появится в `build/mikto`. Проверка:

```bash
./build/mikto --version    # mikto v0.1.0-beta
./build/mikto modules      # 15 модулей + зрелость
```

## 2. Первый скан

```bash
./build/mikto scan https://your-own-site.example --html report.html
```

Что происходит:

1. цель валидируется (имя / IP / URL) и попадает в строгий scope;
2. модули идут в порядке зависимостей: `assets → whois → subdom → emails →
   emailsec → ports → infra → neighbors → tech → webpaths → exposed →
   headers → waf → cve → secrets`;
3. на **stderr** живёт строка прогресса, на stdout растёт дерево;
4. пишется `report.html` — один самодостаточный файл, открывается двойным
   кликом, работает офлайн.

Безопасный режим (по умолчанию) вежлив: ~55 частых портов, 8 воркеров,
лимитер на всё, ~60 известных веб-путей. Подтверждение не нужно.

## 3. Как читать отчёт

HTML-отчёт открывается **Обзором**: риск-скор 0–100, буквенная оценка (A–F),
состав очков, топ-5 приоритетных действий, бары находок по модулям. Ниже:

* **Находки** — каждая проблема с серьёзностью, местом, доказательством и
  рекомендацией; фильтры по серьёзности / модулю / хосту / тексту.
* **Хосты** — полный инвентарь по хосту: DNS-записи, WHOIS, TLS-сертификат,
  порты с уверенностью проб, технологии, пути, субдомены, e-mail'ы,
  репутация.
* **Инфраструктура** — серверные IP с ASN / владельцем сети, какие имена из
  scope указывают на каждый IP, соседи по сегменту (/24, /64), домены на том
  же IP, общие NS/MX.
* **Корреляции** — интерактивная карта сущностей графа разведки + таблицы
  сущностей и связей с провенансом.
* **Веб** — все заголовки ответов, матрица ✓/✗ заголовков безопасности по URL.
* **Трафик** — что mikto отправил и что получил (с `--trace`).
* **Сведения о скане** — настройки, модули, здоровье внешних источников.

Интерфейс переключается **RU ↔ EN** кнопкой языка справа сверху; выбор
запоминается в браузере.

JSON — те же данные в машинном виде:

```bash
./build/mikto scan https://your-own-site.example --json report.json
jq '.findings[] | {severity, module, title}' report.json
```

## 4. Режимы

* **safe (по умолчанию)** — вежливый профиль, описанный выше.
* **`--deep`** — полный диапазон портов 1–65535, расширенный список путей,
  AXFR-проба. mikto печатает предупреждение и просит ввести `yes` (или
  передать `--yes`). Используйте только если разрешение явно покрывает deep.
* **`--modules a,b,c`** — подмножество модулей. Чистый OSINT-проход, вообще
  без проб к цели:

  ```bash
  ./build/mikto scan example.com --modules subdom,emails,neighbors,infra
  ```
* **`--thread <n|max>`** — размер пула воркеров для сетевых этапов (по
  умолчанию 8, `max` = 64). Если поднимаешь — добавь и `--rate`: лимитер темпа
  всегда остаётся потолком вежливости:

  ```bash
  ./build/mikto scan example.com --thread max --rate 500
  ```

## 5. Мониторинг изменений

Сохраните JSON-отчёт, через время отсканируйте снова и сравните:

```bash
./build/mikto scan example.com --json monday.json
# ... прошла неделя ...
./build/mikto scan example.com --json friday.json
./build/mikto diff monday.json friday.json --html diff.html
```

`diff` перечисляет новые/пропавшие субдомены, IP, открытые порты, смены
версий технологий, движение DNS-записей и новые/закрытые находки — и
**возвращает код 1, если что-то изменилось**, поэтому одна и та же команда
работает в cron и CI.

## 6. Куда дальше

* [MODULES.ru.md](MODULES.ru.md) — детально про каждый модуль.
* [RESPONSIBLE_USE.ru.md](RESPONSIBLE_USE.ru.md) — этический контракт.
* [DEV_GUIDE.ru.md](DEV_GUIDE.ru.md) — расширяем mikto своими модулями.
* [BUILD.ru.md](BUILD.ru.md) — Windows, Docker, CI, опции сборки.
