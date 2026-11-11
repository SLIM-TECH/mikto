# Сборка mikto

mikto собирается CMake'ом на Linux, macOS и Windows и запускается везде, где
есть Docker. Требования нарочно скучные: компилятор C++20, libcurl и OpenSSL.

## Linux / macOS

Однострочник для POSIX-систем (Linux, macOS, BSD, WSL):

```bash
./build.sh   # configure + сборка + тесты; доп. аргументы уходят в cmake
```

Ручной способ:

```bash
# debian / ubuntu
sudo apt install build-essential cmake libcurl4-openssl-dev libssl-dev
# fedora / rhel
sudo dnf install gcc-c++ cmake make libcurl-devel openssl-devel
# arch
sudo pacman -S gcc cmake make curl openssl
# alpine
apk add build-base cmake curl-dev openssl-dev
# macOS (brew)
brew install cmake curl openssl@3
```

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j          # -j$(nproc) на linux, -j3 на macos
ctest --test-dir build --output-on-failure
sudo cmake --install build      # опционально
```

Заметки:

* если libcurl/OpenSSL не найдены, configure напечатает точную команду
  установки пакета для вашего дистрибутива — копаться в сырых ошибках CMake
  не придётся;
* OpenSSL на macOS: если cmake его не находит —
  `-DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)`;
* полный сброс: `rm -rf build`.

### Опции CMake

| Опция | Умолчание | Смысл |
|-------|-----------|-------|
| `-DCMAKE_BUILD_TYPE` | — | для реальной работы — `Release` |
| `-DMIKTO_WERROR=ON` | OFF | предупреждения как ошибки (так делает CI) |
| `-DMIKTO_BUILD_TESTS=OFF` | ON | не собирать тестовый бинарник (быстрее на CI) |

## Windows

Те же исходники, никаких форков. Два пути:

### MSVC + vcpkg (рекомендую)

```powershell
git clone https://github.com/microsoft/vcpkg C:\vcpkg
C:\vcpkg\bootstrap-vcpkg.bat

git clone https://github.com/mikto-scanner/mikto && cd mikto
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release ^
  -DCMAKE_TOOLCHAIN_FILE=C:\vcpkg\scripts\buildsystems\vcpkg.cmake
cmake --build build --config Release
.\build\Release\mikto.exe --version
```

В репо лежит манифест `vcpkg.json`, поэтому vcpkg сам поставит curl + OpenSSL
при первой конфигурации (CI закэширует `vcpkg_installed`).

### MSYS2 / MinGW-w64

```bash
pacman -S mingw-w64-ucrt-x86_64-{gcc,cmake,curl,openssl} make
cmake -B build -DCMAKE_BUILD_TYPE=Release -G "Unix Makefiles"
cmake --build build -j
./build/mikto.exe --version
```

Замечания по Windows:

* Winsock инициализируется в `main()` (`mikto::WsaInit`) и чистится на выходе;
* `isatty` маппится на `_isatty` — цвета работают в Windows Terminal и
  выключаются при пайпе, как на POSIX;
* DNS идёт на безключевые резолверы (1.1.1.1 / 8.8.8.8), потому что
  `/etc/resolv.conf` там не существует, плюс фолбэк через `getaddrinfo`;
* каталог кэша: `%USERPROFILE%\.cache\mikto` (фолбэк — temp).

## Docker

```bash
docker build -t mikto .
docker run --rm mikto --version
# отчёт в текущую папку
docker run --rm -v "$PWD:/reports" mikto scan https://your-own-site.example --html /reports/report.html
```

* стадия 1 — сборка gcc внутри `debian:12-slim` (cmake, libcurl, openssl dev);
* стадия 2 — только `mikto` + рантайм-библиотеки, работает от непривилегированного
  пользователя `scanner`;
* отчёты пишутся в `/reports` — монтируйте туда каталог;
* `docker-compose.yml` даёт готовый сервис `scan` и опциональный
  `--profile watch` — ежедневный скан + diff по `targets.txt`.

## CI

`.github/workflows/ci.yml` гонит на каждый push/PR:

* **linux** — полная сборка с `-DMIKTO_WERROR=ON` + все 1422 проверки + smoke;
* **windows** — сборка MSVC + vcpkg-манифест + smoke `--version`;
* **macos** — сборка с Homebrew OpenSSL + smoke.

Файл можно копировать как есть при форке; секретов не нужно (все источники
по умолчанию без ключей).

## Неисправности

| Симптом | Лечение |
|---------|---------|
| `libcurl development files were NOT found` | поставьте dev-пакет (в тексте ошибки есть команда для вашего дистрибутива) |
| `OpenSSL development files were NOT found` | то же — `libssl-dev` / `openssl-devel` / `openssl@3` |
| cmake не находит OpenSSL на macOS | добавьте `-DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)` |
| GCC < 11 падает на ошибках C++20 | нужен свежее компилятор; mikto требует C++20 ranges/chars |
| тесты падают в песочнице без сети | юнит-тесты офлайн-безопасны; сети не касается никто — проверьте прокси-env для smoke-прогона CLI |
| Windows: сборка vcpkg долгая | curl+openssl компилируются один раз; кэш (GH actions или `vcpkg_installed`) ускоряет повторные |
