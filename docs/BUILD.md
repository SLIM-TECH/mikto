# Building mikto

mikto builds with CMake on Linux, macOS and Windows, and runs anywhere
Docker runs. Requirements are intentionally boring: a C++20 compiler,
libcurl and OpenSSL.

## Linux / macOS

One-liner for POSIX systems (Linux, macOS, BSD, WSL):

```bash
./build.sh   # configure + build + tests, honors extra args (pass cmake flags)
```

Manual way:

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
cmake --build build -j          # -j$(nproc) on linux, -j3 on macos
ctest --test-dir build --output-on-failure
sudo cmake --install build      # optional
```

Notes:

* the configure step prints the exact missing-package install command per
  distro if libcurl/OpenSSL is not found — no raw CMake spelunking needed;
* OpenSSL on macOS: pass `-DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)` if
  cmake cannot find it;
* reset everything: `rm -rf build`.

### CMake options

| Option | Default | Meaning |
|--------|---------|---------|
| `-DCMAKE_BUILD_TYPE` | — | use `Release` for real runs |
| `-DMIKTO_WERROR=ON` | OFF | warnings as errors (used in CI) |
| `-DMIKTO_BUILD_TESTS=OFF` | ON | skip the test binary (faster CI builds) |

## Windows

Same sources, no forks. Two routes:

### MSVC + vcpkg (recommended)

```powershell
git clone https://github.com/microsoft/vcpkg C:\vcpkg
C:\vcpkg\bootstrap-vcpkg.bat

git clone https://github.com/mikto-scanner/mikto && cd mikto
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release ^
  -DCMAKE_TOOLCHAIN_FILE=C:\vcpkg\scripts\buildsystems\vcpkg.cmake
cmake --build build --config Release
.\build\Release\mikto.exe --version
```

The repo ships a `vcpkg.json` manifest, so vcpkg installs curl + OpenSSL
automatically on first configure (the CI workflow caches `vcpkg_installed`).

### MSYS2 / MinGW-w64

```bash
pacman -S mingw-w64-ucrt-x86_64-{gcc,cmake,curl,openssl} make
cmake -B build -DCMAKE_BUILD_TYPE=Release -G "Unix Makefiles"
cmake --build build -j
./build/mikto.exe --version
```

Windows behaviour notes:

* Winsock is initialized in `main()` (`mikto::WsaInit`) and cleaned up on exit;
* `isatty` maps to `_isatty` — colours work in Windows Terminal and are
  disabled when output is piped, same as POSIX;
* DNS uses keyless resolvers (1.1.1.1 / 8.8.8.8) because `/etc/resolv.conf`
  does not exist there, with a `getaddrinfo` fallback path;
* cache directory: `%USERPROFILE%\.cache\mikto` (falls back to temp).

## Docker

```bash
docker build -t mikto .
docker run --rm mikto --version
# отчёт в текущую папку
docker run --rm -v "$PWD:/reports" mikto scan https://your-own-site.example --html /reports/report.html
```

* stage 1 builds with gcc inside `debian:12-slim` (cmake, libcurl, openssl dev);
* stage 2 ships only `mikto` + runtime libs and runs as unprivileged `scanner`;
* reports go to `/reports` — mount a directory there;
* `docker-compose.yml` adds a ready-made `scan` service and an optional
  `--profile watch` daily-scan + diff loop over `targets.txt`.

## CI

`.github/workflows/ci.yml` runs on every push/PR:

* **linux** — full build with `-DMIKTO_WERROR=ON` + all 1422 checks + smoke run;
* **windows** — MSVC + vcpkg manifest build + `--version` smoke;
* **macos** — Homebrew OpenSSL build + smoke.

Copy the file if you fork; no secrets needed (all sources are keyless by
default).

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `libcurl development files were NOT found` | install the dev package (the error text lists your distro's command) |
| `OpenSSL development files were NOT found` | same — `libssl-dev` / `openssl-devel` / `openssl@3` |
| cmake cannot find OpenSSL on macOS | add `-DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)` |
| GCC < 11 fails with C++20 errors | use a newer compiler; mikto needs C++20 ranges/chars |
| tests fail in a sandbox without network | unit tests are offline-safe; only `test_reporters`/`test_detect` touch no network at all — check your proxy env for the CLI smoke run |
| Windows: `vcpkg` build takes long | it compiles curl+openssl once; the cache (GH actions or `vcpkg_installed`) makes it fast afterwards |
