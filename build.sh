#!/bin/sh
# mikto — сборка из исходников одним скриптом (Linux, macOS, BSD, WSL).
# Требует: cmake >= 3.16, C++20 компилятор, libcurl и openssl (dev-пакеты).
set -eu
cd "$(dirname "$0")"

JOBS="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"
echo "mikto: configure (jobs=$JOBS)"
cmake -B build -DCMAKE_BUILD_TYPE=Release "$@"

echo "mikto: build"
cmake --build build -j "$JOBS"

echo
echo "ok: ./build/mikto  (запуск: ./build/mikto help)"
if [ -x build/mikto_tests ]; then
  ./build/mikto_tests
fi
