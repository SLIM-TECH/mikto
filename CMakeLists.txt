cmake_minimum_required(VERSION 3.16)
project(mikto LANGUAGES CXX VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(MIKTO_BUILD_TESTS "Build the mikto test suite" ON)
option(MIKTO_WERROR "Treat compiler warnings as errors" OFF)

find_package(CURL)
find_package(OpenSSL)
find_package(Threads REQUIRED)

if(NOT CURL_FOUND)
  message(FATAL_ERROR
    "libcurl development files were NOT found.\n"
    "mikto requires libcurl (>= 7.x) with headers to build.\n"
    "Install it with one of the following commands, then re-run cmake:\n"
    "  Debian/Ubuntu : sudo apt install libcurl4-openssl-dev\n"
    "  Fedora/RHEL   : sudo dnf install libcurl-devel\n"
    "  Arch          : sudo pacman -S curl\n"
    "  Alpine        : apk add curl-dev\n"
    "  macOS (brew)  : brew install curl\n"
    "If libcurl is installed in a non-standard prefix, point cmake to it:\n"
    "  cmake -B build -DCURL_ROOT=/path/to/curl\n"
    "See https://cmake.org/cmake/help/latest/module/FindCURL.html")
endif()

if(NOT OpenSSL_FOUND)
  message(FATAL_ERROR
    "OpenSSL development files were NOT found.\n"
    "mikto requires OpenSSL (>= 1.1.1, 3.x recommended) with headers to build.\n"
    "Install it with one of the following commands, then re-run cmake:\n"
    "  Debian/Ubuntu : sudo apt install libssl-dev\n"
    "  Fedora/RHEL   : sudo dnf install openssl-devel\n"
    "  Arch          : sudo pacman -S openssl\n"
    "  Alpine        : apk add openssl-dev\n"
    "  macOS (brew)  : brew install openssl@3")
endif()

add_library(mikto_core STATIC
  src/util.cpp
  src/version.cpp
  src/types.cpp
  src/target.cpp
  src/cli.cpp
  src/net.cpp
  src/dns.cpp
  src/progress.cpp
  src/rate_limiter.cpp
  src/http_client.cpp
  src/tls.cpp
  src/scan_result.cpp
  src/providers.cpp
  src/intel_graph.cpp
  src/scan_diff.cpp
  src/osint.cpp
  src/cve_db.cpp
  src/orchestrator.cpp
  src/modules/registry.cpp
  src/modules/web_common.cpp
  src/modules/ports.cpp
  src/modules/tech.cpp
  src/modules/webpaths.cpp
  src/modules/subdom.cpp
  src/modules/emails.cpp
  src/modules/emailsec.cpp
  src/modules/infra.cpp
  src/modules/neighbors.cpp
  src/modules/whois.cpp
  src/modules/headers.cpp
  src/modules/waf.cpp
  src/modules/exposed.cpp
  src/modules/cve.cpp
  src/modules/secrets.cpp
  src/modules/assets.cpp
  src/reporters/console.cpp
  src/reporters/json_report.cpp
  src/reporters/html_report.cpp
  src/reporters/sarif_report.cpp
  src/reporters/csv_report.cpp
)

target_include_directories(mikto_core PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CMAKE_CURRENT_SOURCE_DIR}/third_party
)

target_link_libraries(mikto_core PUBLIC
  CURL::libcurl
  OpenSSL::SSL
  OpenSSL::Crypto
  Threads::Threads
)

if(MSVC)
  # исходники в utf-8 (текст отчёта с юникодом)
  target_compile_options(mikto_core PRIVATE /utf-8)
elseif(WIN32)
  target_compile_options(mikto_core PRIVATE -Wall -Wextra -Wpedantic)
  if(MIKTO_WERROR)
    target_compile_options(mikto_core PRIVATE -Werror)
  endif()
else()
  target_compile_options(mikto_core PRIVATE -Wall -Wextra -Wpedantic)
  if(MIKTO_WERROR)
    target_compile_options(mikto_core PRIVATE -Werror)
  endif()
endif()

if(WIN32)
  target_link_libraries(mikto_core PUBLIC ws2_32)
endif()

add_executable(mikto src/main.cpp)
target_link_libraries(mikto PRIVATE mikto_core)
if(MSVC)
  target_compile_options(mikto PRIVATE /utf-8)
elseif(NOT WIN32)
  target_compile_options(mikto PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(MIKTO_BUILD_TESTS)
  enable_testing()
  add_executable(mikto_tests
    tests/test_main.cpp
    tests/test_util.cpp
    tests/test_version_cmp.cpp
    tests/test_target.cpp
    tests/test_headers.cpp
    tests/test_secrets.cpp
    tests/test_cvedb.cpp
    tests/test_scan_result.cpp
    tests/test_recon.cpp
    tests/test_osint.cpp
    tests/test_detect.cpp
    tests/test_graph.cpp
    tests/test_emailsec.cpp
    tests/test_diff.cpp
    tests/test_providers.cpp
    tests/test_reporters.cpp
  )
  target_link_libraries(mikto_tests PRIVATE mikto_core)
  if(NOT MSVC)
    target_compile_options(mikto_tests PRIVATE -Wall -Wextra -Wpedantic)
  endif()
  add_test(NAME mikto_tests COMMAND mikto_tests)
endif()

install(TARGETS mikto RUNTIME DESTINATION bin)
