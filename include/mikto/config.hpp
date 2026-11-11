#pragma once
// mikto — конфиг, заполняет cli
#include <filesystem>
#include <set>
#include <string>
#include <vector>

#include "target.hpp"
#include "types.hpp"
#include "version.hpp"

namespace mikto {

struct Config {
  std::vector<Target> targets;

  // пусто = все модули
  std::set<std::string> modules;
  bool all_modules = true;

  // deep только после явного подтверждения
  bool deep = false;

  int concurrency = 8;          // воркеры
  double rate = 100.0;          // коннектов и запросов в сек
  int connect_timeout_ms = 1500;
  int http_timeout_s = 10;

  // true только когда юзер сам передал флаг
  bool concurrency_set = false;
  bool rate_set = false;
  bool timeout_set = false;
  std::string user_agent = "mikto/" + std::string(MIKTO_VERSION) + " (+responsible use)";

  std::vector<uint16_t> ports;      // explicit --ports spec, empty = auto
  bool ports_explicit = false;      // true when user passed --ports

  std::string json_out;
  std::string html_out;
  std::string sarif_out;
  std::string csv_out;

  Severity min_severity = Severity::Info;  // фильтр консоли (--severity)
  bool severity_filter_set = false;

  std::string nvd_key;          // иначе env NVD_API_KEY
  std::string shodan_key;       // иначе env SHODAN_API_KEY
  std::string censys_creds;     // "API_ID:API_SECRET", env CENSYS_API_ID + CENSYS_API_SECRET
  std::filesystem::path cache_dir;  // default: ~/.cache/mikto

  bool no_color = false;
  bool no_progress = false;
  bool verbose = false;
  bool trace = false;           // лог сети для --trace
  bool assume_yes = false;      // подтвердить --deep без интерактива
};

}  // namespace mikto
