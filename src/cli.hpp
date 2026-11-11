#pragma once
// результат парсинга cli
#include <string>

#include "mikto/config.hpp"

namespace mikto {

struct Cli {
  int exit_code = 0;
  bool show_help = false;
  bool show_version = false;
  bool show_modules = false;
  bool show_providers = false;
  bool is_diff = false;
  std::string diff_old, diff_new;  // `mikto diff <old.json> <new.json>`
  bool error = false;
  std::string error_msg;
  Config config;
};

Cli parse_cli(int argc, char** argv);
std::string usage_text();
std::string deep_warning_text();

}  // namespace mikto
