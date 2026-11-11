// mikto — точка входа
#include <fstream>
#include <iostream>

#include "cli.hpp"
#include "mikto/module.hpp"
#include "mikto/orchestrator.hpp"
#include "mikto/providers.hpp"
#include "mikto/reporter.hpp"
#include "mikto/scan_diff.hpp"
#include "mikto/scan_result.hpp"
#include "mikto/util.hpp"
#include "mikto/version.hpp"
#include "mikto/win_compat.hpp"

#include <nlohmann/json.hpp>

namespace {

bool confirm_interactive() {
  if (!mikto::is_stdin_tty()) return false;
  std::cout << "Type 'yes' to continue: " << std::flush;
  std::string line;
  if (!std::getline(std::cin, line)) return false;
  return mikto::trim(line) == "yes";
}

// exit: 0 одинаково, 1 есть изменения, 2 ошибка
int run_diff(const mikto::Cli& cli) {
  auto load = [](const std::string& path, nlohmann::json& out,
                 std::string& err) -> bool {
    std::ifstream f(path);
    if (!f) {
      err = "cannot open report file: " + path;
      return false;
    }
    try {
      out = nlohmann::json::parse(f);
    } catch (const std::exception& e) {
      err = "invalid JSON in " + path + ": " + e.what();
      return false;
    }
    return true;
  };
  nlohmann::json old_j, new_j;
  std::string err;
  if (!load(cli.diff_old, old_j, err) || !load(cli.diff_new, new_j, err)) {
    std::cerr << "mikto: " << err << "\n";
    return 2;
  }
  mikto::ScanDiffResult d = mikto::diff_reports(old_j, new_j);
  std::cout << mikto::diff_console_text(d, !cli.config.no_color);
  if (!cli.config.json_out.empty()) {
    std::ofstream f(cli.config.json_out, std::ios::trunc);
    if (!f) {
      std::cerr << "mikto: cannot open diff JSON file: "
                << cli.config.json_out << "\n";
      return 2;
    }
    f << mikto::diff_to_json(d).dump(2) << "\n";
    std::cout << "written: " << cli.config.json_out << "\n";
  }
  if (!cli.config.html_out.empty()) {
    if (!mikto::write_diff_html(d, cli.config.html_out, err)) {
      std::cerr << "mikto: " << err << "\n";
      return 2;
    }
    std::cout << "written: " << cli.config.html_out << "\n";
  }
  return d.identical() ? 0 : 1;
}

}  // namespace

int main(int argc, char** argv) {
  // на windows будим winsock до любых сокетов, на posix пустышка
  mikto::WsaInit wsa_guard;
  (void)wsa_guard;

  mikto::Cli cli = mikto::parse_cli(argc, argv);

  if (cli.error) {
    std::cerr << "mikto: error: " << cli.error_msg << "\n";
    return cli.exit_code;
  }
  if (cli.show_version) {
    std::cout << "mikto v" << mikto::MIKTO_VERSION << "\n";
    return 0;
  }
  if (cli.show_modules) {
    std::cout << mikto::modules_help_table();
    return 0;
  }
  if (cli.show_providers) {
    std::cout << mikto::providers_help_text();
    return 0;
  }
  if (cli.show_help) {
    std::cout << mikto::usage_text();
    return 0;
  }

  if (cli.is_diff) return run_diff(cli);

  const mikto::Config& cfg = cli.config;

  // ---- подтверждение deep ----
  if (cfg.deep && !cfg.assume_yes) {
    std::cout << mikto::deep_warning_text();
    if (!confirm_interactive()) {
      std::cerr << "mikto: deep mode requires confirmation "
                << "(run with --yes, or confirm interactively)\n";
      return 1;
    }
  }

  // ---- баннер ----
  std::cout << "mikto v" << mikto::MIKTO_VERSION << " — target: "
            << cfg.targets.front().original;
  if (cfg.targets.size() > 1)
    std::cout << " (+" << (cfg.targets.size() - 1) << " more)";
  std::cout << "\n";
  std::cout << (cfg.deep ? "mode: deep" : "mode: safe") << " — use only on "
               "systems you are explicitly permitted to test\n\n";

  // ---- скан ----
  mikto::ScanResult result;
  std::string err;
  if (mikto::run_scan(cfg, result, err) != 0) {
    std::cerr << "mikto: scan failed: " << err << "\n";
    return 2;
  }

  // ---- репорты ----
  std::vector<std::string> written;
  auto console = mikto::make_console_reporter();
  if (!console->write(result, cfg, err)) {
    std::cerr << "mikto: console report failed: " << err << "\n";
    return 2;
  }
  if (!cfg.json_out.empty()) {
    auto json = mikto::make_json_reporter(cfg.json_out);
    if (!json->write(result, cfg, err)) {
      std::cerr << "mikto: " << err << "\n";
      return 2;
    }
    written.push_back(cfg.json_out);
  }
  if (!cfg.html_out.empty()) {
    auto html = mikto::make_html_reporter(cfg.html_out);
    if (!html->write(result, cfg, err)) {
      std::cerr << "mikto: " << err << "\n";
      return 2;
    }
    written.push_back(cfg.html_out);
  }
  if (!cfg.sarif_out.empty()) {
    auto sarif = mikto::make_sarif_reporter(cfg.sarif_out);
    if (!sarif->write(result, cfg, err)) {
      std::cerr << "mikto: " << err << "\n";
      return 2;
    }
    written.push_back(cfg.sarif_out);
  }
  if (!cfg.csv_out.empty()) {
    auto csv = mikto::make_csv_reporter(cfg.csv_out);
    if (!csv->write(result, cfg, err)) {
      std::cerr << "mikto: " << err << "\n";
      return 2;
    }
    written.push_back(cfg.csv_out);
  }
  for (const auto& p : written)
    std::cout << "written: " << p << "\n";
  return 0;
}
