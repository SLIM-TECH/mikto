// парсинг аргументов
#include "cli.hpp"

#include <algorithm>
#include <cstdlib>
#include <filesystem>

#include "mikto/target.hpp"
#include "mikto/util.hpp"
#include "mikto/version.hpp"

namespace mikto {

std::string usage_text() {
  return R"(mikto v)" + std::string(MIKTO_VERSION) +
         R"( — authorized-only reconnaissance & audit scanner

usage:
  mikto <command> [options]

commands:
  scan <target|file> [...]   scan targets (IP, hostname, URL, or a file of them)
  diff <old.json> <new.json> compare two scan reports and list infrastructure
                             changes (new/removed subdomains, IPs, ports,
                             tech versions, findings; exit code 1 when
                             changes exist — CI-friendly monitoring)
  modules                    list available check modules
  providers                  list external data sources, their auth env vars
                             and documented free-tier limits
  help                       show this help

options:
  --deep                     widen port range and enable deeper probes
                             (shows a warning and requires confirmation)
  --modules <a,b,c>          run only the listed modules (see `mikto modules`)
  --ports <spec>             custom TCP port list, e.g. 80,443,8000-8100
  --json <file>              write machine-readable JSON report
  --html <file>              write self-contained HTML report
  --sarif <file>             write SARIF 2.1.0 report (GitHub code
                             scanning compatible)
  --csv <file>               write flat CSV table of findings
  --severity <level>         minimum severity for console output
                             (info|low|medium|high|critical)
  --concurrency <n>          parallel workers, 1..64 (default 8; deep: 48)
  --thread <n|max>           same as --concurrency; 'max' = 64 workers
                             (content discovery, port scan and other
                             network-heavy stages split across workers)
  --rate <n>                 max connect attempts / requests per second
                             (default 100; deep: 800)
  --timeout <sec>            TCP connect timeout (default 1.5; deep: 1.0)
  --http-timeout <sec>       HTTP request timeout (default 10)
  --user-agent <ua>          custom User-Agent for HTTP requests
  --trace                    print the traffic log: every HTTP request,
                             DNS query, TCP/TLS/whois probe sent and what
                             came back (also embedded in JSON/HTML reports)
  --cache-dir <dir>          cache directory (default ~/.cache/mikto)
  --nvd-key <key>            NVD API key (or set the NVD_API_KEY env var)
  --shodan-key <key>         optional Shodan key for full infra data
                             (or set the SHODAN_API_KEY env var; without it
                             the free keyless InternetDB is used)
  --censys-key <id:secret>   optional Censys Search API credentials for
                             per-service software/CPE enrichment (or set
                             the CENSYS_API_ID + CENSYS_API_SECRET env vars)
  --no-color                 disable ANSI colors
  --no-progress              disable the live progress bar
  --verbose                  verbose progress output
  -y, --yes                  accept warnings non-interactively
  -h, --help                 show help
  -V, --version              show version

examples:
  mikto scan https://target.example
  mikto scan 203.0.113.10 --deep
  mikto scan targets.txt --json report.json
  mikto scan https://target.example --html report.html --severity medium
  mikto scan https://target.example --modules cve,exposed,secrets,headers
  mikto scan example.com --modules subdom,emails,neighbors,infra
  mikto scan example.com --json scans/mon.json && mikto diff scans/mon.json scans/tue.json

ethics:
  Use mikto only against systems you have explicit permission to test.
  mikto discovers issues; it never exploits them.
)";
}

std::string deep_warning_text() {
  return R"(
  ============================================================
   WARNING: DEEP MODE
   Deep mode expands the scan to the FULL TCP port range and
   enables deeper service probes. This generates significantly
   more traffic against the target and may be noticeable to
   its operators and monitoring systems.

   Continue ONLY if you have explicit, written authorization
   to test this target in deep mode.
  ============================================================
)";
}

namespace {

bool parse_port_spec(const std::string& spec, std::vector<uint16_t>& out,
                     std::string& err) {
  out.clear();
  for (const std::string& part : split(spec, ',')) {
    std::string p = trim(part);
    if (p.empty()) continue;
    size_t dash = p.find('-');
    if (dash != std::string::npos) {
      std::string lo_s = trim(p.substr(0, dash));
      std::string hi_s = trim(p.substr(dash + 1));
      long lo = std::strtol(lo_s.c_str(), nullptr, 10);
      long hi = std::strtol(hi_s.c_str(), nullptr, 10);
      if (lo < 1 || hi > 65535 || lo > hi) {
        err = "invalid port range: " + p;
        return false;
      }
      for (long v = lo; v <= hi && out.size() < 70000; ++v)
        out.push_back(static_cast<uint16_t>(v));
    } else {
      long v = std::strtol(p.c_str(), nullptr, 10);
      if (v < 1 || v > 65535) {
        err = "invalid port: " + p;
        return false;
      }
      out.push_back(static_cast<uint16_t>(v));
    }
  }
  // дедуп + сортировка
  std::sort(out.begin(), out.end());
  out.erase(std::unique(out.begin(), out.end()), out.end());
  if (out.empty()) {
    err = "empty port spec";
    return false;
  }
  return true;
}

// значение берём из следующего argv
bool next_value(int argc, char** argv, int& i, const std::string& opt,
                std::string& val, Cli& out) {
  if (i + 1 >= argc) {
    out.error = true;
    out.exit_code = 1;
    out.error_msg = "option " + opt + " requires a value";
    return false;
  }
  val = argv[++i];
  return true;
}

}  // namespace

Cli parse_cli(int argc, char** argv) {
  Cli cli;

  if (argc < 2) {
    cli.show_help = true;
    return cli;
  }

  std::string first = argv[1];
  if (first == "-h" || first == "--help" || first == "help") {
    cli.show_help = true;
    return cli;
  }
  if (first == "-V" || first == "--version") {
    cli.show_version = true;
    return cli;
  }
  if (first == "modules") {
    cli.show_modules = true;
    return cli;
  }
  if (first == "providers") {
    cli.show_providers = true;
    return cli;
  }
  if (first == "diff") {
    cli.is_diff = true;
    std::vector<std::string> positional;
    for (int i = 2; i < argc; ++i) {
      std::string arg = argv[i];
      if (arg == "-h" || arg == "--help") {
        cli.show_help = true;
        return cli;
      }
      std::string val;
      if (arg == "--json") {
        if (!next_value(argc, argv, i, arg, val, cli)) return cli;
        cli.config.json_out = val;
      } else if (arg == "--html") {
        if (!next_value(argc, argv, i, arg, val, cli)) return cli;
        cli.config.html_out = val;
      } else if (arg == "--no-color") {
        cli.config.no_color = true;
      } else if (!arg.empty() && arg[0] == '-' && arg.size() > 1) {
        cli.error = true;
        cli.exit_code = 1;
        cli.error_msg = "diff: unknown option " + arg + " (try `mikto help`)";
        return cli;
      } else {
        positional.push_back(arg);
      }
    }
    if (positional.size() != 2) {
      cli.error = true;
      cli.exit_code = 1;
      cli.error_msg = "diff: exactly two JSON report files are required "
                      "(mikto diff old.json new.json)";
      return cli;
    }
    cli.diff_old = positional[0];
    cli.diff_new = positional[1];
    return cli;
  }
  if (first != "scan") {
    cli.error = true;
    cli.exit_code = 1;
    cli.error_msg = "unknown command: " + first + " (try `mikto help`)";
    return cli;
  }

  Config& cfg = cli.config;
  std::vector<std::string> raw_targets;

  for (int i = 2; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "-h" || arg == "--help") {
      cli.show_help = true;
      return cli;
    }
    if (arg == "-V" || arg == "--version") {
      cli.show_version = true;
      return cli;
    }

    std::string val;
    if (arg == "--deep") {
      cfg.deep = true;
    } else if (arg == "--safe") {
      cfg.deep = false;  // explicit; default anyway
    } else if (arg == "-y" || arg == "--yes") {
      cfg.assume_yes = true;
    } else if (arg == "--no-color") {
      cfg.no_color = true;
    } else if (arg == "--no-progress") {
      cfg.no_progress = true;
    } else if (arg == "--trace") {
      cfg.trace = true;
    } else if (arg == "--verbose") {
      cfg.verbose = true;
    } else if (arg == "--modules") {
      if (!next_value(argc, argv, i, arg, val, cli)) return cli;
      for (const std::string& m : split(val, ',')) {
        std::string name = to_lower(trim(m));
        if (!name.empty()) {
          cfg.modules.insert(name);
          cfg.all_modules = false;
        }
      }
      if (cfg.modules.empty()) {
        cli.error = true;
        cli.exit_code = 1;
        cli.error_msg = "--modules: empty list";
        return cli;
      }
    } else if (arg == "--ports") {
      if (!next_value(argc, argv, i, arg, val, cli)) return cli;
      std::string perr;
      if (!parse_port_spec(val, cfg.ports, perr)) {
        cli.error = true;
        cli.exit_code = 1;
        cli.error_msg = perr;
        return cli;
      }
      cfg.ports_explicit = true;
    } else if (arg == "--json") {
      if (!next_value(argc, argv, i, arg, val, cli)) return cli;
      cfg.json_out = val;
    } else if (arg == "--html") {
      if (!next_value(argc, argv, i, arg, val, cli)) return cli;
      cfg.html_out = val;
    } else if (arg == "--sarif") {
      if (!next_value(argc, argv, i, arg, val, cli)) return cli;
      cfg.sarif_out = val;
    } else if (arg == "--csv") {
      if (!next_value(argc, argv, i, arg, val, cli)) return cli;
      cfg.csv_out = val;
    } else if (arg == "--severity") {
      if (!next_value(argc, argv, i, arg, val, cli)) return cli;
      bool ok = false;
      cfg.min_severity = severity_from_string(val, ok);
      if (!ok) {
        cli.error = true;
        cli.exit_code = 1;
        cli.error_msg = "--severity: unknown level '" + val +
                        "' (info|low|medium|high|critical)";
        return cli;
      }
      cfg.severity_filter_set = true;
    } else if (arg == "--concurrency") {
      if (!next_value(argc, argv, i, arg, val, cli)) return cli;
      long n = std::strtol(val.c_str(), nullptr, 10);
      if (n < 1 || n > 64) {
        cli.error = true;
        cli.exit_code = 1;
        cli.error_msg = "--concurrency: must be 1..64";
        return cli;
      }
      cfg.concurrency = static_cast<int>(n);
      cfg.concurrency_set = true;
    } else if (arg == "--thread") {
      // --thread: алиас --concurrency, max = потолок пула (64)
      if (!next_value(argc, argv, i, arg, val, cli)) return cli;
      if (val == "max") {
        cfg.concurrency = 64;
        cfg.concurrency_set = true;
      } else {
        long n = std::strtol(val.c_str(), nullptr, 10);
        if (n < 1 || n > 64) {
          cli.error = true;
          cli.exit_code = 1;
          cli.error_msg = "--thread: must be 1..64 or 'max'";
          return cli;
        }
        cfg.concurrency = static_cast<int>(n);
        cfg.concurrency_set = true;
      }
    } else if (arg == "--rate") {
      if (!next_value(argc, argv, i, arg, val, cli)) return cli;
      double r = std::strtod(val.c_str(), nullptr);
      if (r < 1.0 || r > 10000.0) {
        cli.error = true;
        cli.exit_code = 1;
        cli.error_msg = "--rate: must be 1..10000";
        return cli;
      }
      cfg.rate = r;
      cfg.rate_set = true;
    } else if (arg == "--timeout") {
      if (!next_value(argc, argv, i, arg, val, cli)) return cli;
      double s = std::strtod(val.c_str(), nullptr);
      if (s < 0.1 || s > 30.0) {
        cli.error = true;
        cli.exit_code = 1;
        cli.error_msg = "--timeout: must be 0.1..30 seconds";
        return cli;
      }
      cfg.connect_timeout_ms = static_cast<int>(s * 1000);
      cfg.timeout_set = true;
    } else if (arg == "--http-timeout") {
      if (!next_value(argc, argv, i, arg, val, cli)) return cli;
      double s = std::strtod(val.c_str(), nullptr);
      if (s < 1.0 || s > 120.0) {
        cli.error = true;
        cli.exit_code = 1;
        cli.error_msg = "--http-timeout: must be 1..120 seconds";
        return cli;
      }
      cfg.http_timeout_s = static_cast<int>(s);
    } else if (arg == "--user-agent") {
      if (!next_value(argc, argv, i, arg, val, cli)) return cli;
      cfg.user_agent = val;
    } else if (arg == "--cache-dir") {
      if (!next_value(argc, argv, i, arg, val, cli)) return cli;
      cfg.cache_dir = val;
    } else if (arg == "--nvd-key") {
      if (!next_value(argc, argv, i, arg, val, cli)) return cli;
      cfg.nvd_key = val;
    } else if (arg == "--shodan-key") {
      if (!next_value(argc, argv, i, arg, val, cli)) return cli;
      cfg.shodan_key = val;
    } else if (arg == "--censys-key") {
      if (!next_value(argc, argv, i, arg, val, cli)) return cli;
      cfg.censys_creds = val;
      if (cfg.censys_creds.find(':') == std::string::npos) {
        cli.error = true;
        cli.exit_code = 1;
        cli.error_msg =
            "--censys-key: expected API_ID:API_SECRET (Censys uses "
            "two credentials)";
        return cli;
      }
    } else if (!arg.empty() && arg[0] == '-' && arg.size() > 1) {
      cli.error = true;
      cli.exit_code = 1;
      cli.error_msg = "unknown option: " + arg + " (try `mikto help`)";
      return cli;
    } else {
      raw_targets.push_back(arg);
    }
  }

  if (raw_targets.empty()) {
    cli.error = true;
    cli.exit_code = 1;
    cli.error_msg = "no targets given (try `mikto help`)";
    return cli;
  }
  std::string terr;
  if (!parse_target_list(raw_targets, cfg.targets, terr)) {
    cli.error = true;
    cli.exit_code = 1;
    cli.error_msg = terr;
    return cli;
  }

  // ключи из env, если не заданы флагом
  if (cfg.nvd_key.empty()) {
    const char* env = std::getenv("NVD_API_KEY");
    if (env) cfg.nvd_key = env;
  }
  if (cfg.shodan_key.empty()) {
    const char* env = std::getenv("SHODAN_API_KEY");
    if (env) cfg.shodan_key = env;
  }
  if (cfg.censys_creds.empty()) {
    const char* id = std::getenv("CENSYS_API_ID");
    const char* sec = std::getenv("CENSYS_API_SECRET");
    if (id && sec && *id && *sec)
      cfg.censys_creds = std::string(id) + ":" + sec;
  }
  if (cfg.cache_dir.empty()) {
    // на windows HOME нет — берём USERPROFILE, если и его нет — temp
    const char* home = std::getenv("HOME");
    if (!home) home = std::getenv("USERPROFILE");
    std::filesystem::path base =
        home ? std::filesystem::path(home) / ".cache"
             : std::filesystem::temp_directory_path();
    cfg.cache_dir = base / "mikto";
  }

  // deep поднимает дефолты, но только те, что юзер не задал сам
  if (cfg.deep) {
    if (!cfg.rate_set) cfg.rate = 800.0;
    if (!cfg.concurrency_set) cfg.concurrency = 48;
    if (!cfg.timeout_set) cfg.connect_timeout_ms = 1000;
  }

  return cli;
}

}  // namespace mikto
