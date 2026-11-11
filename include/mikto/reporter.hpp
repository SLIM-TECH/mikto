#pragma once
// mikto — интерфейс репортеров
#include <memory>
#include <string>

namespace mikto {

class ScanResult;
struct Config;

class IReporter {
 public:
  virtual ~IReporter() = default;
  // false + err при ошибке записи
  virtual bool write(const ScanResult& r, const Config& cfg, std::string& err) = 0;
};

std::unique_ptr<IReporter> make_console_reporter();
std::unique_ptr<IReporter> make_json_reporter(const std::string& path);
std::unique_ptr<IReporter> make_html_reporter(const std::string& path);
// sarif 2.1.0 и csv
std::unique_ptr<IReporter> make_sarif_reporter(const std::string& path);
std::unique_ptr<IReporter> make_csv_reporter(const std::string& path);

}  // namespace mikto
