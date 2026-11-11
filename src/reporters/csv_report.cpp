// csv репортер: одна строка на находку, RFC 4180, utf-8.
#include <fstream>

#include "mikto/config.hpp"
#include "mikto/reporter.hpp"
#include "mikto/scan_result.hpp"
#include "mikto/types.hpp"
#include "mikto/util.hpp"
#include "mikto/version.hpp"

namespace mikto {

namespace {

class CsvReporter : public IReporter {
 public:
  explicit CsvReporter(std::string path) : path_(std::move(path)) {}

  bool write(const ScanResult& r, const Config& cfg, std::string& err) override {
    (void)cfg;
    std::ofstream f(path_, std::ios::trunc);
    if (!f) {
      err = "cannot open CSV report file: " + path_;
      return false;
    }
    f << "severity,module,host,port,service,location,title,detail,"
         "recommendation,evidence,references\n";
    for (const auto& fd : r.findings) {
      std::string refs;
      for (size_t i = 0; i < fd.references.size(); ++i) {
        if (i) refs += " ";
        refs += fd.references[i];
      }
      f << csv_escape(severity_key(fd.severity)) << ','
        << csv_escape(fd.module) << ','
        << csv_escape(fd.host) << ','
        << (fd.port > 0 ? std::to_string(fd.port) : std::string()) << ','
        << csv_escape(fd.service) << ','
        << csv_escape(fd.location) << ','
        << csv_escape(fd.title) << ','
        << csv_escape(fd.detail) << ','
        << csv_escape(fd.recommendation) << ','
        << csv_escape(fd.evidence) << ','
        << csv_escape(refs) << '\n';
    }
    if (!f) {
      err = "failed writing CSV report: " + path_;
      return false;
    }
    return true;
  }

 private:
  std::string path_;
};

}  // namespace

std::unique_ptr<IReporter> make_csv_reporter(const std::string& path) {
  return std::make_unique<CsvReporter>(path);
}

}  // namespace mikto
