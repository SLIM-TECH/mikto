// sarif 2.1.0 репортер: critical/high -> error, medium -> warning, ниже -> note.
#include <fstream>

#include <nlohmann/json.hpp>

#include "mikto/config.hpp"
#include "mikto/reporter.hpp"
#include "mikto/scan_result.hpp"
#include "mikto/types.hpp"
#include "mikto/util.hpp"
#include "mikto/version.hpp"

namespace mikto {

namespace {

using json = nlohmann::json;

std::string slugify(const std::string& s) {
  std::string out;
  for (char c : s) {
    unsigned char uc = static_cast<unsigned char>(c);
    if (std::isalnum(uc)) out += static_cast<char>(std::tolower(uc));
    else if (out.empty() || out.back() != '-') out += '-';
  }
  while (!out.empty() && out.back() == '-') out.pop_back();
  if (out.empty()) out = "finding";
  return out;
}

const char* sarif_level(Severity s) {
  switch (s) {
    case Severity::Critical:
    case Severity::High: return "error";
    case Severity::Medium: return "warning";
    default: return "note";
  }
}

class SarifReporter : public IReporter {
 public:
  explicit SarifReporter(std::string path) : path_(std::move(path)) {}

  bool write(const ScanResult& r, const Config& cfg, std::string& err) override {
    (void)cfg;
    json rules = json::array();
    std::map<std::string, std::string> rule_ids;  // module|title -> ruleId
    std::set<std::string> used_ids;

    for (const auto& f : r.findings) {
      std::string base =
          std::string("mikto/") + f.module + "/" + slugify(f.title);
      std::string id = base;
      int disamb = 2;
      std::string key = f.module + "|" + f.title;
      while (used_ids.count(id) &&
             rule_ids.find(key) == rule_ids.end() && disamb < 100)
        id = base + "-" + std::to_string(disamb++);
      auto it = rule_ids.find(key);
      if (it == rule_ids.end()) {
        rule_ids[key] = id;
        used_ids.insert(id);
        json rule = {{"id", id}};
        rule["shortDescription"] = {{"text", truncate_ellipsis(f.title, 200)}};
        if (!f.detail.empty())
          rule["fullDescription"] = {{"text", truncate_ellipsis(f.detail, 1000)}};
        if (!f.references.empty() && f.references[0].rfind("http", 0) == 0)
          rule["helpUri"] = f.references[0];
        rule["properties"] = {{"module", f.module},
                              {"mikto-severity", severity_key(f.severity)}};
        rules.push_back(std::move(rule));
      }
    }

    json results = json::array();
    for (const auto& f : r.findings) {
      json res;
      res["ruleId"] = rule_ids[f.module + "|" + f.title];
      res["level"] = sarif_level(f.severity);
      std::string msg = f.detail.empty() ? f.title : f.detail;
      if (!f.evidence.empty()) msg += " (evidence: " + f.evidence + ")";
      res["message"] = {{"text", truncate_ellipsis(msg, 2000)}};
      // url для web-находок, иначе хост
      std::string uri = f.location.rfind("http", 0) == 0 ? f.location
                        : !f.host.empty() ? f.host
                                          : "global";
      json loc = {{"physicalLocation",
                   {{"artifactLocation", {{"uri", uri}}}}}};
      if (f.port > 0)
        loc["logicalLocations"] = json::array({json{
            {"name", f.host + ":" + std::to_string(f.port)},
            {"kind", "network-resource"}}});
      res["locations"] = json::array({loc});
      res["properties"] = {{"severity", severity_key(f.severity)},
                           {"host", f.host},
                           {"port", f.port},
                           {"service", f.service},
                           {"location", f.location},
                           {"recommendation", f.recommendation},
                           {"references", f.references}};
      results.push_back(std::move(res));
    }

    json j = {
        {"$schema", "https://json.schemastore.org/sarif-2.1.0.json"},
        {"version", "2.1.0"},
        {"runs", json::array({json{
             {"tool",
              {{"driver",
                {{"name", "mikto"},
                 {"version", MIKTO_VERSION},
                 {"informationUri", MIKTO_HOMEPAGE},
                 {"semanticVersion", MIKTO_VERSION},
                 {"shortDescription",
                  {{"text",
                    "authorized-only reconnaissance & audit scanner"}}},
                 {"rules", rules}}}}},
             {"results", results}}})}};

    std::ofstream f(path_, std::ios::trunc);
    if (!f) {
      err = "cannot open SARIF report file: " + path_;
      return false;
    }
    f << j.dump(2) << "\n";
    if (!f) {
      err = "failed writing SARIF report: " + path_;
      return false;
    }
    return true;
  }

 private:
  std::string path_;
};

}  // namespace

std::unique_ptr<IReporter> make_sarif_reporter(const std::string& path) {
  return std::make_unique<SarifReporter>(path);
}

}  // namespace mikto
