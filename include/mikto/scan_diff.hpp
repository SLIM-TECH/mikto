#pragma once
// mikto — diff двух отчётов; exit 1 = есть изменения
#include <map>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace mikto {

struct DiffChange {
  std::string kind;      // "subdomain", "ip", "port", "tech", "path", "dns",
                         // "email", "neighbor", "certificate", "finding",
                         // "infra_tag"
  std::string action;    // "added" | "removed" | "changed"
  std::string entity;    // host the change belongs to, "global" otherwise
  std::string detail;    // human-readable one-liner
  std::string severity;  // "info".."critical" (prioritization hint)
  std::string first_seen;  // started_at of the OLD scan ("" when added)
  std::string last_seen;   // started_at of the NEW scan ("" when removed)
};

struct ScanDiffResult {
  std::string old_started, new_started;
  std::vector<DiffChange> changes;      // sorted: severity desc, then kind
  std::map<std::string, int> by_kind;   // kind -> count
  std::map<std::string, int> by_action; // added/removed/changed counts
  bool identical() const { return changes.empty(); }
};

// нет секции = пусто, битые формы терпим
ScanDiffResult diff_reports(const nlohmann::json& old_j,
                            const nlohmann::json& new_j);

nlohmann::json diff_to_json(const ScanDiffResult& d);

std::string diff_console_text(const ScanDiffResult& d, bool color);

// false + err при io
bool write_diff_html(const ScanDiffResult& d, const std::string& path,
                     std::string& err);

}  // namespace mikto
