#include "mikto/types.hpp"

#include <cstdlib>

#include "mikto/util.hpp"

namespace mikto {

const char* severity_name(Severity s) {
  switch (s) {
    case Severity::Info: return "Info";
    case Severity::Low: return "Low";
    case Severity::Medium: return "Medium";
    case Severity::High: return "High";
    case Severity::Critical: return "Critical";
  }
  return "Info";
}

const char* severity_key(Severity s) {
  switch (s) {
    case Severity::Info: return "info";
    case Severity::Low: return "low";
    case Severity::Medium: return "medium";
    case Severity::High: return "high";
    case Severity::Critical: return "critical";
  }
  return "info";
}

const char* severity_color(Severity s) {
  switch (s) {
    case Severity::Info: return "\033[90m";     // bright black
    case Severity::Low: return "\033[36m";      // cyan
    case Severity::Medium: return "\033[33m";   // yellow
    case Severity::High: return "\033[31m";     // red
    case Severity::Critical: return "\033[1;97;41m";  // bold white on red
  }
  return "";
}

Severity severity_from_string(const std::string& s, bool& ok) {
  ok = true;
  std::string v = to_lower(s);
  if (v == "info") return Severity::Info;
  if (v == "low") return Severity::Low;
  if (v == "medium") return Severity::Medium;
  if (v == "high") return Severity::High;
  if (v == "critical") return Severity::Critical;
  ok = false;
  return Severity::Info;
}

Severity severity_from_cvss(double score) {
  if (score >= 9.0) return Severity::Critical;
  if (score >= 7.0) return Severity::High;
  if (score >= 4.0) return Severity::Medium;
  if (score > 0.0) return Severity::Low;
  return Severity::Info;
}

Severity severity_from_nvd(const std::string& s) {
  std::string v = to_upper(s);
  if (v == "CRITICAL") return Severity::Critical;
  if (v == "HIGH") return Severity::High;
  if (v == "MEDIUM" || v == "MODERATE") return Severity::Medium;
  if (v == "LOW") return Severity::Low;
  return Severity::Info;
}

}  // namespace mikto
