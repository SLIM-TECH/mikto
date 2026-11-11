#pragma once
// mikto — универсальная находка, одна на все репортеры
#include <string>
#include <vector>

#include "types.hpp"

namespace mikto {

struct Finding {
  Severity severity = Severity::Info;
  std::string module;      // producing module, e.g. "headers"
  std::string host;        // target host the finding belongs to
  int port = 0;            // tcp port; 0 when not applicable
  std::string service;     // human label, e.g. "nginx 1.25.3"
  std::string location;    // "tcp/27017", "header:Content-Security-Policy", URL
  std::string title;       // short statement of the problem
  std::string detail;      // why it matters / what was observed
  std::string recommendation;  // what to do about it
  std::string evidence;    // short, redacted where relevant
  std::vector<std::string> references;  // CVE ids, URLs

  // дублей подавлено add_finding, их локации в evidence
  int duplicates = 0;
};

}  // namespace mikto
