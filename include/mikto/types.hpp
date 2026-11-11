#pragma once
// mikto — severity
#include <cstdint>
#include <string>

namespace mikto {

enum class Severity : uint8_t { Info = 0, Low, Medium, High, Critical };

const char* severity_name(Severity s);
const char* severity_key(Severity s);
const char* severity_color(Severity s);
// ok=false на незнакомой строке
Severity severity_from_string(const std::string& s, bool& ok);
Severity severity_from_cvss(double score);
Severity severity_from_nvd(const std::string& s);

}  // namespace mikto
