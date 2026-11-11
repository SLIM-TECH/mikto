#pragma once
// mikto — версия и сравнение версий
#include <string>

namespace mikto {

inline constexpr const char* MIKTO_VERSION = "0.1.0-beta";
inline constexpr const char* MIKTO_HOMEPAGE = "https://github.com/mikto-scanner/mikto";

// "9.6p1" > "9.6", возвращает -1/0/1
int compare_versions(const std::string& a, const std::string& b);

}  // namespace mikto
