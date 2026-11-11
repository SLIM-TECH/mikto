#pragma once
// mikto — строковые хелперы
#include <string>
#include <vector>

namespace mikto {

std::string trim(const std::string& s);
std::string to_lower(const std::string& s);
std::string to_upper(const std::string& s);
std::vector<std::string> split(const std::string& s, char sep);
bool starts_with(const std::string& s, const std::string& prefix);
bool ends_with(const std::string& s, const std::string& suffix);
bool iequals(const std::string& a, const std::string& b);

bool contains_ci(const std::string& haystack, const std::string& needle);

// для html-репорта
std::string html_escape(const std::string& s);

// режем по границе utf-8, в конце "..."
std::string truncate_ellipsis(const std::string& s, size_t max_len);

// utc
std::string now_iso8601_utc();
std::string format_duration(double seconds);

// rfc 4180, репортер csv тоже зовёт
std::string csv_escape(const std::string& s);

}  // namespace mikto
