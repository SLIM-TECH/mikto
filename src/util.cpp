#include "mikto/util.hpp"

#include <cctype>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <sstream>

namespace mikto {

std::string trim(const std::string& s) {
  size_t b = 0;
  size_t e = s.size();
  while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
  while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
  return s.substr(b, e - b);
}

std::string to_lower(const std::string& s) {
  std::string r = s;
  for (char& c : r) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return r;
}

std::string to_upper(const std::string& s) {
  std::string r = s;
  for (char& c : r) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
  return r;
}

std::vector<std::string> split(const std::string& s, char sep) {
  std::vector<std::string> out;
  std::string cur;
  for (char c : s) {
    if (c == sep) {
      out.push_back(cur);
      cur.clear();
    } else {
      cur.push_back(c);
    }
  }
  out.push_back(cur);
  return out;
}

bool starts_with(const std::string& s, const std::string& prefix) {
  return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

bool ends_with(const std::string& s, const std::string& suffix) {
  return s.size() >= suffix.size() &&
         s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool iequals(const std::string& a, const std::string& b) {
  if (a.size() != b.size()) return false;
  for (size_t i = 0; i < a.size(); ++i) {
    if (std::tolower(static_cast<unsigned char>(a[i])) !=
        std::tolower(static_cast<unsigned char>(b[i])))
      return false;
  }
  return true;
}

bool contains_ci(const std::string& haystack, const std::string& needle) {
  if (needle.empty()) return true;
  std::string h = to_lower(haystack);
  std::string n = to_lower(needle);
  return h.find(n) != std::string::npos;
}

std::string html_escape(const std::string& s) {
  std::string out;
  out.reserve(s.size());
  for (char c : s) {
    switch (c) {
      case '&': out += "&amp;"; break;
      case '<': out += "&lt;"; break;
      case '>': out += "&gt;"; break;
      case '"': out += "&quot;"; break;
      case '\'': out += "&#39;"; break;
      default: out.push_back(c);
    }
  }
  return out;
}

std::string truncate_ellipsis(const std::string& s, size_t max_len) {
  if (s.size() <= max_len) return s;
  if (max_len <= 3) return s.substr(0, max_len);
  size_t cut = max_len - 3;
  // не рвём utf-8
  while (cut > 0 && (static_cast<unsigned char>(s[cut]) & 0xC0) == 0x80) --cut;
  return s.substr(0, cut) + "...";
}

std::string now_iso8601_utc() {
  std::time_t now = std::time(nullptr);
  std::tm tm{};
  gmtime_r(&now, &tm);
  char buf[64];
  std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02dZ",
                tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour,
                tm.tm_min, tm.tm_sec);
  return buf;
}

std::string format_duration(double seconds) {
  if (seconds < 10.0) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%.1fs", seconds);
    return buf;
  }
  if (seconds < 90.0) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%ds", static_cast<int>(seconds));
    return buf;
  }
  int total = static_cast<int>(seconds);
  char buf[48];
  std::snprintf(buf, sizeof(buf), "%dm %ds", total / 60, total % 60);
  return buf;
}

std::string csv_escape(const std::string& s) {
  bool needs_quotes = false;
  for (char c : s) {
    if (c == ',' || c == '"' || c == '\r' || c == '\n') {
      needs_quotes = true;
      break;
    }
  }
  if (!needs_quotes) return s;
  std::string out = "\"";
  for (char c : s) {
    if (c == '"') out += "\"\"";
    else out += c;
  }
  out += '"';
  return out;
}

}  // namespace mikto
