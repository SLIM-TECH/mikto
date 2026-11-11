// цели: валидное или ошибка, без угадываний
#include "mikto/target.hpp"

#include "mikto/win_compat.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <filesystem>
#include <fstream>

#include "mikto/util.hpp"

namespace mikto {

namespace {

bool host_charset_ok(const std::string& h) {
  if (h.empty() || h.size() > 253) return false;
  for (char c : h) {
    if (std::isalnum(static_cast<unsigned char>(c))) continue;
    if (c == '.' || c == '-' || c == '_') continue;
    return false;
  }
  if (h.find("..") != std::string::npos) return false;
  return true;
}

bool parse_port(const std::string& s, int& out) {
  if (s.empty() || s.size() > 5) return false;
  for (char c : s)
    if (!std::isdigit(static_cast<unsigned char>(c))) return false;
  long v = std::strtol(s.c_str(), nullptr, 10);
  if (v < 1 || v > 65535) return false;
  out = static_cast<int>(v);
  return true;
}

}  // namespace

bool looks_like_ipv4(const std::string& s) {
  in_addr a{};
  return inet_pton(AF_INET, s.c_str(), &a) == 1;
}

bool looks_like_ipv6(const std::string& s) {
  if (s.find(':') == std::string::npos) return false;
  in6_addr a{};
  return inet_pton(AF_INET6, s.c_str(), &a) == 1;
}

bool parse_target(const std::string& raw_in, Target& out, std::string& err) {
  std::string raw = trim(raw_in);
  if (raw.empty()) {
    err = "empty target";
    return false;
  }
  // контроль-символы отсеиваем сразу
  for (char c : raw) {
    if (std::iscntrl(static_cast<unsigned char>(c)) || std::isspace(static_cast<unsigned char>(c))) {
      err = "invalid characters in target: " + raw;
      return false;
    }
  }

  Target t;
  t.original = raw;
  std::string rest = raw;

  if (starts_with(rest, "https://")) {
    t.scheme = "https";
    rest = rest.substr(8);
  } else if (starts_with(rest, "http://")) {
    t.scheme = "http";
    rest = rest.substr(7);
  } else if (rest.find("://") != std::string::npos) {
    err = "unsupported URL scheme in target: " + raw +
          " (use http:// or https://)";
    return false;
  }

  // путь отрезаем, сканируем хост целиком
  size_t slash = rest.find('/');
  if (slash != std::string::npos) rest = rest.substr(0, slash);
  size_t at = rest.rfind('@');
  if (at != std::string::npos) rest = rest.substr(at + 1);

  if (!rest.empty() && rest.front() == '[') {
    // IPv6 literal, optionally [::1]:443
    size_t close = rest.find(']');
    if (close == std::string::npos) {
      err = "unterminated '[' in IPv6 target: " + raw;
      return false;
    }
    std::string host = rest.substr(1, close - 1);
    if (!looks_like_ipv6(host)) {
      err = "invalid IPv6 address: " + host;
      return false;
    }
    t.host = host;
    t.is_ip = true;
    std::string tail = rest.substr(close + 1);
    if (!tail.empty()) {
      if (tail.front() != ':') {
        err = "unexpected text after IPv6 address in: " + raw;
        return false;
      }
      int port = 0;
      if (!parse_port(tail.substr(1), port)) {
        err = "invalid port in target: " + raw;
        return false;
      }
      t.port = port;
    }
  } else {
    // host[:port], много двоеточий = голый ipv6
    size_t colon = rest.rfind(':');
    std::string host = rest;
    bool has_colon = colon != std::string::npos;
    if (has_colon && rest.find(':') == colon) {
      int port = 0;
      if (!parse_port(rest.substr(colon + 1), port)) {
        err = "invalid port in target: " + raw;
        return false;
      }
      host = rest.substr(0, colon);
      t.port = port;
    } else if (has_colon) {
      if (!looks_like_ipv6(rest)) {
        err = "invalid IPv6 address: " + rest;
        return false;
      }
      t.host = rest;
      t.is_ip = true;
      out = t;
      return true;
    }
    if (!host_charset_ok(host)) {
      err = "invalid hostname in target: " + raw;
      return false;
    }
    t.host = to_lower(host);
    t.is_ip = looks_like_ipv4(t.host);
  }

  if (t.host.empty()) {
    err = "missing host in target: " + raw;
    return false;
  }
  out = t;
  return true;
}

bool parse_target_list(const std::vector<std::string>& inputs,
                       std::vector<Target>& out, std::string& err) {
  out.clear();
  for (const std::string& input : inputs) {
    std::error_code ec;
    if (std::filesystem::is_regular_file(input, ec)) {
      std::ifstream f(input);
      if (!f) {
        err = "cannot open targets file: " + input;
        return false;
      }
      std::string line;
      int line_no = 0;
      while (std::getline(f, line)) {
        ++line_no;
        std::string t = trim(line);
        if (t.empty() || t[0] == '#') continue;
        Target parsed;
        if (!parse_target(t, parsed, err)) {
          err = input + ":" + std::to_string(line_no) + ": " + err;
          return false;
        }
        out.push_back(parsed);
      }
    } else {
      Target parsed;
      if (!parse_target(input, parsed, err)) return false;
      out.push_back(parsed);
    }
  }
  // дедуп с сохранением порядка
  std::vector<Target> uniq;
  for (const Target& t : out) {
    bool dup = false;
    for (const Target& u : uniq) {
      if (u.host == t.host && u.port == t.port && u.scheme == t.scheme) {
        dup = true;
        break;
      }
    }
    if (!dup) uniq.push_back(t);
  }
  out = uniq;
  return !out.empty();
}

}  // namespace mikto
