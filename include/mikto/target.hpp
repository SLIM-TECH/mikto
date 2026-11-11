#pragma once
// mikto — парсинг целей; трогаем только то, что дали явно
#include <string>
#include <vector>

namespace mikto {

struct Target {
  std::string original;  // exactly as provided
  std::string scheme;    // "" | "http" | "https"
  std::string host;      // hostname or IP (no brackets for IPv6)
  int port = 0;          // explicit port from URL form, 0 = not specified
  bool is_ip = false;
};

// Parses a single token: "https://host", "host:port", "203.0.113.10", "[::1]".
bool parse_target(const std::string& raw, Target& out, std::string& err);

// строка файла = цель, # комментарии; при ошибке не угадываем
bool parse_target_list(const std::vector<std::string>& inputs,
                       std::vector<Target>& out, std::string& err);

bool looks_like_ipv4(const std::string& s);
bool looks_like_ipv6(const std::string& s);

}  // namespace mikto
