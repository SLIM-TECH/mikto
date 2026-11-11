#pragma once
// mikto — запуск модулей по зависимостям
#include <string>

namespace mikto {

class ScanResult;
struct Config;

// 0 = ок, неноль = фатал (err заполнен)
int run_scan(const Config& cfg, ScanResult& result, std::string& err);

}  // namespace mikto
