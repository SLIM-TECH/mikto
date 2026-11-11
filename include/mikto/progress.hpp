#pragma once
// mikto — прогресс в stderr, отчёты не пачкает
#include <atomic>
#include <chrono>
#include <mutex>
#include <string>

namespace mikto {

class Progress {
 public:
  Progress(bool enabled, bool color);

  void stage(const std::string& module, const std::string& label, size_t total);
  void grow_total(size_t add);  // для этапов с заранее неизвестным объёмом
  void tick(size_t n = 1);
  void item(const std::string& text);
  void done();
  void finish();

 private:
  void render_locked(bool force);
  std::string bar_locked(size_t width) const;

  bool enabled_;
  bool color_;
  bool is_tty_ = false;

  std::mutex mu_;
  std::string module_;
  std::string label_;
  std::string item_;
  size_t total_ = 0;
  std::atomic<size_t> done_{0};
  bool active_ = false;

  std::chrono::steady_clock::time_point start_{};
  std::chrono::steady_clock::time_point last_render_{};
};

}  // namespace mikto
