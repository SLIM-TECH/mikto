#include "mikto/progress.hpp"

#include "mikto/win_compat.hpp"

#include <cstdio>
#include <ctime>

namespace mikto {

Progress::Progress(bool enabled, bool color)
    : enabled_(enabled), color_(color) {
  is_tty_ = is_stderr_tty();
}

void Progress::stage(const std::string& module, const std::string& label,
                     size_t total) {
  std::lock_guard<std::mutex> g(mu_);
  module_ = module;
  label_ = label;
  total_ = total;
  item_.clear();
  done_.store(0);
  active_ = true;
  start_ = std::chrono::steady_clock::now();
  last_render_ = {};
  if (enabled_ && (is_tty_ || total > 0)) render_locked(true);
}

void Progress::grow_total(size_t add) {
  if (add == 0) return;
  std::lock_guard<std::mutex> g(mu_);
  total_ += add;
  render_locked(false);
}

void Progress::tick(size_t n) {
  done_.fetch_add(n);
  std::lock_guard<std::mutex> g(mu_);
  render_locked(false);
}

void Progress::item(const std::string& text) {
  std::lock_guard<std::mutex> g(mu_);
  item_ = text;
  render_locked(false);
}

void Progress::done() {
  std::lock_guard<std::mutex> g(mu_);
  if (enabled_ && active_) {
    double s = std::chrono::duration<double>(std::chrono::steady_clock::now() -
                                             start_)
                   .count();
    if (is_tty_)
      std::fprintf(stderr, "\r\033[K");
    else
      std::fprintf(stderr, "[mikto] %s: %s (%.1fs)\n", module_.c_str(),
                   label_.c_str(), s);
    if (is_tty_ && total_ > 0)
      std::fprintf(stderr, "[mikto] %s: %s — %zu/%zu (%.1fs)\n",
                   module_.c_str(), label_.c_str(), done_.load(), total_, s);
  }
  active_ = false;
  module_.clear();
  label_.clear();
  item_.clear();
  total_ = 0;
  done_.store(0);
}

void Progress::finish() {
  std::lock_guard<std::mutex> g(mu_);
  if (enabled_ && is_tty_) std::fprintf(stderr, "\r\033[K");
  active_ = false;
}

std::string Progress::bar_locked(size_t width) const {
  if (total_ == 0) return "";
  size_t fill = done_.load() * width / (total_ ? total_ : 1);
  if (fill > width) fill = width;
  std::string bar;
  bar.reserve(width + 4);
  for (size_t i = 0; i < width; ++i) bar.push_back(i < fill ? '#' : '.');
  return bar;
}

namespace {

// ужимаем длинную метку под ширину строки (ascii — режем по байтам)
std::string fit_label(const std::string& label, size_t budget) {
  if (label.size() <= budget) return label;
  if (budget <= 4) return label.substr(0, budget);
  return label.substr(0, budget - 3) + "...";
}

}  // namespace

void Progress::render_locked(bool force) {
  if (!enabled_ || !active_) return;
  if (!is_tty_) return;  // stage-completion lines are printed by done()

  auto now = std::chrono::steady_clock::now();
  double since = std::chrono::duration<double>(now - last_render_).count();
  if (!force && since < 0.10) return;  // throttle to ~10 fps
  last_render_ = now;

  double s =
      std::chrono::duration<double>(now - start_).count();
  int mins = static_cast<int>(s) / 60;
  int secs = static_cast<int>(s) % 60;

  // ширина экрана: на узких (мобильные эмуляторы, сплит-окна) бар сжимаем,
  // на совсем узких убираем, метку обрезаем — строка не переносится
  int cols = terminal_width(80);
  if (cols < 24) cols = 24;
  if (cols > 240) cols = 240;
  // [mikto](8) + module(9) + sep(2) + done/total(11) + sep(2) + time(5)
  const size_t fixed = 37;

  char line[512];
  if (total_ > 0) {
    size_t avail = static_cast<size_t>(cols);
    if (avail >= 62) {
      // + sep(2) вокруг бара
      size_t bar_w = avail >= 96 ? 22 : (avail >= 78 ? 16 : 12);
      size_t rest = avail > fixed + bar_w + 2 ? avail - fixed - bar_w - 2 : 8;
      std::snprintf(line, sizeof line,
                    "\r\033[K[mikto] %-9s %s  %s  %zu/%zu  %2d:%02d",
                    module_.c_str(), fit_label(label_, rest).c_str(),
                    bar_locked(bar_w).c_str(), done_.load(), total_, mins,
                    secs);
    } else {
      size_t rest = avail > fixed + 2 ? avail - fixed - 2 : 8;
      std::snprintf(line, sizeof line,
                    "\r\033[K[mikto] %-9s %s  %zu/%zu  %2d:%02d",
                    module_.c_str(), fit_label(label_, rest).c_str(),
                    done_.load(), total_, mins, secs);
    }
    std::fputs(line, stderr);
  } else {
    static const char kSpin[] = "|/-\\";
    size_t idx = static_cast<size_t>(s * 8) % 4;
    size_t rest = static_cast<size_t>(cols) > fixed + 2
                      ? static_cast<size_t>(cols) - fixed - 2
                      : 12;
    // в спине на 4 колонки шире: спиннер + два разделителя вместо бара
    size_t label_budget = rest > 8 ? rest - 4 : rest;
    std::snprintf(line, sizeof line, "\r\033[K[mikto] %-9s %s %c %s  %2d:%02d",
                  module_.c_str(), fit_label(label_, label_budget).c_str(),
                  kSpin[idx], fit_label(item_, rest).c_str(), mins, secs);
    std::fputs(line, stderr);
  }
  std::fflush(stderr);
}

}  // namespace mikto
