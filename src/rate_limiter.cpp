#include "mikto/rate_limiter.hpp"

#include <thread>

namespace mikto {

void RateLimiter::acquire() {
  std::unique_lock<std::mutex> lock(m_);
  while (true) {
    auto now = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(now - last_).count();
    tokens_ = std::min(burst_, tokens_ + elapsed * rate_);
    last_ = now;
    if (tokens_ >= 1.0) {
      tokens_ -= 1.0;
      return;
    }
    double need = (1.0 - tokens_) / rate_;
    lock.unlock();
    // спим дробно: целые мс давали busy-spin
    std::this_thread::sleep_for(std::chrono::duration<double>(need));
    lock.lock();
  }
}

}  // namespace mikto
