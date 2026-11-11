#pragma once
// mikto — token bucket на всю сеть
#include <chrono>
#include <mutex>

namespace mikto {

class RateLimiter {
 public:
  explicit RateLimiter(double rate_per_sec, double burst = 0.0)
      : rate_(rate_per_sec > 0 ? rate_per_sec : 1.0),
        burst_(burst > 0 ? burst : (rate_per_sec > 0 ? rate_per_sec : 1.0)),
        tokens_(burst > 0 ? burst : (rate_per_sec > 0 ? rate_per_sec : 1.0)),
        last_(std::chrono::steady_clock::now()) {}

  // ждём токен
  void acquire();

  double rate() const { return rate_; }

 private:
  double rate_;
  double burst_;
  double tokens_;
  std::chrono::steady_clock::time_point last_;
  std::mutex m_;
};

}  // namespace mikto
