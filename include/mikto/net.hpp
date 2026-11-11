#pragma once
// mikto — сырой tcp клиент
#include <cstdint>
#include <optional>
#include <string>

namespace mikto {

// единственный владелец сырого fd
class UniqueFd {
 public:
  UniqueFd() = default;
  explicit UniqueFd(int fd) : fd_(fd) {}
  UniqueFd(const UniqueFd&) = delete;
  UniqueFd& operator=(const UniqueFd&) = delete;
  UniqueFd(UniqueFd&& o) noexcept : fd_(o.fd_) { o.fd_ = -1; }
  UniqueFd& operator=(UniqueFd&& o) noexcept {
    if (this != &o) {
      reset();
      fd_ = o.fd_;
      o.fd_ = -1;
    }
    return *this;
  }
  ~UniqueFd() { reset(); }

  int get() const { return fd_; }
  bool valid() const { return fd_ >= 0; }
  int release() {
    int f = fd_;
    fd_ = -1;
    return f;
  }
  void reset(int fd = -1);

 private:
  int fd_ = -1;
};

// при ошибке fd невалидный, причина в err
UniqueFd tcp_connect(const std::string& host, uint16_t port, int timeout_ms,
                     std::string& err);

// false на ошибке или таймауте
bool send_all(int fd, const std::string& data, int timeout_ms);

// "" = ничего не пришло, это не ошибка
std::string read_available(int fd, int total_timeout_ms, size_t max_bytes = 4096);

}  // namespace mikto
