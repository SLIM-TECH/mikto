// mikto — raw tcp клиент. posix-сокеты, на windows — winsock2.
#include "mikto/net.hpp"

#include "mikto/win_compat.hpp"

#include <cerrno>
#include <chrono>
#include <cstring>

namespace mikto {

void UniqueFd::reset(int fd) {
  if (fd_ >= 0) sock_close(fd_);
  fd_ = fd;
}

UniqueFd tcp_connect(const std::string& host, uint16_t port, int timeout_ms,
                     std::string& err) {
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* res = nullptr;
  int rc = getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res);
  if (rc != 0) {
    err = "address resolution failed for " + host + ": " + gai_strerror(rc);
    return UniqueFd{};
  }
  struct AddrGuard {
    addrinfo* p;
    ~AddrGuard() {
      if (p) freeaddrinfo(p);
    }
  } guard{res};

  std::string last_err;
  for (addrinfo* ai = res; ai; ai = ai->ai_next) {
    int fd = static_cast<int>(
        ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol));
    if (fd < 0) {
      last_err = sock_err_str(sock_errno());
      continue;
    }
#ifdef _WIN32
    u_long mode = 1;
    ::ioctlsocket(fd, FIONBIO, &mode);
#else
    int flags = ::fcntl(fd, F_GETFL, 0);
    ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif

    int cr = ::connect(fd, ai->ai_addr, static_cast<int>(ai->ai_addrlen));
    if (cr != 0) {
      if (sock_errno() != MIKTO_EINPROGRESS) {
        last_err = sock_err_str(sock_errno());
        sock_close(fd);
        continue;
      }
      pollfd p{};
      p.fd = fd;
      p.events = POLLOUT;
      int pr = ::poll(&p, 1, timeout_ms);
      if (pr <= 0) {
        last_err =
            (pr == 0) ? "connect timeout" : sock_err_str(sock_errno());
        sock_close(fd);
        continue;
      }
      int soerr = 0;
      mikto_socklen_t len = sizeof(soerr);
      ::getsockopt(fd, SOL_SOCKET, SO_ERROR,
                   reinterpret_cast<char*>(&soerr), &len);
      if (soerr != 0) {
        last_err = sock_err_str(soerr);
        sock_close(fd);
        continue;
      }
    }
    // обратно в блокирующий режим, таймауты recv/send как страховка
#ifdef _WIN32
    u_long block = 0;
    ::ioctlsocket(fd, FIONBIO, &block);
    DWORD tv = static_cast<DWORD>(timeout_ms);
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
                 reinterpret_cast<const char*>(&tv), sizeof tv);
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO,
                 reinterpret_cast<const char*>(&tv), sizeof tv);
#else
    ::fcntl(fd, F_SETFL, flags);
    timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
#endif
    return UniqueFd(fd);
  }
  err = "connect failed: " + last_err;
  return UniqueFd{};
}

bool send_all(int fd, const std::string& data, int timeout_ms) {
  size_t off = 0;
  auto deadline =
      std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
  while (off < data.size()) {
    auto n = ::send(fd, data.data() + off,
                    static_cast<int>(data.size() - off), MIKTO_MSG_NOSIGNAL);
    if (n > 0) {
      off += static_cast<size_t>(n);
      continue;
    }
    if (n < 0 && sock_errno() == MIKTO_EWOULDBLOCK) {
      if (std::chrono::steady_clock::now() >= deadline) return false;
      pollfd p{};
      p.fd = fd;
      p.events = POLLOUT;
      ::poll(&p, 1, 100);
      continue;
    }
    if (n < 0 && sock_errno() == MIKTO_EINTR) continue;
    return false;
  }
  return true;
}

std::string read_available(int fd, int total_timeout_ms, size_t max_bytes) {
  std::string out;
  auto deadline =
      std::chrono::steady_clock::now() + std::chrono::milliseconds(total_timeout_ms);
  bool got_any = false;
  while (out.size() < max_bytes) {
    auto now = std::chrono::steady_clock::now();
    if (now >= deadline) break;
    int wait_ms = got_any
                      ? 250
                      : static_cast<int>(std::chrono::duration_cast<
                                             std::chrono::milliseconds>(deadline - now)
                                             .count());
    pollfd p{};
    p.fd = fd;
    p.events = POLLIN;
    int pr = ::poll(&p, 1, wait_ms);
    if (pr <= 0) {
      if (pr < 0 && sock_errno() == MIKTO_EINTR) continue;
      break;
    }
    char buf[2048];
    auto n = ::recv(fd, buf, sizeof buf, 0);
    if (n < 0) {
      if (sock_errno() == MIKTO_EINTR) continue;
      break;
    }
    if (n == 0) break;  // peer закрыл соединение
    out.append(buf, buf + n);
    got_any = true;
  }
  return out;
}

}  // namespace mikto
