#pragma once
// mikto — сокеты posix и winsock через один интерфейс
#include <string>
#include <thread>

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
  #endif
  #ifndef NOMINMAX
  #define NOMINMAX
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <io.h>

  // в winsock функция называется WSAPoll, зовём одинаково везде
  #define poll WSAPoll

  #define MIKTO_MSG_NOSIGNAL 0
  #define MIKTO_EWOULDBLOCK WSAEWOULDBLOCK
  #define MIKTO_EINPROGRESS WSAEWOULDBLOCK
  #define MIKTO_EINTR 0

  namespace mikto {

  inline int sock_close(int fd) { return ::closesocket(fd); }
  inline int sock_errno() { return WSAGetLastError(); }
  inline std::string sock_err_str(int e) {
    char buf[160];
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, static_cast<DWORD>(e),
                   MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buf, sizeof buf,
                   nullptr);
    std::string s(buf);
    while (!s.empty() &&
           (s.back() == '\n' || s.back() == '\r' || s.back() == ' '))
      s.pop_back();
    return s.empty() ? ("wsa error " + std::to_string(e)) : s;
  }

  using mikto_socklen_t = int;

  // winsock надо разбудить до любых сокетов, иначе всё молча падает
  struct WsaInit {
    WsaInit() {
      WSADATA d;
      WSAStartup(MAKEWORD(2, 2), &d);
    }
    ~WsaInit() { WSACleanup(); }
  };

  }  // namespace mikto

#else  // posix

  #include <arpa/inet.h>
  #include <fcntl.h>
  #include <netdb.h>
  #include <netinet/in.h>
  #include <poll.h>
  #include <sys/ioctl.h>
  #include <sys/socket.h>
  #include <unistd.h>
  #include <cstring>
  #include <cstdlib>

  #define MIKTO_MSG_NOSIGNAL MSG_NOSIGNAL
  #define MIKTO_EWOULDBLOCK EAGAIN
  #define MIKTO_EINPROGRESS EINPROGRESS
  #define MIKTO_EINTR EINTR

  namespace mikto {

  inline int sock_close(int fd) { return ::close(fd); }
  inline int sock_errno() { return errno; }
  inline std::string sock_err_str(int e) { return std::strerror(e); }

  using mikto_socklen_t = socklen_t;

  // на posix ничего инициализировать не надо
  struct WsaInit {};

  }  // namespace mikto

#endif

namespace mikto {

// jthread есть не во всех станах (termux/старые ndk) — единая точка фолбэка.
// код обязан явно join'ить: у std::thread деструктор без join() = terminate
#if defined(__cpp_lib_jthread)
using mikto_thread = std::jthread;
#else
using mikto_thread = std::thread;
#endif

inline bool is_stdin_tty() {
#ifdef _WIN32
  return _isatty(_fileno(stdin)) != 0;
#else
  return isatty(STDIN_FILENO) != 0;
#endif
}
inline bool is_stdout_tty() {
#ifdef _WIN32
  return _isatty(_fileno(stdout)) != 0;
#else
  return isatty(STDOUT_FILENO) != 0;
#endif
}
inline bool is_stderr_tty() {
#ifdef _WIN32
  return _isatty(_fileno(stderr)) != 0;
#else
  return isatty(STDERR_FILENO) != 0;
#endif
}

// ширина терминала в колонках; узким экранам (ssh, мобильные эмуляторы)
// прогресс рисуем компактнее. ioctl -> COLUMNS -> fallback
inline int terminal_width(int fallback = 80) {
#ifdef _WIN32
  CONSOLE_SCREEN_BUFFER_INFO csbi;
  HANDLE h = GetStdHandle(STD_ERROR_HANDLE);
  if (h && h != INVALID_HANDLE_VALUE && GetConsoleScreenBufferInfo(h, &csbi))
    return csbi.srWindow.Right - csbi.srWindow.Left + 1;
#else
  struct winsize ws;
  if (ioctl(STDERR_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0)
    return ws.ws_col;
#endif
  if (const char* c = std::getenv("COLUMNS")) {
    int v = std::atoi(c);
    if (v > 0) return v;
  }
  return fallback;
}

}  // namespace mikto
