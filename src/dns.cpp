#include "mikto/dns.hpp"

#include "mikto/win_compat.hpp"

#include <atomic>
#include <chrono>
#include <cstring>
#include <fstream>
#include <random>

#include "mikto/net.hpp"
#include "mikto/util.hpp"

namespace mikto {

namespace {

constexpr size_t kMaxPacket = 65536;

uint16_t rd16(const uint8_t* p) {
  return static_cast<uint16_t>((p[0] << 8) | p[1]);
}
uint32_t rd32(const uint8_t* p) {
  return (static_cast<uint32_t>(p[0]) << 24) |
         (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}
void wr16(std::string& s, uint16_t v) {
  s.push_back(static_cast<char>(v >> 8));
  s.push_back(static_cast<char>(v & 0xff));
}

// потокобезопасно
uint16_t next_id() {
  static std::atomic<uint16_t> counter{0};
  uint16_t base = counter.fetch_add(1);
  std::random_device rd;
  return static_cast<uint16_t>(base ^ rd());
}

std::string ip_to_arpa(const std::string& ip) {
  sockaddr_in sa4{};
  sockaddr_in6 sa6{};
  if (inet_pton(AF_INET, ip.c_str(), &sa4.sin_addr) == 1) {
    unsigned char* a = reinterpret_cast<unsigned char*>(&sa4.sin_addr);
    std::string out;
    for (int i = 3; i >= 0; --i) {
      out += std::to_string(a[i]);
      out += ".";
    }
    return out + "in-addr.arpa";
  }
  if (inet_pton(AF_INET6, ip.c_str(), &sa6.sin6_addr) == 1) {
    unsigned char* a = reinterpret_cast<unsigned char*>(&sa6.sin6_addr);
    std::string out;
    for (int i = 15; i >= 0; --i) {
      static const char* hex = "0123456789abcdef";
      out.push_back(hex[a[i] & 0xf]);
      out.push_back('.');
      out.push_back(hex[a[i] >> 4]);
      out.push_back('.');
    }
    return out + "ip6.arpa";
  }
  return "";
}

}  // namespace

std::string dns_type_name(uint16_t type) {
  switch (type) {
    case kDnsA: return "A";
    case kDnsNS: return "NS";
    case kDnsCNAME: return "CNAME";
    case kDnsSOA: return "SOA";
    case kDnsPTR: return "PTR";
    case kDnsMX: return "MX";
    case kDnsTXT: return "TXT";
    case kDnsAAAA: return "AAAA";
    case kDnsCAA: return "CAA";
    case kDnsAXFR: return "AXFR";
    default: return "TYPE" + std::to_string(type);
  }
}

std::string dns_encode_name(const std::string& qname, bool& ok) {
  ok = true;
  if (qname.empty() || qname.size() > 253) {
    ok = false;
    return "";
  }
  std::string out;
  size_t start = 0;
  for (size_t i = 0; i <= qname.size(); ++i) {
    if (i == qname.size() || qname[i] == '.') {
      size_t label = i - start;
      if (label == 0 || label > 63) {
        ok = false;
        return "";
      }
      out.push_back(static_cast<char>(label));
      out.append(qname, start, label);
      start = i + 1;
    }
  }
  out.push_back('\0');
  return out;
}

std::string dns_decode_name(const uint8_t* buf, size_t len, size_t& off,
                            int max_jumps) {
  if (!buf || off >= len) return "";
  std::string out;
  size_t cursor = off;
  bool jumped = false;
  size_t end_off = off;  // продолжение в исходном стриме
  int jumps = 0;

  for (;;) {
    if (cursor >= len) return "";
    uint8_t b = buf[cursor];
    if (b == 0) {
      if (!jumped) end_off = cursor + 1;
      break;
    }
    if ((b & 0xc0) == 0xc0) {
      if (cursor + 1 >= len) return "";
      size_t ptr = static_cast<size_t>((b & 0x3f) << 8 | buf[cursor + 1]);
      if (!jumped) end_off = cursor + 2;
      jumped = true;
      if (++jumps > max_jumps || ptr >= len) return "";
      cursor = ptr;
      continue;
    }
    // обычная метка
    size_t label_len = b;
    if (cursor + 1 + label_len > len) return "";
    if (!out.empty()) out.push_back('.');
    for (size_t i = 0; i < label_len; ++i) {
      char c = static_cast<char>(buf[cursor + 1 + i]);
      if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
      out.push_back(c);
    }
    if (out.size() > 253) return "";
    cursor += 1 + label_len;
    if (!jumped) end_off = cursor;
  }
  off = end_off;
  return out;
}

std::string dns_format_rdata(const uint8_t* msg, size_t len, size_t rdoff,
                             size_t rdlen, uint16_t type) {
  if (rdoff + rdlen > len) return "";
  char addr[INET6_ADDRSTRLEN] = {0};
  switch (type) {
    case kDnsA: {
      if (rdlen != 4) return "";
      if (inet_ntop(AF_INET, msg + rdoff, addr, sizeof addr)) return addr;
      return "";
    }
    case kDnsAAAA: {
      if (rdlen != 16) return "";
      if (inet_ntop(AF_INET6, msg + rdoff, addr, sizeof addr)) return addr;
      return "";
    }
    case kDnsNS:
    case kDnsCNAME:
    case kDnsPTR: {
      size_t o = rdoff;
      return dns_decode_name(msg, len, o);
    }
    case kDnsMX: {
      if (rdlen < 3) return "";
      uint16_t pref = rd16(msg + rdoff);
      size_t o = rdoff + 2;
      std::string host = dns_decode_name(msg, len, o);
      if (host.empty()) return "";
      return std::to_string(pref) + " " + host;
    }
    case kDnsTXT: {
      std::string out;
      size_t p = rdoff;
      const size_t end = rdoff + rdlen;
      while (p < end) {
        uint8_t sl = msg[p++];
        if (p + sl > end) return out;
        out.append(reinterpret_cast<const char*>(msg + p), sl);
        p += sl;
      }
      return out;
    }
    case kDnsSOA: {
      size_t o = rdoff;
      std::string mname = dns_decode_name(msg, len, o);
      std::string rname = dns_decode_name(msg, len, o);
      if (o + 20 > len) return mname.empty() ? "" : mname;
      uint32_t serial = rd32(msg + o);
      std::string out = mname + " " + rname + " serial=" + std::to_string(serial);
      return out;
    }
    case kDnsCAA: {
      if (rdlen < 2) return "";
      uint8_t flags = msg[rdoff];
      uint8_t tlen = msg[rdoff + 1];
      if (rdoff + 2 + tlen > rdoff + rdlen) return "";
      std::string tag(reinterpret_cast<const char*>(msg + rdoff + 2), tlen);
      std::string val(reinterpret_cast<const char*>(msg + rdoff + 2 + tlen),
                      rdlen - 2 - tlen);
      return std::to_string(flags) + " " + tag + " \"" + val + "\"";
    }
    default:
      return "(" + std::to_string(rdlen) + " bytes)";
  }
}

std::vector<DnsRecord> dns_parse_response(const uint8_t* buf, size_t len) {
  std::vector<DnsRecord> out;
  if (len < 12) return out;
  uint16_t qd = rd16(buf + 4);
  uint16_t an = rd16(buf + 6);
  size_t off = 12;
  // Skip questions.
  for (uint16_t i = 0; i < qd; ++i) {
    dns_decode_name(buf, len, off);
    if (off + 4 > len) return out;
    off += 4;
  }
  // answers + authority, там NS/SOA зоны
  uint16_t total = static_cast<uint16_t>(an);
  total = static_cast<uint16_t>(total + rd16(buf + 8));   // nscount
  total = static_cast<uint16_t>(total + rd16(buf + 10));  // arcount
  for (uint16_t i = 0; i < total; ++i) {
    if (off >= len) break;
    std::string name = dns_decode_name(buf, len, off);
    if (off + 10 > len) break;
    uint16_t type = rd16(buf + off);
    // uint16_t klass = rd16(buf + off + 2);  // always IN for our use
    uint32_t ttl = rd32(buf + off + 4);
    uint16_t rdlen = rd16(buf + off + 8);
    off += 10;
    if (off + rdlen > len) break;
    DnsRecord r;
    r.type = dns_type_name(type);
    r.name = name;
    r.ttl = ttl;
    r.value = dns_format_rdata(buf, len, off, rdlen, type);
    if (!r.value.empty()) out.push_back(std::move(r));
    off += rdlen;
  }
  return out;
}

std::vector<std::string> dns_resolvers() {
  std::vector<std::string> out;
  std::ifstream f("/etc/resolv.conf");
  std::string line;
  while (out.size() < 3 && std::getline(f, line)) {
    line = trim(line);
    if (starts_with(line, "nameserver ")) {
      std::string ns = trim(line.substr(11));
      if (!ns.empty() && ns.find(':') == std::string::npos)  // IPv4 for now
        out.push_back(ns);
    }
  }
  if (out.empty()) {
    out.push_back("1.1.1.1");
    out.push_back("8.8.8.8");
  }
  return out;
}

std::vector<DnsRecord> dns_query(const std::string& qname, uint16_t qtype,
                                 int timeout_ms, int& rcode, std::string& err) {
  rcode = -1;
  std::vector<DnsRecord> out;
  bool ok = false;
  std::string wire = dns_encode_name(qname, ok);
  if (!ok) {
    err = "invalid qname: " + qname;
    return out;
  }
  uint16_t id = next_id();

  std::string pkt;
  pkt.reserve(18 + wire.size());
  wr16(pkt, id);
  wr16(pkt, 0x0100);  // RD=1
  wr16(pkt, 1);       // qdcount
  wr16(pkt, 0);
  wr16(pkt, 0);
  wr16(pkt, 0);
  pkt += wire;
  wr16(pkt, qtype);
  wr16(pkt, 1);  // IN

  for (const std::string& resolver : dns_resolvers()) {
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(53);
    if (inet_pton(AF_INET, resolver.c_str(), &sa.sin_addr) != 1) continue;

    UniqueFd fd(static_cast<int>(socket(AF_INET, SOCK_DGRAM, 0)));
    if (!fd.valid()) {
      err = "socket() failed";
      continue;
    }
    // один корректный запрос влезает в один дейтаграмм
    auto sent = sendto(fd.get(), pkt.data(),
                       static_cast<int>(pkt.size()), 0,
                       reinterpret_cast<sockaddr*>(&sa),
                       static_cast<mikto_socklen_t>(sizeof sa));
    if (sent < 0) {
      err = "sendto failed";
      continue;
    }

    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(timeout_ms);
    std::string buf;
    buf.resize(kMaxPacket);
    while (std::chrono::steady_clock::now() < deadline) {
      int remain = static_cast<int>(
          std::chrono::duration_cast<std::chrono::milliseconds>(
              deadline - std::chrono::steady_clock::now())
              .count());
      if (remain <= 0) break;
      pollfd p{fd.get(), POLLIN, 0};
      int pr = poll(&p, 1, remain);
      if (pr <= 0) continue;  // timeout -> try next resolver
      sockaddr_in from{};
      mikto_socklen_t flen = sizeof from;
      auto n = recvfrom(fd.get(), buf.data(),
                        static_cast<int>(buf.size()), 0,
                        reinterpret_cast<sockaddr*>(&from), &flen);
      if (n < 12) continue;
      if (rd16(reinterpret_cast<const uint8_t*>(buf.data())) != id) continue;
      uint16_t flags = rd16(reinterpret_cast<const uint8_t*>(buf.data()) + 2);
      rcode = static_cast<int>(flags & 0x000f);
      if (rcode == 3) return out;  // nxdomain, точно нет такого имени
      if (rcode != 0) {
        err = "DNS rcode " + std::to_string(rcode);
        continue;
      }
      out = dns_parse_response(reinterpret_cast<const uint8_t*>(buf.data()),
                               static_cast<size_t>(n));
      return out;
    }
    err = "DNS timeout (" + resolver + ")";
  }
  return out;
}

bool dns_resolve(const std::string& name, std::vector<std::string>& ips,
                 int timeout_ms) {
  ips.clear();
  int rc = 0;
  std::string err;
  for (uint16_t t : {kDnsA, kDnsAAAA}) {
    auto recs = dns_query(name, t, timeout_ms, rc, err);
    for (const auto& r : recs) {
      if (r.type == "A" || r.type == "AAAA")
        if (ips.size() < 8 &&
            std::find(ips.begin(), ips.end(), r.value) == ips.end())
          ips.push_back(r.value);
    }
  }
  // udp/53 глухой, getaddrinfo в последнюю очередь
  if (ips.empty() && rc != 3 && !err.empty()) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(name.c_str(), nullptr, &hints, &res) == 0 && res) {
      std::vector<std::string> seen;
      for (addrinfo* ai = res; ai && ips.size() < 8; ai = ai->ai_next) {
        char buf[INET6_ADDRSTRLEN] = {0};
        if (ai->ai_family == AF_INET) {
          auto* sa = reinterpret_cast<sockaddr_in*>(ai->ai_addr);
          inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof buf);
        } else if (ai->ai_family == AF_INET6) {
          auto* sa = reinterpret_cast<sockaddr_in6*>(ai->ai_addr);
          inet_ntop(AF_INET6, &sa->sin6_addr, buf, sizeof buf);
        } else {
          continue;
        }
        if (std::find(seen.begin(), seen.end(), buf) == seen.end()) {
          seen.push_back(buf);
          ips.push_back(buf);
        }
      }
      freeaddrinfo(res);
    }
  }
  return !ips.empty();
}

std::string dns_reverse(const std::string& ip, int timeout_ms) {
  std::string arpa = ip_to_arpa(ip);
  if (arpa.empty()) return "";
  int rc = 0;
  std::string err;
  auto recs = dns_query(arpa, kDnsPTR, timeout_ms, rc, err);
  for (const auto& r : recs)
    if (r.type == "PTR" && !r.value.empty()) return r.value;
  return "";
}

std::vector<DnsRecord> dns_all_records(const std::string& name,
                                       int timeout_ms, std::string* err) {
  std::vector<DnsRecord> out;
  std::string last_err;
  int rc = 0;
  for (uint16_t t : {kDnsA, kDnsAAAA, kDnsMX, kDnsNS, kDnsTXT, kDnsSOA,
                     kDnsCAA}) {
    auto recs = dns_query(name, t, timeout_ms, rc, last_err);
    for (auto& r : recs) out.push_back(std::move(r));
  }
  if (err) *err = last_err;
  return out;
}

bool dns_axfr(const std::string& zone, const std::string& ns_host,
              std::vector<std::string>& records, int timeout_ms) {
  bool ok = false;
  std::string wire = dns_encode_name(zone, ok);
  if (!ok) return false;
  uint16_t id = next_id();
  std::string pkt;
  wr16(pkt, id);
  wr16(pkt, 0x0000);  // no RD for AXFR
  wr16(pkt, 1);
  wr16(pkt, 0);
  wr16(pkt, 0);
  wr16(pkt, 0);
  pkt += wire;
  wr16(pkt, kDnsAXFR);
  wr16(pkt, 1);

  std::string err;
  UniqueFd fd = tcp_connect(ns_host, 53, timeout_ms, err);
  if (!fd.valid()) return false;

  std::string framed;
  wr16(framed, static_cast<uint16_t>(pkt.size()));
  framed += pkt;
  if (!send_all(fd.get(), framed, timeout_ms)) return false;

  // отказ axfr: закрытие или 0 answers
  std::string stream = read_available(fd.get(), timeout_ms, 128 * 1024);
  if (stream.size() < 2 + 12) return false;

  // tcp-framing: длина + сообщение
  size_t off = 0;
  int soa_count = 0;
  int parsed = 0;
  while (off + 2 <= stream.size() && parsed < 64) {
    uint16_t mlen = rd16(reinterpret_cast<const uint8_t*>(stream.data()) + off);
    if (mlen == 0 || off + 2 + mlen > stream.size()) break;
    const uint8_t* msg = reinterpret_cast<const uint8_t*>(stream.data()) + off + 2;
    size_t mlen_sz = mlen;
    if (mlen_sz < 12) break;
    if (rd16(msg) != id) break;  // wrong id -> not our transfer
    uint16_t rcode = rd16(msg + 2) & 0x000f;
    if (rcode != 0) return false;  // REFUSED / NOTAUTH etc.
    auto recs = dns_parse_response(msg, mlen_sz);
    for (const auto& r : recs) {
      if (r.type == "SOA") ++soa_count;
      std::string line = r.type + " " + r.name + " -> " + r.value;
      records.push_back(std::move(line));
    }
    off += 2 + mlen;
    ++parsed;
    // зона кончилась, SOA повторился
    if (soa_count >= 2) {
      return true;  // full transfer received
    }
  }
  // частичный стрим с SOA тоже улика
  return !records.empty() && soa_count >= 1;
}

}  // namespace mikto
