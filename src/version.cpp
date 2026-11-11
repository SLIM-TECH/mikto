#include "mikto/version.hpp"

#include <algorithm>
#include <cctype>

#include "mikto/util.hpp"

namespace mikto {

namespace {

// цифры численно, остальное побайтово
int natural_cmp(const std::string& a, const std::string& b) {
  size_t i = 0, j = 0;
  while (i < a.size() && j < b.size()) {
    if (std::isdigit(static_cast<unsigned char>(a[i])) &&
        std::isdigit(static_cast<unsigned char>(b[j]))) {
      long long na = 0, nb = 0;
      while (i < a.size() && std::isdigit(static_cast<unsigned char>(a[i]))) {
        na = na * 10 + (a[i] - '0');
        ++i;
      }
      while (j < b.size() && std::isdigit(static_cast<unsigned char>(b[j]))) {
        nb = nb * 10 + (b[j] - '0');
        ++j;
      }
      if (na != nb) return na < nb ? -1 : 1;
    } else {
      if (a[i] != b[j]) return a[i] < b[j] ? -1 : 1;
      ++i;
      ++j;
    }
  }
  if (i < a.size()) return 1;
  if (j < b.size()) return -1;
  return 0;
}

}  // namespace

int compare_versions(const std::string& a, const std::string& b) {
  auto segs_a = split(a, '.');
  auto segs_b = split(b, '.');
  size_t n = std::max(segs_a.size(), segs_b.size());
  for (size_t k = 0; k < n; ++k) {
    std::string sa = k < segs_a.size() ? segs_a[k] : "0";
    std::string sb = k < segs_b.size() ? segs_b[k] : "0";
    int c = natural_cmp(sa, sb);
    if (c != 0) return c;
  }
  return 0;
}

}  // namespace mikto
