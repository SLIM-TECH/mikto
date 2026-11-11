// тесты emailsec
#include "test_fw.hpp"

#include "modules/modules.hpp"

using namespace mikto;

MIKTO_TEST(spf_rejects_non_spf_records) {
  SpfPolicy p = evaluate_spf("v=DMARC1; p=reject");
  CHECK(!p.valid);
  p = evaluate_spf("hello world");
  CHECK(!p.valid);
  p = evaluate_spf("");
  CHECK(!p.valid);
}

MIKTO_TEST(spf_strict_policy) {
  SpfPolicy p = evaluate_spf("v=spf1 include:_spf.google.com ip4:198.51.100.0/24 -all");
  CHECK(p.valid);
  CHECK_EQ(p.all_policy, std::string("fail"));
  CHECK_EQ(p.lookup_count, 1);  // include ест лимит, ip4 нет
  CHECK_EQ(p.includes.size(), size_t(1));
  CHECK(!p.private_ip4);
}

MIKTO_TEST(spf_plus_all_is_allow_all) {
  SpfPolicy p = evaluate_spf("v=spf1 +all");
  CHECK(p.valid);
  CHECK_EQ(p.all_policy, std::string("allow_all"));
}

MIKTO_TEST(spf_missing_all_mechanism) {
  SpfPolicy p = evaluate_spf("v=spf1 ip4:203.0.113.0/24");
  CHECK(p.valid);
  CHECK_EQ(p.all_policy, std::string("missing"));
}

MIKTO_TEST(spf_softfail_and_neutral) {
  CHECK_EQ(evaluate_spf("v=spf1 ~all").all_policy, std::string("softfail"));
  CHECK_EQ(evaluate_spf("v=spf1 ?all").all_policy, std::string("neutral"));
}

MIKTO_TEST(spf_lookup_counting) {
  SpfPolicy p = evaluate_spf(
      "v=spf1 a mx ptr exists:ex.com include:a.com include:b.com redirect=c.com -all");
  CHECK(p.valid);
  CHECK_EQ(p.lookup_count, 7);
}

MIKTO_TEST(spf_private_ranges_flagged) {
  CHECK(evaluate_spf("v=spf1 ip4:127.0.0.1 -all").private_ip4);
  CHECK(evaluate_spf("v=spf1 ip4:10.0.0.0/8 -all").private_ip4);
  CHECK(evaluate_spf("v=spf1 ip4:192.168.1.1 -all").private_ip4);
  CHECK(evaluate_spf("v=spf1 ip4:172.16.5.4 -all").private_ip4);
  CHECK(evaluate_spf("v=spf1 ip4:172.31.9.9 -all").private_ip4);
  CHECK(!evaluate_spf("v=spf1 ip4:172.32.0.1 -all").private_ip4);
  CHECK(!evaluate_spf("v=spf1 ip4:198.51.100.7 -all").private_ip4);
  CHECK(evaluate_spf("v=spf1 ip4:0.0.0.0/0 -all").private_ip4);
}

MIKTO_TEST(spf_is_case_insensitive_on_version_tag) {
  SpfPolicy p = evaluate_spf("V=SPF1 -ALL");
  CHECK(p.valid);
  CHECK_EQ(p.all_policy, std::string("fail"));
}

MIKTO_TEST(dmarc_full_policy) {
  DmarcPolicy d = evaluate_dmarc(
      "v=DMARC1; p=reject; sp=quarantine; pct=50; rua=mailto:dmarc@ex.com");
  CHECK(d.valid);
  CHECK_EQ(d.p, std::string("reject"));
  CHECK_EQ(d.sp, std::string("quarantine"));
  CHECK_EQ(d.pct, 50);
  CHECK(d.has_rua);
}

MIKTO_TEST(dmarc_missing_p_flagged) {
  DmarcPolicy d = evaluate_dmarc("v=DMARC1; rua=mailto:x@ex.com");
  CHECK(d.valid);
  CHECK(d.p.empty());
  CHECK(d.has_rua);
  d = evaluate_dmarc("v=DMARC1; p=none");
  CHECK_EQ(d.pct, 100);
  CHECK(!d.has_rua);
}

MIKTO_TEST(dmarc_invalid_version_rejected) {
  DmarcPolicy d = evaluate_dmarc("v=DMARC2; p=reject");
  CHECK(!d.valid);
}

MIKTO_TEST(dkim_selector_list_sane) {
  const auto& sels = dkim_selectors();
  CHECK(sels.size() >= 10);
  bool has_google = false, has_default = false;
  for (const auto& s : sels) {
    if (s == "google") has_google = true;
    if (s == "default") has_default = true;
  }
  CHECK(has_google);
  CHECK(has_default);
}
