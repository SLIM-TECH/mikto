// тесты секретов
#include "test_fw.hpp"

#include "modules/modules.hpp"

using namespace mikto;

MIKTO_TEST(secrets_aws_key) {
  std::vector<Finding> out;
  scan_body_for_secrets("https://t.example/main.js",
                        "var cfg = {key:'AKIAIOSFODNN7EXAMPLE'};", out);
  CHECK_EQ(out.size(), size_t(1));
  CHECK(out[0].title.find("AWS access key id") != std::string::npos);
  CHECK(out[0].severity == Severity::High);
  // ключ не печатается целиком
  CHECK(out[0].evidence.find("AKIAIO") == std::string::npos ||
        out[0].evidence.find("(redacted)") != std::string::npos);
  CHECK(out[0].evidence.find("IOSFODNN7EXAMPLE") == std::string::npos);
  CHECK_EQ(out[0].host, std::string("t.example"));
  CHECK_EQ(out[0].port, 443);
}

MIKTO_TEST(secrets_private_key) {
  std::vector<Finding> out;
  scan_body_for_secrets("http://t.example/backup.txt",
                        "-----BEGIN RSA PRIVATE KEY-----\nMIIE...", out);
  CHECK_EQ(out.size(), size_t(1));
  CHECK(out[0].severity == Severity::Critical);
}

MIKTO_TEST(secrets_google_and_slack) {
  std::vector<Finding> out;
  std::string body = "gapi: AIzaSyA1234567890abcdefghijklmnopqrstuv\n"
                     "slack: xoxb-123456789012-abcdefghijk";
  scan_body_for_secrets("https://t.example/", body, out);
  CHECK_EQ(out.size(), size_t(2));
}

MIKTO_TEST(secrets_clean_body_no_findings) {
  std::vector<Finding> out;
  scan_body_for_secrets("https://t.example/",
                        "<html><body>nothing here</body></html>", out);
  CHECK_EQ(out.size(), size_t(0));
}

MIKTO_TEST(secrets_no_full_key_in_evidence) {
  std::vector<Finding> out;
  std::string key = "AKIA" + std::string(16, 'A');
  scan_body_for_secrets("https://t.example/", "k=" + key, out);
  CHECK_EQ(out.size(), size_t(1));
  CHECK(out[0].evidence.find(key) == std::string::npos);
  CHECK(out[0].evidence.find("(redacted)") != std::string::npos);
}
