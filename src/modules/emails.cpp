// mikto — пассивный сбор имейлов: crt.sh + свои страницы
#include "modules.hpp"

#include <algorithm>
#include <set>
#include <vector>

#include "mikto/rate_limiter.hpp"
#include "mikto/util.hpp"

namespace mikto {

// чистый экстрактор

namespace {

bool valid_local_char(unsigned char c) {
  return std::isalnum(c) || c == '.' || c == '-' || c == '_' || c == '+';
}
bool valid_domain_char(unsigned char c) {
  return std::isalnum(c) || c == '-' || c == '.';
}

}  // namespace

void extract_emails(const std::string& body, const std::string& root_domain,
                    std::vector<std::string>& out) {
  std::string root = to_lower(root_domain);
  const std::string low = to_lower(body);
  std::set<std::string> seen(out.begin(), out.end());

  auto junk = [](const std::string& email) {
    std::string l = to_lower(email);
    if (l.size() < 6 || l.size() > 80) return true;
    // мусор из картинок и трекеров
    if (l.find("@2x") != std::string::npos) return true;
    if (l.find("sentry.io") != std::string::npos) return true;
    if (l.find("sentry-next") != std::string::npos) return true;
    if (l.find(".png") != std::string::npos ||
        l.find(".jpg") != std::string::npos ||
        l.find(".jpeg") != std::string::npos ||
        l.find(".gif") != std::string::npos ||
        l.find(".webp") != std::string::npos ||
        l.find(".svg") != std::string::npos)
      return true;
    // токены-версии от бандлов тоже мусор
    bool digit_start = std::isdigit(static_cast<unsigned char>(l[0]));
    if (digit_start) return true;
    return false;
  };

  size_t i = 0;
  while (i < low.size()) {
    size_t at = low.find('@', i);
    if (at == std::string::npos) break;

    size_t ls = at;
    while (ls > 0 && valid_local_char(static_cast<unsigned char>(low[ls - 1])))
      --ls;
    size_t de = at + 1;
    while (de < low.size() &&
           valid_domain_char(static_cast<unsigned char>(low[de])))
      ++de;

    std::string local = low.substr(ls, at - ls);
    std::string dom = low.substr(at + 1, de - at - 1);
    i = de > at + 1 ? de : at + 1;

    // точки-дефисы на краях откусываем, иначе живые адреса отлетают
    while (!local.empty() && (local.back() == '.' || local.back() == '-' ||
                              local.back() == '_'))
      local.pop_back();
    while (!dom.empty() && (dom.back() == '.' || dom.back() == '-'))
      dom.pop_back();

    if (local.empty() || dom.empty()) continue;
    if (dom.find('.') == std::string::npos) continue;
    if (dom.front() == '.' || dom.back() == '.') continue;
    if (local.front() == '.') continue;

    std::string email = local + "@" + dom;

    // только свой домен и сабдомены
    if (!root.empty()) {
      if (dom == root) {
      } else if (dom.size() > root.size() + 1 &&
                 dom.compare(dom.size() - root.size(), root.size(), root) ==
                     0 &&
                 dom[dom.size() - root.size() - 1] == '.') {
      } else {
        continue;  // чужой домен
      }
    }
    if (junk(email)) continue;
    if (seen.insert(email).second) out.push_back(email);
    if (out.size() >= 50) return;  // лимит отчёта
  }
}

// модуль

namespace {

class EmailsModule : public IModule {
 public:
  std::string name() const override { return "emails"; }
  std::string description() const override {
    return "e-mail address discovery from certificates (crt.sh) and public pages (theHarvester-style, passive)";
  }
  Maturity maturity() const override { return Maturity::Preview; }
  std::vector<std::string> depends() const override { return {"assets"}; }

  bool run(ModuleContext& ctx) override {
    std::vector<std::string> domains;
    for (const auto& t : ctx.cfg.targets)
      if (!t.is_ip && std::find(domains.begin(), domains.end(), t.host) ==
                          domains.end())
        domains.push_back(t.host);
    if (domains.empty()) return true;

    // 3 страницы + crt.sh на каждый домен — задачи плоские, пул общий
    ctx.pstage("emails", "harvesting addresses", domains.size() * 4);
    HttpOptions opt;
    opt.timeout_s = 20;
    opt.user_agent = ctx.cfg.user_agent;
    opt.max_body_bytes = 1024 * 1024;

    // задача = один запрос; результат складываем в свою ячейку
    struct HarvestTask {
      std::string url;
      size_t domain_idx;
    };
    std::vector<HarvestTask> tasks;
    for (size_t di = 0; di < domains.size(); ++di) {
      const std::string& domain = domains[di];
      for (const std::string& path : {"", "/contact", "/about"})
        tasks.push_back({"https://" + domain + path, di});
      tasks.push_back({"https://crt.sh/?q=" + domain + "&output=json", di});
    }
    std::vector<std::vector<std::string>> per_task(tasks.size());
    ctx.parallel(tasks.size(),
                 [&](size_t i) {
                   ctx.pitem(tasks[i].url);
                   HttpResponse resp = ctx.get(tasks[i].url, opt);
                   if (resp.ok_network() && resp.status == 200)
                     extract_emails(resp.body, domains[tasks[i].domain_idx],
                                    per_task[i]);
                   ctx.ptick();
                 },
                 16);

    for (size_t di = 0; di < domains.size(); ++di) {
      const std::string& domain = domains[di];
      // merge по домену: порядок задач стабилен, дедуп
      std::vector<std::string> emails;
      for (size_t i = 0; i < tasks.size(); ++i) {
        if (tasks[i].domain_idx != di) continue;
        for (const auto& e : per_task[i])
          if (std::find(emails.begin(), emails.end(), e) == emails.end())
            emails.push_back(e);
      }

      if (emails.empty()) {
        ctx.log("emails: none found for " + domain);
        continue;
      }
      std::sort(emails.begin(), emails.end());
      HostResult& host = ctx.result.ensure_host(domain, false);
      host.emails = emails;

      std::string evidence;
      for (size_t i = 0; i < emails.size() && i < 10; ++i) {
        if (!evidence.empty()) evidence += ", ";
        evidence += emails[i];
      }
      if (emails.size() > 10) evidence += ", ...";

      Finding f;
      f.severity = Severity::Info;
      f.module = "emails";
      f.host = domain;
      f.service = "recon";
      f.location = domain;
      f.title = std::to_string(emails.size()) + " e-mail addresses discovered";
      f.detail =
          "Addresses published on the target's own pages and in public "
          "certificate records. Attackers use them for phishing and "
          "credential-stuffing wordlists; verify the list is intentional.";
      f.recommendation =
          "Publish only role-based addresses where possible, avoid "
          "personal addresses in public pages/JS, and consider a contact "
          "form instead of raw mailto links.";
      f.evidence = evidence;
      ctx.result.add_finding(std::move(f));
    }
    ctx.pdone();
    return true;
  }
};

}  // namespace

std::unique_ptr<IModule> make_emails_module() {
  return std::make_unique<EmailsModule>();
}

}  // namespace mikto
