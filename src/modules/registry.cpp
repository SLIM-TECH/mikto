// mikto — реестр модулей, порядок в списке = порядок запуска
#include "modules.hpp"

#include <map>
#include <sstream>

namespace mikto {

const char* maturity_name(Maturity m) {
  switch (m) {
    case Maturity::Reference: return "reference";
    case Maturity::Preview: return "preview";
  }
  return "reference";
}

std::vector<std::string> module_names() {
  return {"assets",   "whois",    "subdom",   "emails", "emailsec",
          "ports",    "infra",    "neighbors", "tech",  "webpaths",
          "exposed",  "headers",  "waf",      "cve",    "secrets"};
}

std::vector<std::unique_ptr<IModule>> create_module(const std::string& name) {
  std::vector<std::unique_ptr<IModule>> out;
  if (name == "assets") out.push_back(make_assets_module());
  else if (name == "whois") out.push_back(make_whois_module());
  else if (name == "subdom") out.push_back(make_subdom_module());
  else if (name == "emails") out.push_back(make_emails_module());
  else if (name == "emailsec") out.push_back(make_emailsec_module());
  else if (name == "ports") out.push_back(make_ports_module());
  else if (name == "infra") out.push_back(make_infra_module());
  else if (name == "neighbors") out.push_back(make_neighbors_module());
  else if (name == "tech") out.push_back(make_tech_module());
  else if (name == "webpaths") out.push_back(make_webpaths_module());
  else if (name == "exposed") out.push_back(make_exposed_module());
  else if (name == "headers") out.push_back(make_headers_module());
  else if (name == "waf") out.push_back(make_waf_module());
  else if (name == "cve") out.push_back(make_cve_module());
  else if (name == "secrets") out.push_back(make_secrets_module());
  return out;
}

std::string modules_help_table() {
  std::ostringstream out;
  out << "available modules (canonical run order):\n\n";
  for (const auto& name : module_names()) {
    auto mods = create_module(name);
    if (mods.empty()) continue;
    out << "  " << name << "  "
        << "(" << maturity_name(mods[0]->maturity()) << ")\n"
        << "      " << mods[0]->description() << "\n";
    auto deps = mods[0]->depends();
    if (!deps.empty()) {
      out << "      depends on:";
      for (const auto& d : deps) out << " " << d;
      out << "\n";
    }
  }
  out << "\nRun selected modules with --modules a,b,c; dependencies are\n"
         "enabled automatically. Modules are read-only: they observe and\n"
         "report, they never exploit.\n";
  return out.str();
}

}  // namespace mikto
