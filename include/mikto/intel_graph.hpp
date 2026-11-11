#pragma once
// mikto — граф сущностей: источники и уверенность, пересобирается из ScanResult
#include <map>
#include <string>
#include <vector>

namespace mikto {

class ScanResult;  // full definition needed only by the .cpp

enum class NodeType {
  Domain,       // any host name (target or discovered subdomain)
  Ip,           // IPv4/IPv6 address
  Asn,          // autonomous system ("AS13335")
  Provider,     // CDN / WAF / registrar / reputation source / cloud
  Service,      // "host:port" with an observed protocol
  Technology,   // named product/version fingerprint
  Endpoint,     // URL path that actually answered
  Email,        // e-mail address
  Certificate,  // TLS certificate subject
  MailExchanger,// MX target
  Nameserver,   // NS target
  Cve           // CVE identifier
};

// ключ для json
const char* node_type_key(NodeType t);
const char* node_type_name(NodeType t);

struct GraphNode {
  std::string id;      // "<type-key>:<normalized value>"
  NodeType type = NodeType::Domain;
  std::string value;   // normalized: domains/hosts/emails lowercase
  std::string status;  // "confirmed" | "probable" | "possible" | "unverified"
  double confidence = 0.0;  // 0..1 (strongest observation)
  std::vector<std::string> sources;  // module names / external providers
  std::string first_seen;
  std::string last_seen;
};

struct GraphEdge {
  std::string src;
  std::string dst;     // node ids
  std::string relation;  // "resolves_to", "has_service", "runs", ...
  std::string status;
  double confidence = 0.0;
  std::string evidence;   // short human-readable justification
  std::vector<std::string> sources;
};

class IntelGraph {
 public:
  // один проход по готовому ScanResult
  void build(const ScanResult& r);

  const std::vector<GraphNode>& nodes() const { return nodes_; }
  const std::vector<GraphEdge>& edges() const { return edges_; }
  std::map<std::string, int> node_counts() const;  // by type key
  std::map<std::string, int> edge_counts() const;  // by relation

  // get-or-create по (тип, значение); статус по сильнейшему наблюдению
  GraphNode& ensure(NodeType type, const std::string& value,
                    const std::string& status, double confidence,
                    const std::string& source);

  // дедуп по (src, dst, relation), evidence копится
  void link(const std::string& src_id, const std::string& dst_id,
            const std::string& relation, const std::string& status,
            double confidence, const std::string& evidence,
            const std::string& source);

 private:
  std::vector<GraphNode> nodes_;
  std::map<std::string, size_t> index_;  // id -> position in nodes_
  std::vector<GraphEdge> edges_;
  std::string now_;  // first/last seen timestamp
};

// больше = сильнее
int graph_status_rank(const std::string& status);

}  // namespace mikto
