# mikto — implementation roadmap

Ordering principle: accuracy and honesty first, then correlation, then breadth.
Nothing here adds modules for their own sake; each item states the measurable
outcome it targets. Status markers reflect the **0.1.0-beta** build.

## Done in 0.1.0-beta (intelligence-engine build)

- [x] **R2 — Intelligence correlation engine** — shipped as `intel_graph`
      (`include/mikto/intel_graph.hpp`). Typed entity graph (12 node types:
      domain, ip, asn, provider, service, technology, endpoint, email,
      certificate, mail_exchanger, nameserver, cve) built from ScanResult at
      scan end; every node/edge carries sources, confidence 0–1 and a status
      (`confirmed` / `probable` / `possible` / `unverified`). Entity resolution
      dedupes on (type, normalized value) only — no merging on shared IPs.
      Serialised into JSON `intelligence_graph`, summarized on console.
- [x] **R3 — Scan diff** — `mikto diff <old.json> <new.json>` with JSON + HTML
      output, first-seen/last-seen timestamps, severity hints, exit code 1 on
      changes (CI/cron monitoring). Covers subdomains, IPs, ports, tech
      versions, paths, DNS records, certificates, infra tags, findings.
- [x] **R4 — Output formats** — SARIF 2.1.0 (`--sarif`, GitHub code scanning
      compatible) and CSV (`--csv`, RFC 4180). CycloneDX still open (see R4b).
- [x] **R5 (partial) — `emailsec` module** — SPF policy quality, DMARC policy
      evaluation, DKIM selector probing, MTA-STS, TLS-RPT, DNSSEC, CAA notes.
      All DNS-only, passive, unit-tested; complements (not duplicates) the
      `assets` absence checks.
- [x] **Provider catalog + health tracking** (V2 §5.6) — `mikto providers`
      catalog command, per-scan request accounting, circuit breaker (5
      consecutive transport failures) with half-open probes, per-provider
      request cap, honest degradation recorded in JSON `providers` section.
- [x] **Edge/origin honesty (V2 §6.3)** — the WAF module's CDN finding now
      states `PROXY/CDN DETECTED`, `EDGE NETWORK`, `EDGE IP` semantics and
      `ORIGIN STATUS: not publicly confirmed` explicitly; mikto never probes
      behind the edge.

## R1 — Vulnerability accuracy (continue)

- Keep a maintained CPE mapping table in a data file, not code; add tests
  against a snapshot of real NVD responses.
- Parse NVD `configuration.operator` (AND/OR/negate) to avoid counting a CVE
  applicable when its rule requires a *combination* of products.
- Fetch CISA KEV and EPSS (both keyless) and annotate findings: "in KEV" /
  "EPSS 0.7" — one extra prioritization axis, zero keys.
- Feed CVE matches into the intelligence graph with richer status
  (`strong candidate` vs `unverified match`) once exact-version reasoning
  lands.

## R4b — Remaining formats

- CycloneDX inventory (tech/services) — SBOM-style asset hand-off.
- HTML report: relationship view of the intelligence graph (static SVG, no JS
  frameworks) + an Email Security section fed by `emailsec` findings.

## R5 — Remaining modules (each behind the module contract + isolated tests)

| Module | Why it earns its place | Key sources (keyless) |
|---|---|---|
| `certificate_intelligence` | cert lifecycle/issuer/SAN correlation across hosts | crt.sh, live TLS probes |
| `passive_dns` | infrastructure history, CDN/C2 pivot detection | public passive-DNS datasets |
| `dns_security` | zone hygiene: wildcard amplification, DS/DNSKEY chains | DNS (own client) |
| `api_discovery` | OpenAPI/Swagger/GraphQL introspection read-only | harvested paths from webpaths |
| `javascript_intelligence` | source maps (.map), API endpoints, secrets in bundles | already-fetched JS |

Not planned: anything requiring brute force, evasion, or exploitation.

## R6 — Benchmark suite

- `bench/` scenario: fixed authorized target set (local docker-compose with
  known ground truth + a public CT dataset snapshot).
- Metrics recorded per run: coverage/precision/recall vs ground truth, wall
  time, peak RSS, requests, cache-hit ratio, duplicate-request ratio.
- Compare against nmap/subfinder/httpx/katana/whatweb on the SAME targets;
  publish raw numbers even when a competitor wins a category.
- Reference measurements on the demo site (127.0.0.1:8137, safe mode, 0.1.0-beta,
  cold caches, sandboxed CI host — treat as order-of-magnitude, not claims):
  full 15-module scan ≈ 10.4 s wall; webpaths 8.2 s, ports 0.9 s, neighbors
  0.7 s, infra 0.5 s, all other modules < 0.1 s; ASan+UBSan build passes the
  full suite and a real scan with zero sanitizer reports.

## R7 — Performance & robustness engineering

- Profile-guided pass on webpaths (the hot loop) and ports probe ladder.
- HTTP connect reuse for same-origin JS fetches (bounded, read-only).
- DNS: IPv6 resolvers from /etc/resolv.conf; source-address check on UDP
  replies; negative-cache to avoid re-querying NXDOMAIN.
- Optional curl multi-handle pipeline for the OSINT fetchers.
- Provider quotas: make the per-provider request cap configurable via flags
  (`--provider-cap <host=N>`).

## R8 — Optional headless sidecar (separate process, off by default)

- `mikto-browser`: renders JS-heavy pages, exports DOM + network log;
  C++ core consumes it as data. Never a hard dependency; gated behind an
  explicit flag like `--deep`.

## V2 master-prompt backlog (larger arcs, deliberately phased)

- **Plugin SDK** (V2 §16): external module manifest, capability permissions,
  resource limits; starts as a read-only adapter API, no arbitrary process
  access.
- **Headless JS intelligence** (V2 §8.2): via R8 sidecar only, never in-core.
- **Cloud intelligence** (V2 §13): keyless fingerprints first (ASN/header/
  endpoint signals); no credentialed scanning of third-party clouds.
- **Historical timeline** (V2 §15): persistent scan history store on top of
  `mikto diff` (first-seen/last-seen across runs, change timeline, alerting).
- **HTML dashboard sections** (V2 §19): add Intelligence Graph, Email
  Security, Source Coverage, Evidence & Confidence views.
