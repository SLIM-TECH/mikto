# Changelog

All notable changes to mikto are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/); versioning is
loosely semantic while pre-1.0.

## [Unreleased]

### Performance — parallel workers everywhere (`--thread`)

- Every network-heavy stage now runs on the shared worker pool driven by
  `--thread <n|max>` / `--concurrency` (default 8, deep 48, `max` = 64):
  content discovery (seed mining, combination rounds, page mining, link
  probing), tech fingerprinting + CMS version probes, security-headers
  analysis, e-mail harvesting, reverse-IP lookup, Shodan InternetDB /
  geolocation / Censys enrichment, exposed-service probes, WHOIS queries and
  secrets-in-JS downloads. Previously only the port scan and two webpaths
  stages were pooled; everything else was strictly sequential.
- HTTP connections are now keep-alive and shared across workers (libcurl
  share interface: connection + DNS + TLS-session caches with proper
  locking). Each request used to pay a fresh TCP + TLS handshake; on
  remote targets that alone dominated scan time.
- Politeness is unchanged: the global token-bucket limiter (`--rate`,
  default 100 req/s; deep 800) still caps every request, and external API
  pacing (InternetDB/Censys) is preserved — waiting happens outside the
  lock so pacing no longer serialises the whole worker pool.
- Scan results are identical to a single-threaded run: fetches run in
  parallel, but result application stays in deterministic order.

### Fixed

- Progress counters could overflow their stage total (`done/total` showing
  e.g. `2516/2386`): stages that did more work than announced (webpaths
  combination rounds also counted page-mining and link probes; subdom
  undercounted the wildcard slot; emails undercounted crt.sh; emailsec used
  a rough estimate). Totals are now exact — every stage closes at or below
  100 %, and stages with a-priori unknown volume grow their total via
  `grow_total` before ticking the new work.
- Hardened the worker pool against crashes: `ScanResult` containers are now
  a `std::deque` with stable references plus an internal mutex, so
  `ensure_host` / `ensure_web` / `add_finding` stay safe no matter which
  thread calls them (a use-after-free / data race could previously abort
  the scan mid-run, e.g. inside content discovery). Covered by a new
  multithreaded regression test; verified clean under AddressSanitizer and
  ThreadSanitizer.
- TLS session sharing in the libcurl share cache is enabled only with
  OpenSSL/BoringSSL/LibreSSL backends — some alternative TLS libraries had
  crashes on concurrent session reuse. Connection and DNS sharing (the
  actual speed win) remain enabled everywhere.
- Worker pools fall back from `std::jthread` to `std::thread` on platforms
  whose standard library lacks jthread; wildcard-DNS label generation no
  longer uses `rand()`.
- The live progress bar now adapts to the terminal width (ioctl/COLUMNS):
  on narrow terminals the bar shrinks, on very narrow ones it is dropped
  and long labels are truncated, so the line never wraps.
- The HTML report renders comfortably on small screens: denser layout,
  larger touch targets on coarse pointers, horizontally scrollable tables
  (the palette is unchanged).

## [0.1.0-beta] — first public release

The first version published to GitHub. It is the result of a long private
engineering run, so this entry describes the whole tool: what was built, how
it works, and why it earns its place next to the classic recon tools.

### What mikto is

A C++20 CLI scanner for **authorized** targets. It runs 15 modules in
dependency order, correlates everything into a typed intelligence graph, and
renders the result five ways (console tree, JSON, self-contained HTML, SARIF
2.1.0, CSV). It *finds* issues and *never* exploits them: no bruteforce, no
payloads, no WAF evasion, scope never expands on its own.

### How it works (architecture in six lines)

1. Strict target validation → a closed scope (IP / hostname / URL / file of
   targets). Discovered hosts are reported, never scanned.
2. Modules run topologically sorted by declared dependencies; each module is
   an `IModule` with a shared `ModuleContext` (one HTTP client, one
   token-bucket rate limiter, one provider tracker). An exception in one
   module never kills the scan.
3. Every external request is accounted per provider (requests / successes /
   failures); 5 consecutive transport failures open a circuit breaker that
   skips a dead source — degradation is recorded, not hidden.
4. Modules write structured data into a single `ScanResult`; findings carry
   severity, location, detail, recommendation and redacted evidence.
5. After the run, the orchestrator derives the **intelligence graph**:
   12 node types, edges with provenance sources, confidence 0–1 and status
   (`confirmed` / `probable` / `possible` / `unverified`). DNS facts are
   confirmed; header fingerprints stay probable; CVE matches stay unverified.
6. Five reporters render the same `ScanResult` — nothing is sampled or cut;
   every cap is stated with accounting chips.

### What is inside

* **DNS + TLS recon** (`assets`): own RFC 1035 client (A/AAAA/MX/NS/TXT/SOA/
  CAA/PTR, AXFR in deep), SPF/DMARC/CAA policy checks, certificate inspection.
* **WHOIS over TCP/43** (keyless) with RDAP fallback and expiry monitoring.
* **Passive subdomain discovery** (crt.sh / urlscan / Wayback / HackerTarget,
  concurrent, wildcard-aware) and **e-mail harvesting**.
* **E-mail security posture** (`emailsec`): SPF quality, DMARC evaluation,
  DKIM selector probing, MTA-STS, TLS-RPT, DNSSEC.
* **Port scanner with a probe ladder** (banner → TLS → HTTP GET → Redis PING)
  and nmap-style confidence levels, multi-product `Server:` parsing, passive
  OS guess, honeypot/deception analysis (sinkholes, impossible banners,
  protocol-vs-port mismatches).
* **Infrastructure enrichment** (all keyless): Shodan InternetDB, geo / ASN /
  hosting org, URLhaus reputation; optional `--shodan-key` / `--censys-key`
  add depth and feed CPEs into the CVE matcher.
* **Co-hosted neighbours** (reverse-IP) with shared-hosting risk assessment.
* **WhatWeb-style fingerprinting** (~150 markers) incl. JS libraries with
  versions, databases, panels, WordPress plugin inventory, EOL checks.
* **Universal content discovery** (`webpaths`, GET-only): mining from HTML,
  JS/CSS string literals, robots.txt, sitemap.xml + two recursive combination
  rounds; soft-404 baseline; every path labelled with how it was found.
  Path probing runs on a parallel worker pool — `--thread <n|max>` sets the
  worker count (`max` = 64); results are identical to a single-threaded run,
  wall time on big sites drops several-fold.
* **Unauthenticated-service detection** (`exposed`) with strictly read-only
  probes; **security-headers audit** (`headers`); **WAF / anti-bot /
  rate-limiter detection** (`waf`) with an honest per-host `scan_visibility`.
* **CVE matching against live NVD API 2.0** with exact CPE versions (75+
  products), request budgeting, 24 h cache, Exploit-DB enrichment.
* **Secrets detection** with high-precision patterns and redacted evidence.
* **`mikto diff old.json new.json`** — infrastructure change monitoring with
  CI-friendly exit code 1, JSON/HTML diff reports.
* **`mikto providers`** — catalog of the 14 external sources with limits and
  auth env vars.
* **Reports**: risk score 0–100 + grade, executive summary, findings with
  evidence, security-headers matrix, infrastructure section (server IPs, ASN,
  same-segment neighbours, co-hosted domains, shared NS/MX), interactive
  correlations map with per-type icons, pan/zoom and provenance tooltips,
  full traffic log (`--trace`), provider health panel, EN/RU interface switch,
  dark/light theme, print stylesheet — all in ONE offline HTML file.
* **Cross-platform**: Linux / macOS / Windows (Winsock port: `WSAPoll`,
  `_isatty`, WSAStartup, vcpkg manifest), Docker image, GitHub Actions CI
  (linux + windows + macos).

### Quality gates

* 152 unit tests / 1422 checks, dependency-free test runner, ASan+UBSan runs.
* `-Wall -Wextra -Wpedantic` clean; `-DMIKTO_WERROR=ON` used in CI.
* No raw owning pointers; RAII guards for fds, curl and SSL handles.
* Everything testable is a pure function: DNS wire format, WHOIS/geo/feed
  parsing, fingerprinting, classification, report logic.

### Why it is better than the usual single-purpose tools

* `subfinder`/`amass`-style listers print names — mikto resolves them, relates
  them to IPs/ASNs and puts them into a graph with confidence.
* `nmap`-style scanners print ports — mikto explains **how** each service was
  identified (probe ladder confidence) and flags honeypots/sinkholes.
* `nuclei`-style scanners need templates and can exploit — mikto needs
  nothing (keyless), and deliberately cannot exploit.
* `dirb`/`gobuster`-style fuzzers need wordlists and flood — mikto mines the
  site itself (JS literals, robots, sitemaps) and stays within one rate limit.
* `whatweb` fingerprints — mikto fingerprints **and** matches versions
  against NVD with exact CPEs, then shows public exploits.
* `nikto` is a legendary black-box scanner — mikto is its honest, modern
  sibling: read-only, scope-locked, provenance-carrying, multi-format,
  cross-platform, and it tells you when a WAF made the scan incomplete
  instead of pretending it did not.
* The full feature-by-feature comparison against 94 tools lives in
  [docs/COMPARISON.md](docs/COMPARISON.md).

---

## Internal pre-release milestones (before the first public version)

### [0.7.0-dev] — intelligence-engine build
- Intelligence graph (12 node types) with sources, confidence and status;
  serialized into JSON; summarized on console.
- `mikto diff` (JSON/HTML, exit code 1), `mikto providers` catalog.
- Provider health tracking + circuit breaker (5 failures → open, half-open
  probes, per-provider caps).
- New `emailsec` module; SARIF 2.1.0 + CSV reporters.
- HTML informativeness layer: correlations section (canvas entity map with
  glyphs, pan/zoom, hover provenance), infrastructure section, provider
  panel, headers matrix, risk-composition bar, accounting chips.
- 41 new test cases across 5 files (150 tests / 1402 checks at that point).

### [0.6.0] — detection-hardening
- Probe-ladder service detection, multi-product Server parsing, honeypot /
  deception analysis, proxy sinkholes.
- WAF module with per-host `scan_visibility`.
- CVE matching hardened (NVD configuration parsing, severity downgrades for
  unverified matches, Exploit-DB enrichment); duplicate-finding suppression.

### [0.5.0] — recon
- Full DNS recon (assets), WHOIS over TCP/43, passive subdomain discovery,
  e-mail harvesting, Shodan InternetDB / geo+ASN / URLhaus reputation,
  co-hosted neighbours, web stack fingerprinting, universal content discovery
  with combination mining, JSON+HTML reports, traffic trace.

### [0.4.0] — Censys integration
- Optional Censys Search API v2: per-service software with CPEs → cve module,
  labels, ASN/reverse-DNS evidence, geo/ASN fallback.

### [0.3.0] — the recon core
- DNS record recon + SPF/DMARC/CAA analysis, WHOIS module, IP geolocation,
  URLhaus reputation, Exploit-DB linkage, `--trace` traffic log, interactive
  recon tree, deep mode ~8× faster.

### [0.2.0] — first web surface
- Tech fingerprinting, webpaths, subdomains, e-mails, headers audit,
  HTML report, safe/deep modes with the ethical gate.

### [0.1.0-alpha] — the core
- C++20 core, module interface, port scanner, console/JSON reporters,
  risk model, 65k-port sweep in ≈ 90 s.
