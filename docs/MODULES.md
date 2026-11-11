# mikto modules — reference

15 modules run in dependency order. Any subset works via `--modules a,b,c`.
Maturity: **reference** = battle-tested in this codebase, **preview** =
useful today, still growing.

All modules follow one contract (see `include/mikto/module.hpp`):
never expand scope, never modify target state, emit everything through the
shared finding record, account every external request per provider.

## assets — DNS + TLS certificate (preview)

* Own RFC 1035 DNS client (UDP, no external libs): A, AAAA, MX, NS, TXT,
  SOA, CAA, PTR; falls back to `getaddrinfo` when UDP/53 is blocked.
* SPF / DMARC / CAA policy checks; dangling MX/NS verification.
* `--deep`: AXFR zone-transfer probe (read-only; a successful transfer is
  *reported*, never saved as data).
* TLS certificate inspection: issuer, validity, SAN names. SAN hostnames are
  listed as intel — **never scanned**.
* In: hostname/IP from scope. Out: `dns_records`, cert fields, findings
  (wildcard DNS, missing CAA, expiring cert, …).

## whois — registration data (preview)

* WHOIS over TCP/43, IANA referral → authoritative server. Keyless.
* Registrar, created/updated/expires dates, contact e-mails, nameservers.
* Findings: domain expiring soon, privacy-proxied vs direct contacts.
* RDAP fallback when port 43 is closed.

## subdom — passive subdomain discovery (preview)

* Sources queried concurrently: crt.sh, urlscan.io, Wayback Machine,
  HackerTarget. All keyless.
* Wildcard detection (random-label probe) prevents phantom subdomains.
* Discovered names go to the report and the intelligence graph; they are
  **not scanned** (scope never expands). Resolution is parallel (12 workers).

## emails — e-mail harvesting (preview)

* Harvest from certificate transparency logs and pages already fetched from
  the target.
* Only addresses at the target's own domain are kept.

## emailsec — e-mail security posture (preview)

* DNS-only, passive. Reuses `assets` DNS data instead of re-querying.
* SPF quality: `+all` is critical, missing `all`, RFC 7208 lookup limit,
  private ranges in mechanisms.
* DMARC: `p=none`, `pct<100`, `sp=none`, malformed records.
* DKIM selector probing (16 common selectors), MTA-STS (RFC 8461), TLS-RPT
  (RFC 8460), DNSSEC (DNSKEY), positive CAA notes.

## ports — TCP scan + service detection (reference)

* TCP connect scan; safe mode ≈55 curated ports, deep = 1–65535.
* Probe ladder per open port: banner grab → TLS handshake → HTTP GET →
  Redis PING. Each identification carries confidence:
  `confirmed` / `header` / `banner` / `guess`.
* Multi-product `Server:` parsing (Apache + OpenSSL + OS clue), OpenSSL-style
  release letters (`1.1.1d`), passive OS guess from TTL/banners.
* Deception analysis: honeypot banner signatures (Cowrie, Kippo, Dionaea,
  OpenCanary, Honeyd, T-Pot), implausibly old SSH banners, proxy sinkholes
  (≥3 ports with byte-identical responses), protocol-vs-port mismatches,
  TLS on unexpected ports, plain HTTP on 443, forwarding-proxy markers.

## infra — infrastructure enrichment (preview)

* Keyless: Shodan InternetDB (ports, CPEs, CVEs, tags), ipwho.is → ip-api
  geolocation/ASN/hosting org, URLhaus reputation feed.
* Optional keys add depth: `--shodan-key` (full host API incl. OS),
  `--censys-key` (per-service software/CPEs → feeds the cve module, labels,
  ASN/rDNS, geo fallback).
* 24 h disk cache per source (`~/.cache/mikto/`), self-paced requests.

## neighbors — co-hosted domains (preview)

* Reverse-IP lookup (HackerTarget), shared-hosting risk assessment.
* Neighbours are listed in the report and the graph as separate entities —
  never merged with the target.

## tech — web stack fingerprinting (preview)

* ~150 markers: CMS (WordPress, Joomla, Drupal, Bitrix, OpenCart, Magento…),
  languages/frameworks (PHP, ASP.NET, Java/Tomcat, Rails, Django, Flask,
  Express, Next.js…), JS libraries with versions, databases (error signatures
  + open DB ports), hosting panels, CDN/WAF, WordPress plugin inventory.
* Read-only version-revealing probes (`/readme.html`, `/wp-json/`, …) and
  EOL runtime checks.

## webpaths — content discovery (reference)

* GET only. Curated wordlist (≈70 safe / ≈200 deep) is just the seed:
* paths are mined from homepage HTML attributes, string literals inside
  fetched JS/CSS (`fetch("/api/lol/admin")` — SPA routes leak here),
  robots.txt (Disallow/Allow/Sitemap) and sitemap.xml (one index level).
* Two recursive combination rounds: dir+suffix, dir+word, word+suffix,
  dot-suffixes — the second round runs on what the first round found.
* Soft-404 baseline (random path probe) kills catch-all/SPA false positives.
* Every confirmed path records the discovery channel: `page link`, `JS
  literal`, `robots.txt`, `sitemap.xml`, `combination`, `wordlist`.

## exposed — unauthenticated services (reference)

* Strictly read-only probes for services answering without auth: Redis,
  Memcached, MongoDB, Elasticsearch, CouchDB, etcd, Docker API, RabbitMQ
  management, Kubernetes API.
* A finding requires the service to *answer*, not just to have a port open.

## headers — security headers (reference)

* HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy,
  Permissions-Policy, CORS, version disclosure, cookie flags.
* Per-URL matrix in the HTML report (✓/✗ with values on hover).

## waf — blocker detection (preview)

* Passive header/cookie hints + one active block-page fingerprint GET.
* Detects WAF/edge vendors (Cloudflare, Imperva, Sucuri, Akamai,
  ModSecurity, DataDome, F5, CloudFront, DDoS-Guard…), anti-bot challenges,
  HTTP 429 rate limiters, geo/region blocks.
* Sets per-host `scan_visibility`: `full` / `degraded` / `blocked` — so an
  incomplete picture is never mistaken for a complete audit. No bypass
  attempts, ever.

## cve — version matching (preview)

* Version sources: service banners + web stack + databases + Shodan/Censys
  CPEs. CPE map of 75+ products.
* Every match is a live NVD API 2.0 query with exact-version
  `virtualMatchString`; 24 h cache; self-pacing ≈6 s per product keyless
  (~0.8 s with `--nvd-key`); per-scan request budget (15 keyless / 60 keyed)
  so a big inventory cannot stall the scan.
* Findings enriched with public exploit links from Exploit-DB.
* Unverified matches are downgraded honestly (severity hints, `unverified`
  status in the graph).

## secrets — credential patterns (preview)

* High-precision patterns only: AWS/Google/Slack keys, private-key blocks,
  generic token shapes with entropy checks.
* Scans served content + up to 8 same-origin JS files.
* Evidence is always redacted; the report shows a masked sample.

## Caps and honesty

Every cap (subdomains, paths, traffic events, map nodes) is mirrored in the
JSON report and stated in the HTML with accounting chips — overflow is
counted and warned, never silently dropped.
