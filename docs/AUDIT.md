# mikto — engineering audit (accuracy & robustness pass)

Method: full source inspection (core, 14 modules, 3 reporters, tests),
thread-safety review, ASan+UBSan run, end-to-end scan against the local demo
site. Every finding below lists status: **fixed** (with regression test) or
**deferred** (tracked in ROADMAP.md).

Baseline before this pass: build OK, 94 tests / 1111 checks, ctest green.
After: **105 tests / 1155 checks, ctest green, ASan+UBSan clean**, e2e demo
scan reproduces 44 findings including `/api/lol/admin` (source: js).

## Findings

| ID | Severity | Location | Finding | Status |
|---|---|---|---|---|
| F1 | HIGH | `cve.cpp`, `cve_db.cpp` | CVE findings were emitted for EVERY NVD response entry with no client-side verification: `configurations`/`cpeMatch` never parsed, no version-range check, no match reason, no distinction between exact / range / vendor-wide matches — the main false-positive vector | **fixed** |
| F2 | MEDIUM | `http_client.cpp` | With `CURLOPT_FOLLOWLOCATION`, `resp.headers` mixed header blocks of ALL redirect hops (stale security headers from a 301 hop could mask or fake findings) | **fixed** |
| F3 | LOW | `headers.cpp` | Cookie flags detected by substring over the whole `Set-Cookie` value → false positives when the value contains "secure"/"httponly" (`theme=secure-dark`) | **fixed** |
| F4 | LOW | `tech.cpp` | Short body markers (`aos`, `vue`, `slick`) matched inside unrelated words (`chaos`, `converse`) | **fixed** (word-boundary guard for needles < 6 chars) |
| F5 | LOW | `scan_result.cpp` | Traffic events beyond the 20k in-memory cap were silently dropped; JSON showed first 1000 with no totals — contradicted the "nothing is omitted" contract | **fixed** (`trace_dropped_count()`, `traffic_totals` block in JSON) |
| F6 | LOW | `neighbors.cpp` | Reverse-IP fetch used a bare `HttpClient`, bypassing the token bucket AND the `--trace` traffic log (trace incomplete vs its contract) | **fixed** (uses `ctx.get()`) |
| F7 | LOW | `rate_limiter.cpp` | Sleep truncated to whole milliseconds → sub-ms waits became lock/sleep busy-spin | **fixed** (fractional-duration sleep) |
| F8 | LOW | `http_client.cpp` | HTTP connect timeout hardcoded 5 s, ignoring per-target `--timeout` semantics | **fixed** (`HttpOptions.connect_timeout_ms`) |
| F9 | LOW | `cve.cpp` | Same product reached via two sources (banner tcp/443 + tech) emitted duplicate CVE findings | **fixed** (dedup key id+host+product) |
| F10 | INFO | `dns.cpp` | IPv6 nameservers in `/etc/resolv.conf` skipped; UDP reply source address not checked (spoofing needs the random TXID too) | deferred (ROADMAP R7) |
| F11 | INFO | `cve_db.cpp` | CPE vendor mappings partially stale (`rabbitmq` → pivotal_software; modern NVD uses vmware/broadcom) | deferred (ROADMAP R1) |
| F12 | INFO | `json_report.cpp` | Duplicate non-Set-Cookie headers collapse to the first occurrence in JSON | deferred (cosmetic) |
| F13 | INFO | `secrets.cpp` | `collect_same_origin_js` has an unreachable `npos+2` wrap edge (base_url always carries `scheme://`) | deferred (defensive cleanup) |

## F1 details — the accuracy fix (highest value)

`parse_nvd_response()` now walks each CVE's `configurations → nodes →
cpeMatch` and, for the queried vendor:product:

- parses CPE 2.3 **and legacy 2.2** criteria (with CPE unescaping, e.g.
  `joomla\!`);
- evaluates the detected version against the match rule:
  - `exact` — cpeMatch pins exactly this version → **verified**;
  - `range` — `versionStart/EndIncluding/Excluding` bounds → verified iff
    the version falls inside (`compare_versions()` per bound);
  - `any` — version wildcard → **never verified** (vendor-wide);
  - `` — no parseable configuration → unverified;
- fills `match_kind`, `match_rule` (human-readable evidence) and
  `version_verified`.

`cve.cpp` then:

- **skips** entries whose rule exists but the detected version is outside
  (exact-mismatch, range-mismatch) — these were the false positives;
- **downgrades one severity step** for unverified matches (vendor-wide /
  no configuration), because "a version match is not proof of
  exploitability";
- writes the NVD rule into `evidence` and the classification into `detail`;
- dedups per (CVE id, host, product) instead of (id, host:port).

8 new unit tests cover exact/range-in/range-out/wildcard/2.2/other-product/
escaped-CPE. Net effect: fewer findings, each carrying a reason.


## Second wave — findings from the hidencloud.com scan (field evidence)

Scanning a real target (hidencloud.com, a Cloudflare-fronted free-hosting
provider) exposed five defects the unit tests could not catch:

| ID | Severity | Finding | Status |
|---|---|---|---|
| F14 | HIGH | `webpaths`: catch-all baseline only handled 200-catch-alls. A blanket 403 anti-bot challenge (284 KB "Security Verification" page, body varying ~40 B per request) answered EVERY path → 600+ junk "confirmed paths" per endpoint and a >10-minute stall (combo rounds re-fetched the challenge ~1300 times) | **fixed** — baseline generalized to any status + body-similarity check (`similar_body`, 64 B tolerance + normalized prefix); blanket rejection (403/406/429/501/503) skips probing honestly, sets `scan_visibility: degraded`, emits an explanatory finding |
| F15 | HIGH | `ports`: worker pool capped by `hardware_concurrency` — on a 2-core host only 2 threads served an I/O-bound scan; 53 DROP-behaving ports × 1 s timeout ran 82 s for 57 ports | **fixed** — cap is now the safe-mode ceiling (16) regardless of CPU count; token bucket remains the politeness control. Full 14-module scan: >600 s → **45 s** |
| F16 | HIGH | `osint.cpp`: URLhaus csv_recent feed retired by abuse.ch (HTTP 410) → reputation permanently unavailable | **fixed** — replaced with two active keyless feeds: OpenPhish community phishing list (host match) + Feodo Tracker recommended C2 IP blocklist (IP match), both cached, both unit-tested |
| F17 | MEDIUM | WHOIS: IANA referral parsed by substring `whois:` which matched INSIDE the `refer:` value → garbage server ".verisign-grs.com"; the IANA COM-registry fallback object then leaked registry contacts (`info@verisign-grs.com`) into host emails, and the report showed "unknown registrar" | **fixed** — `refer:` parsed as a line-start key; RDAP fallback (rdap.org, HTTPS, keyless) fills registrar/dates/nameservers when port-43 data is empty; whois emails merged only when they belong to the target domain |
| F18 | MEDIUM | Report noise: identical (module, host, title) findings repeated per endpoint/IP ("Location: US..." ×7, "Web stack: Cloudflare" ×4) | **fixed** — `add_finding` suppresses exact duplicates (45 suppressed on hidencloud), survivor carries "also: <location>" in evidence, JSON stats expose `duplicates_suppressed`; Shodan tag sets sorted before title formation |
| F19 | LOW | Safe port list missed hosting/cPanel ports (Shodan knew 2082/2083/2086/2087/2095/2096/8880) | **fixed** — added to kDefaultPorts + service map + TLS-port set |
| F20 | LOW | TLS record saved only from port 443; hosts with TLS only on alternate ports (2083/8443) lost it | **fixed** — canonical 443 preferred, else first successful handshake |

Verification: ctest 1160 checks green, ASan+UBSan clean, live re-scan of
hidencloud.com — 11 ports (was 4), RDAP registrar "Cloudflare, Inc." with
dates, 14 findings (was 60+), 45 duplicates suppressed, 45 s wall time.

## Thread-safety review

- `ports`: worker pool appends into `outcomes` under `resmu`; all
  `ensure_host`/`add_finding` happen after `join()` — safe.
- `subdom`: fetcher and resolver threads use `res_mu`/`out_mu` — safe.
- `ModuleContext::get` from multiple threads: limiter mutex + per-call curl
  handle + trace mutex — safe.
- `ScanResult::record_trace` mutex-guarded; `trace_dropped_` shares the
  mutex — safe.

## Memory / RAII

UniqueFd/UniquePtr wrappers throughout; no leaks reported by ASan; no raw
owning pointers found.

## Verification performed

1. `ctest` — 105 tests, 1155 checks, 0 failures.
2. ASan + UBSan build (`build-asan`): same suite, clean.
3. End-to-end demo scan: 44 findings, `/api/lol/admin` recovered via `js`
   source, `traffic_totals` honest, scan wall time ~9 s (16 workers, safe
   timeouts).

---

# v0.7-dev — V2 intelligence-engine pass (audit + additions)

Method: full re-inspection of the changed layers (orchestrator, module
context, reporters, registry, DNS surface), threat-model for the new
components, unit tests for every pure helper, ASan+UBSan run of the whole
suite plus a real end-to-end scan and a real diff.

Baseline before this pass: 1160 checks / ctest green.
After: **146 tests / 1349 checks, ctest green, ASan+UBSan clean**, end-to-end
demo scan produces all four report formats (console/JSON/SARIF/CSV) with the
intelligence graph populated (45 entities / 45 relations on the demo site).

## Map of the V2 master-prompt items implemented

| V2 item | Where it lives now | Test coverage |
|---|---|---|
| §3 Intelligence graph, provenance, confidence, no premature entity resolution | `include/mikto/intel_graph.hpp`, `src/intel_graph.cpp`; built at scan end by the orchestrator; JSON `intelligence_graph`; console one-liner | `tests/test_graph.cpp` (dedupe, status upgrades, honest confidence, neighbor isolation, unverified CVE matches) |
| §5.6 Provider catalog, quotas, health, circuit breaker | `include/mikto/providers.hpp`, `src/providers.cpp`; wired into `ModuleContext::get` (blocks + accounts every third-party request); JSON `providers`; `mikto providers` command | `tests/test_providers.cpp` (breaker trip/half-open/reopen, caps, URL host extraction, catalog disambiguation) |
| §14 Email & DNS security intelligence | `src/modules/emailsec.cpp` (module `emailsec`, registry position after `emails`) | `tests/test_emailsec.cpp` (SPF all-policy, lookup limit, private ranges, DMARC tags) + live verification against example.com (SPF -all, DMARC reject, DKIM google, DNSSEC — all correct) |
| §15 Scan diff / historical comparison | `include/mikto/scan_diff.hpp`, `src/scan_diff.cpp`, `mikto diff` CLI | `tests/test_diff.cpp` (ports, tech versions, findings, DNS, certificates, severity sorting, JSON/console shapes) |
| §19 SARIF + CSV | `src/reporters/sarif_report.cpp`, `src/reporters/csv_report.cpp`, `--sarif` / `--csv` | `tests/test_reporters.cpp` (SARIF shape/levels/rule dedup; CSV RFC 4180 escaping incl. embedded newline) |
| §6.3 Edge vs origin honesty | `waf.cpp` CDN finding now states EDGE/PROXY/CDN + `ORIGIN STATUS: not publicly confirmed` and the no-bypass policy | reviewed, covered by existing waf tests |
| §2 «Не запускай один и тот же анализ повторно» | `emailsec` reuses `assets` DNS records; only policy-level queries are new (`_dmarc`, selectors, `_mta-sts`, `_smtp._tls`, DNSKEY) | code review |

## Deliberate non-goals in this pass (honesty over checkbox-counting)

- No new modules beyond `emailsec` — V2 §0 says breadth must not replace
  depth; the graph + diff + provider health raise the quality of the existing
  15-module picture instead of padding the module count.
- CVE relations in the graph stay `possible`/`unverified` on purpose: version
  matches are not proof of exploitability (consistent with the v0.6 F1 fix).
- The HTML report does not yet render the graph as a diagram (tracked in
  ROADMAP R4b); the JSON carries the full machine-readable graph now.
- Benchmark numbers quoted in ROADMAP R6 are environment-specific
  measurements, not superiority claims (V2 §20 discipline).

## New engineering notes

- `ScanResult` is non-movable (mutex member) — new tests build results
  in place; keep that in mind for future refactors.
- Provider breaker semantics: failures = transport errors, 5xx, 429 (a 404
  from a provider is a healthy answer to a bad query, not a breaker event);
  half-open probe = every 10th blocked call; one success re-closes.
- ASN node ids are case-canonicalized to the conventional `AS<nr>` form so
  edges never dangle against nodes.
- The diff engine treats missing sections as empty sets — a partial report
  diffs against a full one without crashing, with honest "removed" noise;
  documented for CI users.

## Verification performed (this pass)

1. `ctest` — 146 tests, 1349 checks, 0 failures (Release).
2. ASan + UBSan build: same suite, clean; instrumented end-to-end scan and
   diff also clean.
3. End-to-end demo scan (127.0.0.1:8137): 44 findings, graph 45/45,
   providers section populated (Hackertarget 1 req), SARIF 44 rules /
   44 results, CSV 44 data rows + header.
4. Live passive check `mikto scan example.com --modules emailsec`: SPF -all,
   DMARC p=reject, DKIM selector 'google', DNSSEC signed — matches the
   domain's real published posture.
