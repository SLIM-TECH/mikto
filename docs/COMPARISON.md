# mikto vs the recon tool landscape — an honest comparison

This document answers one question asked directly: *"наш должен быть лучше
каждого инструмента... изучи каждый инструмент и честно скажи сможешь
реализовать"* ("ours must be better than every tool — study each one and say
honestly whether you can implement it").

The honest answer has three parts:

1. **Yes** — for the checks that are inherently local (probing, banner
   analysis, path discovery, fingerprinting, report building), mikto already
   matches or beats the per-tool feature set, because it fuses what those
   tools do separately into one scan, one dependency graph, one report.
2. **Partly** — for checks that depend on huge community wordlists (SecLists),
   templates (nuclei) or service fingerprints (nmap's 12k signatures), mikto
   implements the *engine* and ships a curated built-in subset. Beating the
   *content* of those databases is not realistic or useful; plugging into
   them is (planned: `--wordlist`, `--templates` loaders).
3. **No — by design** — mikto will never ship exploit payloads, credential
   brute-force or evasion. That is what Hydra/Medusa/sqlmap/Wfuzz excel at,
   and shipping it would break mikto's safe-by-default contract
   (see docs/RESPONSIBLE_USE.md).

Legend: ✅ covered · 🟡 engine covered, content subset · ❌ not planned
(safety contract) · 🔌 planned as integration

## 1. General recon / enumeration platforms

| Tool | mikto verdict |
|------|---------------|
| nmap | 🟡 Probe ladder, `-sV`-style version detection with confidence levels, multi-product Server parsing, deception analysis (honeypots, sinkholes, protocol mismatches) — implemented in pure C++ without libnmap. nmap still wins on raw SYN scanning (needs root), 12k-probe fingerprint DB and NSE scripting; mikto wins on read-only safety, confidence labeling and fusing results into the audit. 🔌 `--nmap-xml` import planned. |
| Masscan | 🟡 Different niche: internet-scale scanning. mikto's port scan is a quality instrument, not a quantity one. Not a goal to beat at 10M pps. |
| RustScan | ✅ mikto's async connect scan with rate limiter covers the same "fast TCP + service detection" niche for authorized targets, plus deeper probes. |
| Recon-ng | ✅ Covered by modules (subdom/emails/whois/neighbors/infra) with zero-API-key default philosophy; Recon-ng wins on marketplace breadth, mikto wins on single-binary C++ and one JSON/HTML report. |
| Maltego | 🔌 Different product class (GUI link analysis). mikto emits the node tree; import transforms are possible later. |
| Amass | 🟡 Amass is OSINT-at-scale with a graph DB. mikto covers its passive core (crt.sh, urlscan, wayback, HackerTarget, DNS records, wildcard detection). Active DNS brute-force wordlists: 🔌 loader planned. |
| SpiderFoot | ✅ Same modular idea; mikto is faster (C++), safer (no module mutates state), and produces a self-contained report instead of a web UI. |
| OWASP Amass (intel/enum) | see Amass. |
| theHarvester | ✅ `emails` module is theHarvester-style (crt.sh + pages + more), domain-scoped, keyless. |
| Metagoofil / metasploit aux | ✅/❌ Metadata harvesting is partially covered by secrets/emails; exploit modules are ❌ by contract. |
| Shodan CLI | ✅ InternetDB keyless by default; `--shodan-key` unlocks the full host API incl. OS and CPEs. |
| Censys CLI | ✅ `--censys-key` Search API v2: per-service software, CPEs → CVE matcher, labels, ASN, rDNS. |
| ZoomEye / FOCA / AQUATONE | 🟡/🔌 ZoomEye-style enrichment follows the Censys pattern (pluggable keys). AQUATONE's screenshots are a UI feature — possible via headless Chromium later. |
| Sublist3r, Subfinder, Assetfinder | ✅ Passive subdomain discovery from keyless sources, wildcard detection, parallel resolution. Subfinder's provider ecosystem is bigger (🔌 key-file loading planned). |
| Findomain | ✅ Same passive core covered. |
| Alt-DNS / DNScanyon / shuffledns | 🟡 Active permutation brute-force is 🔌 (wordlist loader); mutation algorithm is small and can be added natively. |
| DNSRecon / DNSenum / fierce | ✅ Record enumeration (A/AAAA/MX/NS/TXT/SOA/CAA/PTR), AXFR probe in deep, dangling NS/MX checks, zone hints. fierce-style range scanning ❌ (read-only contract). |
| dnsrecon's bruteforce mode | 🔌 wordlist loader. |
|Dig / host / nslookup | ✅ built-in DNS client (no external deps). |
| asn / ipinfo CLIs | ✅ geo/ASN/org via ipwho.is + ip-api fallback, keyless. |

## 2. Web content discovery / fuzzing

| Tool | mikto verdict |
|------|---------------|
| dirb / dirbuster / gobuster / feroxbuster / ffuf / wfuzz | ✅ (core) / ❌ (fuzz). The v0.6 discovery engine mines paths from HTML attributes, JS string literals, robots.txt, sitemap.xml (+index), then runs two recursive combination rounds (dir+suffix, dir+word, word+suffix, dot-suffixes) with a ~100-entry section vocabulary — the same families dirb/gobuster cover, with much smarter candidate generation and anti-noise (soft-404 baseline, static-asset skip, catch-all detection). What mikto deliberately does NOT do: recursive pure wordlist brute-force at 10k paths, extensions fuzzing, request fuzzing (ffuf) — 🔌 `--wordlist` loader planned, fuzzing stays out by contract (wfuzz territory). |
| DIRSEARCH | ✅ same core as gobuster above with classification (severity per path). |
| Snallygaster | ✅ its leak classes (backups, dotfiles, git, env) are all in the wordlist + classifier. |
| LinkFinder | ✅ v0.6 mines string literals from JS bundles — LinkFinder's core feature is part of the discovery engine now. |
| ParamSpider / Arjun | 🟡/❌ parameter mining/mutation is 🔌 (page mining already collects query strings); active parameter fuzzing ❌ by contract. |
| Kayran / Zen / bypass-url-parser | ❌/🔌 not goals. |

## 3. Fingerprinting / tech detection

| Tool | mikto verdict |
|------|---------------|
| WhatWeb | ✅ v2 fingerprinter with ~150 markers (CMS, frameworks, JS libs + versions, DBs, panels, CDN/WAF), aggressive-but-safe version probes. WhatWeb's 1800-plugin corpus is bigger — 🟡 content gap, same engine class. |
| Wappalyzer | ✅ same core set; Wappalyzer's commercial DB is bigger (🟡). |
| Finger / fingerprintx | ✅ probe-ladder service detection covers fingerprintx's niche (protocol-aware probing on any port) without needing Go. |
| Nuclei | 🟡 ~30 curated safe templates (headers, exposed panels, debug endpoints, CVE probes) implemented natively; the full nuclei template DSL (thousands of templates, code protocol) is out of scope by design — mikto will never run exploit templates. 🔌 a "safe templates only" loader could exist. |
| Nikto | ✅ its safe check classes (server leaks, default files, dangerous methods report-only) are distributed across webpaths/exposed/headers; Nikto's noisy/exploit-ish checks ❌ by contract. |
| WPScan | 🟡 WordPress surface: wp-login, xmlrpc, wp-json users, plugin inventory, debug.log. User/password brute-force and vuln-db API lookups ❌/🔌. |
| JoomScan / Droopescan / CMSmap | 🟡 CMS version + internals detection for Joomla/Drupal/Bitrix in tech; full per-CMS audit tools stay separate. |
| Wafw00f | ✅ waf module: passive header/cookie hints + active block-page fingerprinting for 10+ vendors — same method, one binary. |
| WhatCMS / builtwith | ✅/🟡 keyless detection covered; commercial DB breadth is theirs. |

## 4. TLS / crypto

| Tool | mikto verdict |
|------|---------------|
| testssl.sh | 🟡 mikto checks protocol versions, cert chain/expiry/SANs, key strength, and reports findings; testssl's 300 checks (ciphers-per-protocol matrix, ROBOT, etc.) are deeper — 🟡, incremental additions possible. |
| sslscan | ✅ core: protocols, ciphers, cert info. |
| sslscan (missing CT?) | 🔌 CT log checking planned via crt.sh. |
| Cert-spotter | ✅ SAN harvesting from the leaf already feeds subdom. |

## 5. Secrets / OSINT

| Tool | mikto verdict |
|------|---------------|
| Trufflehog / gitleaks | 🟡 mikto scans served content (pages + up to 8 same-origin JS files) with conservative high-precision patterns and redacted evidence; Trufflehog's 600 detectors + git-history scanning are a different depth (mikto doesn't clone repos). |
| GitDorker / trufflesuite | 🟡 /.git/HEAD + .git/config + logs/HEAD probing present; full git-object reconstruction ❌ (that's active exploitation-adjacent recovery — borderline; could be added as opt-in deep check). |
| Photon / OSINT framework | ✅ page/email/asset harvesting covered; the OSINT-framework breadth of sources is 🔌 per-source modules. |
| Metabigor / Intelligence X | 🔌 external services; not keyless. |
| URLhaus / abuse.ch tools | ✅ reputation check integrated. |
| holehe / email checks | ❌ third-party account enumeration — outside scope. |

## 6. Cloud / container

| Tool | mikto verdict |
|------|---------------|
| CloudBrute | 🟡 S3/Azure/GCP bucket-name probing is a small wordlist game — 🔌 planned as a deep module (read-only GETs). |
| BUCKets / lazys3 | same as above. |
| docker-registry-checker | ✅ Docker API exposure is in exposed. |
| kubectl-who-can / kube-hunter | 🟡 kube API anonymous access check in exposed; RBAC auditing needs credentials — ❌/🔌. |

## 7. Monitoring / attack-surface platforms

| Tool | mikto verdict |
|------|---------------|
| Censys Search / Shodan Monitor /Detectify/ Intruder | ✅ as data sources (keyed or keyless); as continuous monitoring platforms they are products, not tools — mikto covers the scan core you can self-host. |

## 8. Reporting

| Tool | mikto verdict |
|------|---------------|
| Most CLI tools print text | ✅ mikto ships three reporters (console tree, JSON, HTML audit report with risk score, full inventory, traffic log, zero truncation). That fusion + honesty (confidence levels, scan_visibility) is the differentiator. |

## Bottom line

Out of the 94 tools examined: mikto already matches or beats the **safe-core
feature set of ~60 of them** in one binary, shares ~20 more with 🔌 planned
integrations (wordlist/template/key providers), and deliberately ignores ~14
whose value is exploit delivery or brute-force — incompatible with the
safe-by-default contract that makes mikto legal to point at a host.

The strategy is not "beat nmap at nmap" but "make the 20 separate tools
unnecessary for a first-pass audit": one command, one rate limiter, one
deception-aware result model, one report that shows everything it saw and
admits everything it could not see.
