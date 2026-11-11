# Getting started with mikto

This guide takes you from a fresh clone to your first readable report.
Estimated time: 5 minutes.

## 0. The one rule

Run mikto **only against systems you are allowed to test**. mikto is
read-only and non-destructive by design, but unauthorized *scanning* is
illegal in most jurisdictions regardless of how polite the scanner is.
If your scope is written down — you are fine. If not — get it in writing.

## 1. Build

Linux / macOS:

```bash
sudo apt install build-essential cmake libcurl4-openssl-dev libssl-dev  # debian/ubuntu
# fedora: sudo dnf install gcc-c++ cmake libcurl-devel openssl-devel
# arch:   sudo pacman -S gcc cmake curl openssl

git clone https://github.com/mikto-scanner/mikto && cd mikto
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

Windows and Docker: see [BUILD.md](BUILD.md).

The binary lands in `build/mikto`. Sanity check:

```bash
./build/mikto --version    # mikto v0.1.0-beta
./build/mikto modules      # the 15 modules + maturity
```

## 2. Your first scan

```bash
./build/mikto scan https://your-own-site.example --html report.html
```

What happens:

1. the target is validated (hostname / IP / URL) and put into a strict scope;
2. modules run in dependency order: `assets → whois → subdom → emails →
   emailsec → ports → infra → neighbors → tech → webpaths → exposed →
   headers → waf → cve → secrets`;
3. you see a live progress line on **stderr** and a summary tree on stdout;
4. `report.html` is written — a single self-contained file, open it with
   double click, it works offline.

Safe mode (the default) is polite: ~55 common ports, 8 workers, a rate
limiter on everything, ~60 known web paths. No confirmation needed.

## 3. Reading the report

The HTML report opens with an **Overview**: risk score 0–100, a letter grade
(A–F), the score composition, top-5 priority actions and findings-by-module
bars. Below:

* **Findings** — every issue with severity, location, evidence and a
  recommendation; filter by severity / module / host / free text.
* **Hosts** — the full inventory per host: DNS records, WHOIS, TLS
  certificate, ports with probe confidence, technologies, paths, subdomains,
  e-mails, reputation.
* **Infrastructure** — server IPs with ASN / network owner, which in-scope
  names point to each IP, same-segment (/24, /64) neighbours, co-hosted
  domains, shared NS/MX.
* **Correlations** — an interactive entity map of the intelligence graph +
  filterable entity/relation tables with provenance.
* **Web** — every response header, a ✓/✗ matrix of security headers per URL.
* **Traffic** — what mikto sent and what came back (with `--trace`).
* **Scan info** — settings, modules run, external provider health.

The interface switches **EN ↔ RU** with the language button in the top-right;
the choice is remembered per browser.

JSON output is the same data, machine-readable:

```bash
./build/mikto scan https://your-own-site.example --json report.json
jq '.findings[] | {severity, module, title}' report.json
```

## 4. Modes

* **safe (default)** — the polite profile described above.
* **`--deep`** — full 1–65535 port range, extended path list, AXFR probe.
  mikto prints a warning and asks you to type `yes` (or pass `--yes`).
  Use it only when your permission explicitly covers deep testing.
* **`--modules a,b,c`** — run a subset. OSINT-only pass, no probes to the
  target at all:

  ```bash
  ./build/mikto scan example.com --modules subdom,emails,neighbors,infra
  ```
* **`--thread <n|max>`** — worker-pool size for network stages (default 8,
  `max` = 64). Pair it with `--rate` if you raise it — the rate limiter is
  always the politeness ceiling:

  ```bash
  ./build/mikto scan example.com --thread max --rate 500
  ```

## 5. Monitoring changes

Save a JSON report, scan again later, diff:

```bash
./build/mikto scan example.com --json monday.json
# ... a week passes ...
./build/mikto scan example.com --json friday.json
./build/mikto diff monday.json friday.json --html diff.html
```

`diff` lists new/removed subdomains, IPs, open ports, technology version
changes, DNS record churn and new/resolved findings — and **exits with code
1 when anything changed**, so the same command works in cron and CI.

## 6. Where things go from here

* [MODULES.md](MODULES.md) — what every module does in detail.
* [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md) — the ethics contract.
* [DEV_GUIDE.md](DEV_GUIDE.md) — extend mikto with your own module.
* [BUILD.md](BUILD.md) — Windows, Docker, CI, build options.
