# Responsible Use

`mikto` exists to make **authorized** security work faster and clearer.
This document defines the rules of using it. If your situation is not clearly
covered here — the answer is "don't scan".

## 1. Authorization

Only run mikto against systems where **all** of the following are true:

* you own the systems, **or** you hold a written authorization (contract,
  engagement letter, bug-bounty scope page) that explicitly covers them;
* the authorization covers **the exact hosts, networks and ports** you are
  about to scan, **and the intensity** of the scan you are about to run
  (`--deep` is a different level of permission than a light surface scan);
* you know who to contact if something goes wrong.

When in doubt, get it in writing first. Screenshots of chat messages do not
count as authorization.

## 2. Scope discipline

mikto will not widen your target list on its own: certificate SANs and other
discovered names are **reported as information and never scanned**. Keep the
same discipline as a human:

* build target files deliberately; re-check them before every run;
* never scan CIDR ranges "to see what's there" without explicit permission
  for the whole range;
* cloud environments: verify that your authorization covers the provider's
  shared infrastructure rules too (scanning things that are not yours inside
  a shared network is still unauthorized scanning).

## 3. What mikto will not do

The tool deliberately contains no:

* password bruteforce or credential stuffing;
* exploit payloads or exploitation logic;
* automatic database dumps or data exfiltration;
* denial-of-service logic of any kind;
* stealth/evasion features (fragmentation, decoys, randomization).

Its service probes are strictly read-only handshakes (`PING` to Redis,
`version` to memcached, `hello` to MongoDB, `GET /` to HTTP services). If a
probe would require authentication, mikto reports nothing and moves on —
attempting to bypass authentication is out of scope for this tool, always.

## 4. Data handling

Scan reports may contain sensitive facts (banner versions, secret-pattern
matches with redacted evidence, certificate details).

* Treat every report as confidential; share it only with the system owner
  and people they approve.
* Store reports on systems you control; do not paste them into public
  issue trackers.
* The HTML/JSON reports never contain full secret values — evidence is
  redacted by design. Do not try to reconstruct them from a target's live
  content without authorization.

## 5. Law

Unauthorized access to computer systems and networks is a crime in most
jurisdictions (computer-misuse laws, computer fraud and abuse statutes, etc.).
Unauthorized *scanning* is itself illegal in several of them. You are
responsible for compliance with the laws of your jurisdiction and the laws
that apply to the target. The mikto authors provide the tool as-is, under the
MIT license, and accept no liability for misuse.

## 6. A simple test

Before every run, finish this sentence out loud:

> "I am allowed to test **these hosts**, **at this intensity**, **because
> ______**, and I can prove it."

If you cannot finish the sentence — close the terminal.

## 7. v0.2 specifics: probing and public data

* **webpaths** sends GET requests to a curated list of well-known paths
  (admin panels, dotfiles, debug endpoints). Read-only, but it *is* active
  interaction: make sure your authorization covers it. `--deep` extends the
  path list.
* **subdom / emails / infra / neighbors** read PUBLIC third-party datasets
  (certificate transparency, web archives, Shodan InternetDB, urlscan,
  HackerTarget). They do not interact with the target beyond DNS. Third-party
  services see your queries — respect their terms and quotas.
* **assets (deep)** attempts a read-only **AXFR zone transfer** against the
  zone's nameservers. A properly configured server just refuses; the probe is
  the same as asking DNS for the zone — but it is still an interaction with
  your own DNS infrastructure, covered by any normal testing authorization.
* **whois** queries the public WHOIS registries (TCP/43) about your target
  domain. Pure third-party data lookup.
* **infra** additionally reads the keyless ipwho.is geolocation dataset and
  the abuse.ch URLhaus malware-URL feed; **cve** links findings to the public
  Exploit-DB index. These are third-party reads about the target, never
  interactions with it.
* Discovered subdomains and co-hosted sites are **listed, never scanned**.
  Adding them to scope is your explicit decision.
