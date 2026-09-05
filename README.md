# reconai

AI-assisted recon automation for **authorized** penetration testing / bug bounty work. Give it a
target, it runs a standard set of free, publicly-available Kali recon tools against it (passive
OSINT first, then active scanning if a web service is found), and uses a local Ollama model or the
Claude API to write a narrative summary report.

**Only run this against targets you own or have explicit written permission to test.**

**New to this repo?** Jump to [Development (off Kali)](#development-off-kali) first — it's the
fastest path to a working checkout on any machine (macOS/Linux/WSL), needs nothing beyond Python,
and lets you run the full test suite plus `--dry-run`/`--mock` scans with zero setup. Real,
non-mocked scans need the tool stack in [Setup (on Kali)](#setup-on-kali) below, which only matters
once you're actually running scans rather than working on the code.

## Tools run

| Stage | Tool | Purpose |
|-------|------|---------|
| Passive | whois | Domain registration |
| Passive | dnsrecon | DNS record enumeration |
| Passive | dns_axfr | Attempts a DNS zone transfer (AXFR) against each nameserver — flags full zone leaks |
| Passive | subfinder | Subdomain discovery |
| Passive | crtsh | Direct certificate-transparency query (crt.sh) — extra subdomain coverage beyond subfinder's sources |
| Passive | theHarvester | Email/host OSINT |
| Passive | bucket_enum | Checks S3/GCS/Azure for buckets/storage accounts named after the target |
| Passive | github_secrets | Guesses the target's GitHub org, clones its top repos, scans with trufflehog (verified secrets only) |
| Passive | httpx | Probes discovered subdomains for live hosts (status, title, tech) |
| Passive | subjack | Checks discovered subdomains for takeover-able dangling CNAMEs |
| Passive | waybackurls | Fetches historical URLs from the Wayback Machine archive (never queries the target) |
| Active | nmap | Port scan + service/version detection |
| Active (web port found) | whatweb | Web tech fingerprinting |
| Active | nikto | Web vuln/misconfig scanner |
| Active | gobuster | Directory brute-forcing |
| Active | ffuf | Directory brute-forcing (second engine — different wildcard-detection heuristics catch different things) |
| Active | wafw00f | WAF detection |
| Active (web port found) | cors_scan | Tests Origin-header variants for reflected/wildcard CORS misconfigurations |
| Active (web port found) | security_headers | Clickjacking, HSTS/CSP/nosniff gaps, cookie flags, version-disclosing headers, risky HTTP methods |
| Active (web port found) | auth_audit | Checks discovered login/registration forms for cleartext credential submission, weak password-length caps, and missing CSRF-token naming patterns |
| Active (web port found) | privacy_scan | Checks for tracking scripts loaded without a consent-management marker, and missing Referrer-Policy/Permissions-Policy headers |
| Active | nuclei | Template-based CVE/misconfig scanning |
| Active | getJS | Lists JS files referenced by the page |
| Active | LinkFinder | Extracts API endpoints/paths from page + JS |
| Active (web port found) | cve_correlate | Cross-references whatweb/nmap product versions against the NVD for known CVEs |
| Active (web port found) | secret_scan | Regex-scans JS files + common exposed config paths (`.env` etc.) for high-confidence secret patterns. `--validate-secrets` opt-in adds one read-only confirmatory call per Stripe/Slack secret found (see below) |
| Active (web port found) | graphql_probe | Checks common + discovered GraphQL endpoints for introspection enabled |
| Active (param URLs found) | injection_probe | Custom safe-detection probe: SQLi (error-based), command injection, SSTI, path traversal, open redirect, plus a static (zero-request) flag of SSRF-prone parameter names for manual follow-up |
| Active (param URLs found) | sqlmap | SQL injection detection, locked to safe flags (see below) |
| Active (https port found) | testssl | SSL/TLS configuration audit |

Then a local Ollama model or the Claude API writes a narrative summary over all raw output, and
`reconai/report/impact_analysis.py` derives a plain-language "Security Score" (0-100 + letter
grade) from the findings, surfaced live in the dashboard's report view.

## Check a Link (standalone, no scan required)

Separate from the tools table above: the dashboard's "Check a Link" tab runs a quick heuristic
safety check on a single URL someone sends you (email/SMS/DM) — insecure connection, IP-literal
or punycode hostname, brand-impersonation keywords, known URL shorteners, redirect-chain length,
elevated-risk TLDs, and domain age. It's intentionally **not** gated behind the "I have
authorization" checkbox that scans require: checking a link you received is a self-protective
action, not testing someone else's infrastructure. See `reconai/tools/link_safety_tool.py`.

See [METHODOLOGY.md](METHODOLOGY.md) for how these stages map to real bug-bounty methodology (and, just as
importantly, what's deliberately *not* automated here and why).

### Cloud/OSINT/secrets tools — all free, no required signup

- `dns_axfr`, `crtsh`, `bucket_enum` need nothing beyond what's already installed — they're plain
  HTTP/DNS requests to public infrastructure (crt.sh, S3/GCS/Azure, the target's own nameservers).
- `cve_correlate` queries the NVD's public API. Unauthenticated requests are rate-limited to 5 per 30s,
  which reconai respects with a deliberate delay between the (capped, few) lookups it makes. An
  optional free `NVD_API_KEY` (signup at nvd.nist.gov, no cost) raises that to 50/30s if you want it.
- `github_secrets` guesses a GitHub org name from the target domain and only proceeds if a matching
  *public* org actually exists — many companies won't match, in which case it just reports that and
  moves on. Unauthenticated GitHub API calls are limited to 60/hour; set `GITHUB_TOKEN` (a free
  personal access token, no scopes needed for public data) if you hit that limit.
- `bucket_enum`'s bucket-name guesses and `github_secrets`'s org-name guess both derive from
  `base.guess_org_name()` — the label before the registrable-domain boundary (`syfe` from
  `mark8.syfe.com`), with a small built-in list of common multi-part public suffixes (`.co.uk`,
  `.gov.in`, etc.) so it doesn't misfire on those. Verified needed for real: `www.csk.gov.in` naively
  guessed `"gov"` instead of `"csk"` before this list was added — not just noisy (every unrelated
  "gov"-named S3/GCS bucket on the internet "matched"), but a real authorization-boundary risk for
  `github_secrets` specifically, which would clone and scan whatever GitHub org is actually named
  `"gov"` if one exists, rather than the intended target. Still a best-effort guess outside that
  list, and for orgs that don't share the domain's name at all. `github_secrets` additionally
  refuses to proceed when the guessed name is under 4 characters — verified for real that even the
  *corrected* guess for `www.csk.gov.in` ("csk") is a genuine, unrelated GitHub user account (short
  usernames are highly contested and get claimed early by unrelated people); cloning and scanning it
  would be a real authorization-boundary violation, not just a noisy result, so it's skipped instead.
- `cors_scan`, `security_headers`, and `graphql_probe` need nothing beyond the existing `httpx` pip
  dependency — they're plain HTTP requests against the target's own base URL (varied `Origin`
  headers, a GET + OPTIONS for header/method inspection, a minimal introspection query against
  common/discovered GraphQL paths), no third-party service involved.

### Validating found secrets (opt-in, minimal-impact only)

`secret_scan` detects secrets by regex alone, which can't tell a live credential from one that's
already been rotated/revoked. `--validate-secrets` (CLI) / the "validate found secrets" toggle
(dashboard) turns on exactly one read-only confirmatory call per Stripe secret key or Slack token
found, to the credential's own provider (`GET /v1/charges?limit=1` on Stripe, Slack's own
`auth.test` endpoint) — the same "one confirmatory call, then stop" pattern `github_secrets` already
uses via trufflehog's `--only-verified`. Off by default. Deliberately *not* extended to: AWS access
keys (the regex only captures the key ID, not a paired secret, so there's nothing to validate alone),
or a generic webhook-post-style check for Slack (posting a real message to a live channel is a
state-changing action on the target's systems, not a read). If you need to confirm impact beyond
that — list a Stripe account's real transactions, enumerate an AWS account, etc. — do that manually
and deliberately outside of reconai, for the same reason noted below for injection findings.

### Injection testing scope (detection only, not exploitation)

`injection_probe` and `sqlmap` test parameters discovered via `waybackurls` for injection
vulnerabilities, but deliberately stop at *detection* — reconai never extracts data, opens a shell,
or otherwise acts on a confirmed finding:

- `injection_probe` (custom, in `reconai/tools/injection_probe_tool.py`) sends a small, capped number
  of single-purpose payloads per parameter (SQL error-based, benign `id`/`whoami` command-injection
  check, `{{7*7}}`-style template-injection reflection, `/etc/passwd`-signature path traversal, and
  Location-header open-redirect check for redirect-shaped parameter names) and reports only
  high-confidence signature matches. No boolean/time-based SQLi (too noisy without a stable
  baseline), no active SSRF probing (confirming it safely needs an out-of-band callback listener,
  which is out of scope here — instead, parameter names with an SSRF-prone shape, e.g. `url`, `dest`,
  `webhook`, `proxy`, are statically flagged for manual testing with zero extra requests), no XXE
  (needs an XML-accepting endpoint, which doesn't fit GET-parameter fuzzing), no destructive payloads.
- `sqlmap` is invoked with `--batch --risk=1 --level=1 --technique=BEU` — sqlmap's own least-invasive
  defaults, restricted to Boolean-blind/Error-based/UNION techniques only (excludes Time-based, which
  is slow, and Stacked-queries, which can run statements beyond the original query). reconai never
  passes `--dump`, `--dump-all`, `--os-shell`, `--sql-shell`, or `--os-pwn`.

If you need to actually extract data or gain shell access from a confirmed finding, do that manually
and deliberately with the real `sqlmap`/`commix` CLI outside of reconai — that's a different risk
category than automated recon and shouldn't happen unattended inside a pipeline.

### Routing scans through a proxy

Off by default (direct connections). Turn it on per-scan:

```bash
python3 recon.py example.com --proxy socks5://127.0.0.1:9050   # any SOCKS5/SOCKS4/HTTP proxy
python3 recon.py example.com --tor                              # shorthand for the line above
```

`--tor` is a convenience flag for a local Tor daemon — free, no signup, no third-party service:

```bash
sudo apt install tor && sudo systemctl start tor
```

On the live dashboard, toggle "route through proxy" on the scan form and enter the proxy URL (same
deep-link support as the rest of the form: `?proxy=socks5://127.0.0.1:9050`).

**Every tool was individually, empirically verified** against a real proxy (first a local test
listener, then a live Tor circuit against a real target) rather than assumed to work from
documentation alone — both passes turned up real gaps, some only visible with a genuine SOCKS5
proxy rather than a generic listener:

| Mechanism | Tools |
|---|---|
| Native `--proxy`-style flag (most reliable) | subfinder, nuclei, httpx (ProjectDiscovery), gobuster, ffuf, sqlmap, wafw00f, and whatweb/nikto for **HTTP proxies only** (see below) |
| Go's default HTTP transport honors `HTTP_PROXY`/`HTTPS_PROXY` env vars | waybackurls, trufflehog |
| `proxychains4` (works for anything linked against libc: whois, dig/dnsrecon, nmap, git, Python/Perl/bash tools) | whois, dns, dns_axfr, theHarvester, LinkFinder, nmap, git (used by github_secrets), whatweb/nikto for **SOCKS4/5 proxies**, plus a fallback layer under every tool above |
| **Not proxyable — skipped outright rather than run unprotected** | **getJS, subjack** (small Go binaries confirmed to honor neither mechanism) |

A couple of specifics worth knowing if something looks off:

- **`whatweb` and `nikto` only take their own `--proxy`/`-useproxy` flag for `http://`/`https://`
  proxies.** Verified for real against a live Tor SOCKS5 port: whatweb got `501 "Tor is not an HTTP
  Proxy"` (Tor's own SOCKS port explicitly detects and rejects HTTP CONNECT), and nikto mis-parsed
  the URL entirely (`can't connect: no port given for proxy server socks5::80`) — neither tool's
  native flag understands a SOCKS proxy. For `socks4://`/`socks5://`, reconai skips their native
  flag and falls back to `proxychains4` instead, which was separately verified to work correctly
  for both (whatweb is Ruby, nikto is Perl — both dynamically linked against libc).
- `nmap` switches to a TCP connect scan (`-sT`) instead of its default SYN scan whenever a proxy is
  set — a SYN scan crafts raw packets below the socket layer, which no proxy mechanism can intercept,
  proxychains included. Slightly slower/noisier, but there's no way around it.
- `dig`-based lookups (`dns`, `dns_axfr`) and `testssl` (which shells out to `dig` internally to
  resolve the target) disable proxychains' `proxy_dns` option specifically — verified for real:
  with it on, both failed outright ("dig: parse of /etc/resolv.conf failed" →
  "Fatal error: No IPv4/IPv6 address(es) for ... available"). The actual DNS/zone-transfer/TLS
  traffic is still proxied; only that one internal hostname lookup falls back to your normal
  resolver.
- Setting proxy env vars *and* proxychains-wrapping the same call is never combined — reproduced a
  real failure doing so (`curl: Failed to connect ... Could not connect to server`): a tool that
  reads the env var itself tries to dial the proxy address, and proxychains intercepts that
  connection too, looping it back through the same proxy a second time. Each subprocess call uses
  exactly one mechanism.
- Routing through Tor specifically adds real latency and occasional circuit flakiness — don't be
  surprised if a slow tool (`testssl`) times out or comes back empty on a run that would succeed on
  a retry; that's Tor, not a reconai bug.
- A `socks5://` proxy needs the optional `socksio` package for the in-process (`httpx`-based) tools
  — already in `requirements.txt`, but if you're on an older install: `pip install httpx[socks]`.
- `getJS`/`subjack` being unproxyable means their subdomain-takeover and JS-discovery data simply
  won't be collected while a proxy is on. Run a second pass without `--proxy` if you need it and
  direct connections to those specific lookups are acceptable.

## Setup (on Kali)

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Recon tools used (skip any you don't need — missing tools are skipped gracefully)
sudo apt install -y whois dnsutils dnsrecon theharvester nmap whatweb nikto gobuster \
  nuclei wafw00f testssl.sh ffuf
nuclei -update-templates

# proxychains4 -- only needed if you use --proxy/--tor (see "Routing scans through a
# proxy" above). Usually already present on Kali.
sudo apt install -y proxychains4

# tor -- only needed for the --tor shorthand. Free, local, no signup.
sudo apt install -y tor && sudo systemctl start tor

# subfinder isn't packaged on all Kali versions:
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# ProjectDiscovery's httpx -- NOT the apt "httpx" package, which is an unrelated
# Python HTTP client that happens to share the binary name. Installs to ~/go/bin,
# which the pipeline calls by absolute path to avoid the collision.
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# GetJS -- also installs to ~/go/bin
go install -v github.com/003random/getJS/v2@latest

# LinkFinder -- no apt/go package, runs from its own clone + venv
git clone https://github.com/GerbenJavado/LinkFinder.git ~/LinkFinder
cd ~/LinkFinder && python3 -m venv venv && venv/bin/pip install setuptools -r requirements.txt
cd -

# subjack -- subdomain takeover checking. Installs to ~/go/bin.
go install -v github.com/haccer/subjack@latest

# waybackurls -- historical/parameterized URL discovery. Installs to ~/go/bin.
go install -v github.com/tomnomnom/waybackurls@latest

# sqlmap ships preinstalled on most Kali images; if missing:
sudo apt install -y sqlmap

# trufflehog -- verified-secrets scanning for github_secrets. Installs to ~/go/bin.
# `go install` does NOT work here -- trufflehog's go.mod has a replace directive
# that go install rejects, so use their install script (fetches a binary release):
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
  | sh -s -- -b ~/go/bin
# Also needs `git` (sudo apt install git, usually already present on Kali).
```

`dns_axfr` needs `dig` (already covered by `dnsutils` above). `crtsh`, `bucket_enum`,
`cve_correlate`, `secret_scan`, `cors_scan`, `security_headers`, and `graphql_probe` need nothing
beyond the Python `httpx` library already in `requirements.txt` — no extra install.

### Using Ubuntu instead of Kali

Kali and Ubuntu are both Debian-based, so `apt` itself behaves the same — but Kali curates its own
security-tool repos that Ubuntu doesn't have. Checked against Ubuntu 22.04/24.04's actual package
index: `whois`, `dnsutils`, `dnsrecon`, `nmap`, `whatweb`, `nikto`, `gobuster`, `wafw00f`,
`testssl.sh`, `ffuf`, `sqlmap`, `proxychains4`, and `tor` are all present in Ubuntu's own repos and
install identically. Three are **not** packaged for Ubuntu at all and need a different install path:

```bash
# nuclei is a Go tool -- go install works the same as subfinder/httpx above:
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# gobuster: Ubuntu 22.04 ships v2.0.1 via apt, which doesn't have the "dir"
# subcommand this project's gobuster_tool.py depends on (gobuster v3 syntax --
# `gobuster dir -u ... -w ...`). 22.04's apt package will fail outright. 24.04
# ships v3.6.0 and is fine as-is; on 22.04 (or to be safe regardless of
# release), get current v3 via go install instead of apt:
go install github.com/OJ/gobuster/v3@latest

# theHarvester isn't packaged for Ubuntu -- follow its own install instructions:
# https://github.com/laramies/theHarvester

# seclists (only needed for --wordlist-size large) -- clone instead of apt:
git clone https://github.com/danielmiessler/SecLists.git ~/SecLists
# then: python3 recon.py <target> --wordlist-size large --wordlist ~/SecLists/Discovery/Web-Content/raft-large-directories.txt
```

Also install a Go toolchain if it's not already present (`sudo apt install -y golang-go`) — needed
for every `go install` line on this page, Kali or Ubuntu alike.

### Wordlists (gobuster/ffuf)

Pick a tier at runtime with `--wordlist-size {small,medium,large}` (default `small`), or pass an
exact path with `--wordlist /path/to/list.txt` (overrides the tier). `small` and `medium` ship with
Kali by default; `large` needs SecLists:

```bash
sudo apt install seclists   # only needed for --wordlist-size large
```

### AI backend

Pick one at runtime with `--llm ollama` (default), `--llm claude`, or `--llm groq`.

**Ollama (local, free, offline)** — recommended default for a Kali VM with limited RAM:

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.2:3b
ollama serve &
```

**Claude (cloud API, stronger summaries, needs internet + a paid key):**

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

**Groq (cloud API, genuinely free tier, no card needed):** get a key at
[console.groq.com/keys](https://console.groq.com/keys) (email/GitHub/Google sign-in, no billing
setup), then:

```bash
export GROQ_API_KEY=gsk_...
python3 recon.py example.com --llm groq
```

## Usage

```bash
python3 recon.py example.com
python3 recon.py example.com --llm claude --pdf
python3 recon.py example.com --dry-run          # check tool availability, no execution
python3 recon.py example.com --mock --llm ollama # exercise the pipeline with canned sample output
python3 recon.py example.com --wordlist-size medium
python3 recon.py example.com --tor              # route through a local Tor daemon
python3 recon.py example.com --proxy socks5://127.0.0.1:9050
python3 recon.py example.com --validate-secrets # one read-only confirmatory call per Stripe/Slack secret found
```

### Live dashboard

```bash
python3 recon.py --serve                # binds 127.0.0.1:8765 by default
```

Opens a web UI (same host as the pipeline) that streams per-tool progress in real time over SSE:
launch a scan from the form, or deep-link one with `?target=X&authorized=1&autostart=1`. From another
machine, reach it over an SSH tunnel rather than exposing the port:

```bash
ssh -L 8765:127.0.0.1:8765 <kali-host>
# then open http://127.0.0.1:8765 locally
```

Results are written to `results/<target>/<timestamp>/`: one `.txt` file per tool, `summary.md` (AI
narrative + raw findings), `impact.json` (the Security Score data), optional `summary.pdf`, and
`manifest.json` (run metadata).

## Public demo deployment (Render)

`Dockerfile` builds the whole tool stack on top of `kalilinux/kali-rolling` (a near-verbatim copy
of the [Setup (on Kali)](#setup-on-kali) block above, so it's the same proven install commands,
not a reinvented Ubuntu/Debian equivalent), and `render.yaml` deploys it as a Render Blueprint:

1. Push this repo to GitHub (already done if you're reading this from there).
2. On [render.com](https://render.com): **New → Blueprint**, point it at the repo. It picks up
   `render.yaml` automatically.
3. Fill in the env vars Render prompts for (declared with `sync: false` in `render.yaml`, so
   they're entered directly in Render's dashboard, never committed to the repo):
   - **`GROQ_API_KEY`** (required) — Ollama isn't viable in a small container (no local model
     server, not enough RAM), and Claude's API needs a paid credit balance, so this deployment
     runs on Groq's backend: a hosted API with a genuinely free tier (no card, no spend — sign up
     at [console.groq.com/keys](https://console.groq.com/keys)). Its free-tier rate limit
     (14,400 requests/day) is far more than a demo doing one AI call per completed scan will hit.
   - **`DASHBOARD_BASIC_AUTH_USER`** / **`DASHBOARD_BASIC_AUTH_PASS`** (optional) — if set, every
     request needs HTTP Basic Auth (the browser's own login prompt), so only people you've shared
     the password with can reach the dashboard. Leave both unset (the default) if you have no side
     channel to hand judges a separate password alongside the link — the allowlist below is what
     actually caps abuse risk, not this.
   - **`ALLOWED_SCAN_TARGETS`** (strongly recommended, defaults to `scanme.nmap.org` in
     `render.yaml`) — restricts `/scan` to a comma-separated allowlist. Without this, anyone with
     dashboard access could point real scan traffic (port scans, sqlmap, directory brute-forcing)
     at *any* domain from Render's shared IP space — exactly what cloud providers' acceptable-use
     policies prohibit, regardless of who's asking or why. `scanme.nmap.org` is Nmap's own
     official public test target, maintained with blanket permission for exactly this. This
     restriction only applies to `/scan` — the standalone "Check a Link" feature is unaffected,
     since it only ever makes one benign GET + a WHOIS lookup against whatever URL you give it.
   - **`DISABLED_TOOLS`** (recommended for this 512MB instance, defaults to `github_secrets` in
     `render.yaml`) — comma-separated tool names to skip entirely. `github_secrets` clones and
     scans a real GitHub repo per scan, which verified in practice can OOM-crash a 512MB
     container; disabling it here doesn't affect local/Kali usage.

   None of these are required for the Docker image to *build* — only for the deployment to
   be safe (and stable) to leave a public link to.

4. `render.yaml` requests the **free** instance type, so no payment info is needed to deploy.
   Two tradeoffs come with that:
   - Free web services spin down after 15 minutes idle, so the first request after a gap takes
     ~30-60s to wake back up before the dashboard responds. If that cold start is a problem for a
     specific demo moment, switch `plan: free` to `plan: starter` in `render.yaml` (requires a
     card on file) for an always-on instance.
   - **512MB RAM** -- verified in practice that a single scan's `github_secrets` stage (cloning +
     scanning a real repo) can OOM-crash the container at this limit. `/scan` now runs one scan at
     a time server-side (409 if another is already in progress) specifically to avoid compounding
     that with concurrent scans; `github_secrets` also only clones/scans the single
     most-recently-pushed repo rather than several.
5. When you're done: suspend or delete the Render service (or just unset the basic-auth password)
   to kill the link instantly. No lingering cost or exposure.

Neither this Dockerfile nor a full Docker build has been run/verified locally (no Docker available
in this project's dev environment) — Render's own build is the first real test of the full
install sequence end-to-end. Watch the first build's logs; a specific install step may need a
follow-up fix.

## Development (off Kali)

None of the recon binaries exist outside Linux, so pipeline/report logic is developed and tested
here using `--dry-run` (exercises the "tool not found" path for every wrapper) and `--mock`
(exercises the full pipeline against canned realistic sample output). Verified working from a
clean clone on macOS with just Python 3.9+:

```bash
git clone <this repo> && cd reconai
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt pytest
pytest tests/                              # 288 tests, no external tools needed
python3 recon.py example.com --dry-run --yes
```

`--yes` above isn't optional in a script/CI context: the authorization banner refuses to proceed
in a non-interactive session unless it's passed explicitly, even if you pipe `y` at the prompt —
deliberate, so a scan can't accidentally run unattended without someone actually confirming
authorization. Only needed for `--dry-run`/`--mock`/scripted runs; a real interactive terminal
session prompts normally.
