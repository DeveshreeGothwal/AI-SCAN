# Methodology notes

reconai's tool selection isn't arbitrary — it's periodically checked against how real bug bounty
findings actually get discovered, so the pipeline keeps testing for things hunters actually find
instead of just things that are easy to automate. This file records the most recent pass: what was
reviewed, what gap it exposed, and — just as important — what was deliberately left out and why.

## Source reviewed

[devanshbatham/Awesome-Bugbounty-Writeups](https://github.com/devanshbatham/Awesome-Bugbounty-Writeups),
a curated index of ~600 public disclosure writeups grouped by vulnerability class (XSS, CSRF,
Clickjacking, LFI, Subdomain Takeover, DoS, Auth Bypass, SQLi, IDOR, 2FA, CORS, SSRF, Race
Condition, RCE, Android). Titles alone are a strong methodology signal at this volume — the same
techniques recur across hundreds of independent reports (e.g. "CORS misconfiguration ... account
takeover" appears a dozen different times, by a dozen different hunters, against a dozen different
targets), which is exactly the kind of pattern worth automating: it's common, it's mechanical, and
it doesn't need bug-specific creativity to detect.

## What the corpus actually shows

Reading by category rather than by individual writeup, the recurring *discovery* patterns are:

- **CORS**: near-every writeup is the same three checks — does the server reflect an arbitrary
  `Origin` verbatim, does it accept the literal `null` origin, does substring/regex validation
  break on a domain that merely starts or ends with the real one — then whether
  `Access-Control-Allow-Credentials: true` is also set (which is what turns "reflects origin" into
  "any site can read your authenticated data").
- **Clickjacking**: a single check — is there an `X-Frame-Options` header or a CSP
  `frame-ancestors` directive at all. Every writeup in this category is a variation on "there
  wasn't one."
- **Subdomain takeover**: dangling CNAME pointed at a deprovisioned cloud service. Already covered
  by `subjack` (unchanged by this pass).
- **SSRF**: the "recon wins" pattern shows up repeatedly — hunters don't fuzz blindly, they first
  scan parameter names/JS/wayback output for `url=`, `dest=`, `webhook=`, `callback=`-shaped
  parameters, *then* invest manual effort testing the promising ones with an out-of-band
  listener (Burp Collaborator or similar) to catch the server-side callback.
- **SQLi / LFI / command injection / SSTI / open redirect**: signature-based detection off a single
  crafted request is enough for the large majority of these writeups (an error string, a reflected
  `/etc/passwd`, a `Location` header pointing off-site). Already covered by `injection_probe`.
- **IDOR / 2FA bypass / auth bypass / race conditions**: every writeup in these categories depends
  on an authenticated session and app-specific business logic (increment an ID the current user
  shouldn't see, send two requests concurrently against a stateful action, abuse a specific login
  flow's assumptions). There's no generic, pre-auth signature to detect here.
- **RCE**: almost always the *end* of a chain (upload → LFI → RCE, SSRF → metadata → RCE,
  template injection → RCE), not something found directly. The chain's early links
  (LFI/SSTI/upload-adjacent misconfig) are what's detectable pre-auth; reconai already covers the
  signature-based ones.
- **GraphQL introspection** doesn't have its own category in this (2020-era) list, but shows up
  throughout the RCE/IDOR writeups as the modern equivalent of "leaky API docs" — an exposed
  schema hands an attacker the full data model for free.

## Gap identified and closed

Three categories were common, mechanical, detectable pre-auth with a handful of read-only HTTP
requests, and not yet covered: CORS, missing security headers (clickjacking chief among them), and
GraphQL introspection. Added:

| New tool | Covers | How |
|---|---|---|
| `cors_scan` | CORS misconfiguration | Sends 4 `Origin` variants (arbitrary, `null`, prefix-bypass, suffix-bypass) against the base URL, flags verbatim reflection or wildcard+credentials |
| `security_headers` | Clickjacking, MIME-sniffing, info disclosure, session-cookie hygiene, risky HTTP methods | One GET + one OPTIONS request; checks `X-Frame-Options`/CSP `frame-ancestors`, HSTS, `X-Content-Type-Options`, `Server`/`X-Powered-By` version strings, `Set-Cookie` flags, and `Allow` for `PUT`/`DELETE`/`TRACE`/`CONNECT` |
| `graphql_probe` | Exposed GraphQL schemas | Minimal introspection query (`{__schema{queryType{name}}}`) against common paths plus any `graphql`-looking endpoint already surfaced by `getjs`/`linkfinder`/`waybackurls` |

`injection_probe` also gained a **static SSRF-parameter flag**: parameter names shaped like
`url`/`dest`/`webhook`/`callback`/etc. (already present in `waybackurls` output) are listed as
"flagged for manual review" — zero extra requests, mirroring the "recon wins" triage pattern
instead of pretending to auto-confirm something that needs an out-of-band listener to prove.

All three new tools are pure `httpx` (the pip library already in `requirements.txt`) — no new
binary, no signup, no cost, consistent with the rest of the free-tier tooling documented in
[README.md](README.md).

## Deliberately not automated, and why

- **IDOR, 2FA bypass, most auth-bypass, race conditions**: every real example needs an
  authenticated session and knowledge of the target's specific business logic (which ID scheme,
  which endpoint is stateful, which flow has the timing window). reconai is a pre-auth recon tool;
  faking this generically would mean either doing nothing useful or guessing so broadly it's just
  noise. Out of scope by design, not by oversight.
- **Active SSRF confirmation**: proving SSRF safely means standing up an out-of-band callback
  listener and correlating a callback — real infrastructure, not a code change, and risks becoming
  its own maintenance burden for a "free, no signup" tool. The static parameter-flag above is the
  right-sized substitute: it does the recon, leaves the confirmation (and the OOB infra decision)
  to the human.
- **RCE**: essentially never a direct finding pre-auth in this corpus — it's the payoff at the end
  of a chain reconai's other tools already probe the entry points of (SSTI via `injection_probe`,
  exposed panels/backups via `gobuster`/`ffuf`, known CVEs via `cve_correlate`/`nuclei`).
  Auto-*exploiting* a suspected RCE to confirm it would cross from detection into exploitation,
  which is out of scope for the whole pipeline (see README's injection-testing-scope section).
- **Android pentesting**: entirely different target type and toolchain (APK decompilation,
  `jadx`/`apktool`/MobSF) — out of scope for what is a web-target recon tool.
- **DoS**: findings in this category are inherently about degrading a live service; deliberately
  triggering one is the opposite of "safe, non-destructive recon."

## How this feeds into the existing pipeline

`cors_scan` and `security_headers` slot into the existing web-tools stage (they only need the base
URL, same as `whatweb`/`wafw00f`). `graphql_probe` reuses endpoint data `getjs`/`linkfinder` and
parameter data `waybackurls` already collected, rather than crawling again — same "reuse what's
already been gathered" principle `secret_scan` and `cve_correlate` established. See
[pipeline.py](reconai/pipeline.py)'s `STAGE_ORDER` for the full, current sequence.
