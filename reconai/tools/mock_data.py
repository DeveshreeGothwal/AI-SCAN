"""Canned, realistic sample output per tool, used by --mock so the report/LLM
pipeline can be exercised on a machine that doesn't have the real binaries."""

MOCK_OUTPUTS: dict[str, str] = {
    "whois": (
        "Domain Name: EXAMPLE.COM\n"
        "Registrar: Example Registrar, LLC\n"
        "Creation Date: 1995-08-14T04:00:00Z\n"
        "Registry Expiry Date: 2027-08-13T04:00:00Z\n"
        "Name Server: A.IANA-SERVERS.NET\n"
        "Name Server: B.IANA-SERVERS.NET\n"
    ),
    "dns": (
        "example.com.\t300\tIN\tA\t93.184.216.34\n"
        "example.com.\t300\tIN\tMX\t0 .\n"
        "example.com.\t300\tIN\tNS\ta.iana-servers.net.\n"
        "example.com.\t300\tIN\tNS\tb.iana-servers.net.\n"
        "example.com.\t300\tIN\tTXT\t\"v=spf1 -all\"\n"
    ),
    "subfinder": ("www.example.com\napi.example.com\nstaging.example.com\nmail.example.com\n"),
    "theharvester": (
        "[*] Emails found: 2\n"
        "admin@example.com\n"
        "support@example.com\n"
        "[*] Hosts found: 3\n"
        "www.example.com:93.184.216.34\n"
        "api.example.com:93.184.216.35\n"
    ),
    "nmap": (
        "Nmap scan report for example.com (93.184.216.34)\n"
        "Host is up (0.021s latency).\n"
        "PORT     STATE SERVICE VERSION\n"
        "22/tcp   open  ssh     OpenSSH 8.9p1\n"
        "80/tcp   open  http    nginx 1.22.1\n"
        "443/tcp  open  ssl/http nginx 1.22.1\n"
    ),
    "whatweb": (
        "http://example.com [200 OK] Country[UNITED STATES], "
        "HTTPServer[nginx/1.22.1], IP[93.184.216.34], Nginx[1.22.1], Title[Example Domain]\n"
    ),
    "nikto": (
        "- Nikto v2.5.0\n"
        "+ Target IP: 93.184.216.34\n"
        "+ Server: nginx/1.22.1\n"
        "+ /: The X-Content-Type-Options header is not set.\n"
        "+ /admin/: Directory indexing found.\n"
        "+ 2 host(s) tested\n"
    ),
    "gobuster": (
        "/admin                (Status: 301)\n"
        "/backup               (Status: 200)\n"
        "/login                (Status: 200)\n"
        "/robots.txt           (Status: 200)\n"
    ),
    "httpx": (
        "https://www.example.com [200] [Example Domain] [nginx]\n"
        "https://api.example.com [401] [] [nginx]\n"
        "http://staging.example.com [403] [Forbidden] [Apache]\n"
    ),
    "nuclei": (
        "[CVE-2017-5638] [http] [critical] https://example.com/ (Apache Struts RCE)\n"
        "[missing-hsts-header] [http] [info] https://example.com/\n"
    ),
    "ffuf": (
        "admin                   [Status: 301, Size: 0, Words: 1, Lines: 1]\n"
        "backup.zip              [Status: 200, Size: 4021, Words: 12, Lines: 1]\n"
    ),
    "wafw00f": (
        "[*] Checking https://example.com\n"
        "[+] The site https://example.com is behind Cloudflare (Cloudflare Inc.) WAF.\n"
        "[~] Number of requests: 2\n"
    ),
    "testssl": (
        " Testing protocols via sockets except NPN+ALPN\n"
        " SSLv2      not offered\n"
        " TLS 1.2    offered\n"
        " TLS 1.3    offered\n"
        " Certificate Validity  365 >= 60 days (OK)\n"
    ),
    "getjs": (
        "https://example.com/static/main.js\n"
        "https://example.com/static/vendor.bundle.js\n"
    ),
    "linkfinder": (
        "/api/v1/users\n"
        "/api/v1/login\n"
        "/static/main.js\n"
        "https://api.example.com/graphql\n"
    ),
    "gowitness": "https://example.com\n[MOCK] screenshot saved (no real file written)",
    "subjack": (
        "[Not Vulnerable] www.example.com\n"
        "[VULNERABLE] old-staging.example.com (CNAME: old-staging.herokudns.com, Provider: Heroku)\n"
    ),
    "waybackurls": (
        "https://example.com/product.php?id=1\n"
        "https://example.com/search?q=test&category=all\n"
        "https://example.com/redirect?url=https://example.com/home\n"
        "https://example.com/about\n"
    ),
    "injection_probe": (
        "Probed 3 parameterized URL(s), 4 parameter(s) tested.\n\n"
        "[SQL Injection] param 'id' on https://example.com/product.php?id=1 -- "
        "SQL error signature after appending a single quote\n"
        "[Reflected XSS] param 'q' on https://example.com/search?q=shoes -- "
        "injected marker reflected unescaped in response\n"
        "[Open Redirect] param 'url' on https://example.com/redirect?url=https://example.com/home -- "
        "Location header points at an attacker-controlled URL\n\n"
        "[Informational] parameter name(s) suggestive of SSRF -- not auto-tested "
        "(safely confirming SSRF needs an out-of-band callback listener, out of scope "
        "here), flagged for manual review:\n"
        "param 'url' on https://example.com/redirect?url=https://example.com/home\n"
    ),
    "cors_scan": (
        "Tested 4 Origin header variant(s) against the base URL.\n\n"
        "[CORS Misconfiguration] Origin 'https://reconai-cors-test.invalid' reflected verbatim "
        "in Access-Control-Allow-Origin -- credentials also allowed, so session-riding is possible\n"
    ),
    "security_headers": (
        "[Clickjacking] no X-Frame-Options header and no CSP frame-ancestors directive -- "
        "the page can be embedded in a hostile <iframe>\n"
        "[Missing Header] X-Content-Type-Options: nosniff not set -- browsers may MIME-sniff responses\n"
        "[Cookie Misconfiguration] cookie 'session' missing: httponly, samesite\n"
    ),
    "graphql_probe": (
        "Probed 6 candidate GraphQL endpoint(s).\n\n"
        "[GraphQL Introspection Enabled] https://example.com/graphql -- full schema is "
        "queryable (types, fields, mutations)\n"
    ),
    "auth_audit": (
        "Probed 12 candidate authentication endpoint(s).\n\n"
        "[Cleartext Credential Submission] http://example.com/login -- password form served over "
        "plain HTTP; credentials are sent unencrypted and can be intercepted by anyone on the "
        "network path\n"
        "[Weak Password Policy] http://example.com/register -- password field caps input at "
        "8 characters, well below a reasonable minimum\n\n"
        "[Informational] account lockout / rate-limiting was not tested -- doing so would require "
        "repeated login attempts against a real account, which this tool deliberately never does. "
        "Verify this manually/internally.\n"
    ),
    "privacy_scan": (
        "[Tracking Without Consent Signal] tracker script(s) detected (googletagmanager.com, "
        "fbq() (+1 more)) with no cookie-consent/CMP marker found in the same response -- "
        "trackers may be loading before any consent is given\n"
        "[Weak Referrer Policy] Referrer-Policy header is missing -- the full URL (which can "
        "contain sensitive query parameters) may leak to third parties via the Referer header on "
        "outbound links\n"
    ),
    "link_safety": (
        "Checked https://paypa1-secure-login.xn--80ak6aa92e.zip/verify\n\n"
        "Verdict: HIGH RISK\n\n"
        "[Punycode/Homograph Domain] hostname contains punycode-encoded characters -- often used "
        "to visually impersonate a trusted domain with lookalike characters\n"
        "[Possible Brand Impersonation] hostname contains 'paypal' but the actual domain is not "
        "paypal's real domain -- a classic phishing pattern\n"
        "[Elevated-Risk TLD] .zip is disproportionately used in abuse campaigns -- not proof of "
        "malice on its own, just an elevated-risk signal\n"
        "[Newly Registered Domain] registered 4 day(s) ago -- freshly-registered domains are "
        "disproportionately used in phishing/scam campaigns\n"
    ),
    "sqlmap": (
        "[INFO] testing connection to the target URL\n"
        "[INFO] testing if the target URL content is stable\n"
        "[WARNING] heuristic (basic) test shows that GET parameter 'id' might be injectable\n"
        "[INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'\n"
        "sqlmap identified the following injection point(s) with a total of 32 HTTP(s) requests:\n"
        "---\n"
        "Parameter: id (GET)\n"
        "    Type: boolean-based blind\n"
        "    Title: AND boolean-based blind - WHERE or HAVING clause\n"
        "    Payload: id=1 AND 1=1\n"
        "---\n"
        "[INFO] the back-end DBMS is MySQL\n"
    ),
    "dns_axfr": (
        "$ dig NS example.com +short\n"
        "a.iana-servers.net.\nb.iana-servers.net.\n\n"
        "$ dig @a.iana-servers.net example.com AXFR\n"
        "no zone transfer (refused/failed) -- OK\n"
    ),
    "crtsh": ("www.example.com\napi.example.com\nold-vpn.example.com\n"),
    "bucket_enum": (
        "Checked 75 bucket-name candidate(s) across S3/GCS/Azure.\n\n"
        "[S3] https://example-backup.s3.amazonaws.com/ -- PUBLIC (listable)\n"
        "[GCS] https://storage.googleapis.com/example-assets/ -- exists, access denied (private)\n"
    ),
    "secret_scan": (
        "Scanned 2 JS file(s) and 6 common config path(s).\n\n"
        "[AWS Access Key] found in https://example.com/static/vendor.bundle.js: AKIAIOSFODNN7...\n"
        "[Exposed config file] https://example.com/.env is accessible and looks like real config content\n"
    ),
    "cve_correlate": (
        "Correlating 2 detected product/version pair(s) against the NVD (nvd.nist.gov).\n"
        "Heuristic keyword match, not a strict CPE match -- verify manually before reporting.\n\n"
        "### nginx 1.22.1\n"
        "  - CVE-2022-41741: Buffer overread in nginx MP4 module...\n\n"
        "### OpenSSH 8.9p1\n"
        "  (no CVE matches found, or the NVD query failed)\n"
    ),
    "github_secrets": (
        "GitHub org guess: 'example'. Scanned 2 repo(s) (shallow clone, latest commit only).\n\n"
        "[example-web] no verified secrets found\n\n"
        "[example-infra] {\"SourceMetadata\":{\"Data\":{\"Filesystem\":{\"file\":\"deploy.sh\"}}},"
        "\"DetectorName\":\"AWS\",\"Verified\":true}\n"
    ),
    "google_dorks": (
        "Generated 13 Google dork queries for manual review.\n"
        "Not executed automatically -- automating Google searches risks CAPTCHA/ToS issues, "
        "especially from a Tor exit node. Open these yourself in a browser.\n\n"
        "### Directory listings\n"
        "site:example.com intitle:\"index of\"\n"
        "https://www.google.com/search?q=site%3Aexample.com+intitle%3A%22index+of%22\n"
    ),
}
