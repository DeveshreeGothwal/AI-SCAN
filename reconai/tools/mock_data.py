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
}
