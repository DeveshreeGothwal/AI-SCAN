import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from reconai.tools import injection_probe_tool


class _VulnHandler(BaseHTTPRequestHandler):
    """Serves deliberately vulnerable-looking responses so injection_probe_tool's
    real HTTP round trip (not a mocked one) can be exercised end-to-end."""

    def do_GET(self):
        query = parse_qs(urlparse(self.path).query)
        redirect_value = query.get("redirect", [""])[0]
        if redirect_value == injection_probe_tool._REDIRECT_MARKER:
            self.send_response(302)
            self.send_header("Location", redirect_value)
            self.end_headers()
            return

        if "hashy" in query:
            # Regression fixture: a page that always contains "49" as a
            # substring inside an unrelated hex run (e.g. a SHA-256 IOC hash
            # on a security-advisory page), regardless of what was sent --
            # this must never be mistaken for an evaluated {{7*7}} payload.
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"IOC SHA256: 8b6f3ec59d03492e9bcafe")
            return

        if "clock" in query:
            # Regression fixture: a page with a live, ever-changing
            # server-rendered clock -- verified for real against a live
            # target that this produces a coincidental, payload-independent
            # \b49\b match whenever the minute/second happens to show ":49",
            # regardless of what was actually injected.
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Server time: 11:49:00")
            return

        value = query.get("x", [""])[0]
        if value.endswith("'"):
            body = "You have an error in your SQL syntax; MySQL server version for the right syntax"
        elif value.endswith("; id"):
            body = "output: uid=1000(kali) gid=1000(kali) groups=1000(kali)"
        elif value == "{{7*7}}":
            body = "Result: 49"
        elif value == "../../../../../../etc/passwd":
            body = "root:x:0:0:root:/root:/bin/bash"
        elif injection_probe_tool._XSS_MARKER in value:
            # Deliberately vulnerable: echoes the raw query value back unescaped,
            # like an app that renders "You searched for: <user input>" with no
            # HTML-encoding.
            body = f"<html><body>You searched for: {value}</body></html>"
        else:
            body = "OK"

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, format, *args):
        pass  # silence request logging during tests


@pytest.fixture
def vuln_server():
    server = HTTPServer(("127.0.0.1", 0), _VulnHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join()


def test_detects_all_signature_based_vulnerabilities(vuln_server):
    param_urls = [f"{vuln_server}/?x=1", f"{vuln_server}/?redirect=start"]
    result = injection_probe_tool.run(param_urls, dry_run=False, mock=False)

    assert result.available is True
    assert "[SQL Injection]" in result.stdout
    assert "[Command Injection]" in result.stdout
    assert "[Template Injection (Jinja2)]" in result.stdout
    assert "[Path Traversal]" in result.stdout
    assert "[Open Redirect]" in result.stdout
    assert "[Reflected XSS]" in result.stdout


def test_xss_check_ignores_a_well_behaved_app_that_escapes_output(vuln_server):
    # The "safe=1" param never matches the XSS marker branch in the test
    # server, so it always echoes back "OK" -- equivalent to an app that
    # HTML-escapes user input before rendering it.
    result = injection_probe_tool.run([f"{vuln_server}/?safe=1"], dry_run=False, mock=False)
    assert "[Reflected XSS]" not in result.stdout


def test_clean_target_reports_no_findings(vuln_server):
    # a URL whose only param name doesn't look redirect-ish and whose value
    # never matches a vulnerable signature -- server always replies "OK".
    result = injection_probe_tool.run([f"{vuln_server}/?safe=1"], dry_run=False, mock=False)
    assert "No injection signatures detected" in result.stdout


def test_ssti_check_ignores_49_inside_an_unrelated_hex_string(vuln_server):
    # Regression: a bare "49" in r.text check flagged this as "Template
    # Injection (Jinja2)" against a real target -- the page always contains
    # "49" as a substring of a SHA-256 hash, completely independent of the
    # injected payload. Word-boundary matching must not fire here.
    result = injection_probe_tool.run([f"{vuln_server}/?hashy=1"], dry_run=False, mock=False)
    assert "Template Injection" not in result.stdout


def test_ssti_check_ignores_a_live_clock_that_always_shows_49(vuln_server):
    # Regression: verified for real against a live target rendering a
    # server-side clock -- a bare \b49\b check flagged "Template Injection"
    # on nearly every parameter purely because the live HH:MM:SS happened to
    # show ":49", independent of the injected payload entirely. The baseline
    # request (a harmless control value) must also show "49" here, so the
    # comparison correctly suppresses the finding.
    result = injection_probe_tool.run([f"{vuln_server}/?clock=1&x=1"], dry_run=False, mock=False)
    assert "Template Injection" not in result.stdout


def test_flags_ssrf_prone_param_for_manual_review_without_extra_request(vuln_server):
    # 'callback' matches the SSRF-prone shape but not the open-redirect regex,
    # so this exercises the static flag independent of the redirect check.
    result = injection_probe_tool.run([f"{vuln_server}/?callback=https://internal.example"], dry_run=False, mock=False)
    assert "[Informational]" in result.stdout
    assert "param 'callback'" in result.stdout


def test_dry_run_does_not_make_requests():
    result = injection_probe_tool.run(["http://127.0.0.1:1/?x=1"], dry_run=True)
    assert "[DRY-RUN]" in result.stdout


def test_mock_returns_canned_output():
    result = injection_probe_tool.run(["http://127.0.0.1:1/?x=1"], mock=True)
    assert result.mocked is True
    assert "[SQL Injection]" in result.stdout
