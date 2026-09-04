import subprocess
from unittest.mock import MagicMock, patch

import httpx
import pytest

from reconai.tools import (
    base,
    cors_scan_tool,
    ffuf_tool,
    getjs_tool,
    gobuster_tool,
    httpx_tool,
    nikto_tool,
    nmap_tool,
    nuclei_tool,
    sqlmap_tool,
    subfinder_tool,
    subjack_tool,
    wafw00f_tool,
    whatweb_tool,
)


def _which_all_except(missing: set[str]):
    def _which(binary):
        return None if binary in missing else f"/usr/bin/{binary.rsplit('/', 1)[-1]}"
    return _which


# ---- base.run_command proxy wrapping ----

def test_dry_run_shows_proxychains_wrapped_command():
    with patch("reconai.tools.base.shutil.which", side_effect=_which_all_except(set())):
        result = base.run_command("whois", ["whois", "example.com"], dry_run=True, proxy="socks5://127.0.0.1:9050")
    assert "proxychains4" in result.stdout
    assert "whois example.com" in result.stdout


def test_real_execution_wraps_libc_tools_with_proxychains_and_sets_no_env_vars():
    # Regression: env vars + proxychains together broke real tools that also
    # read the env vars themselves (reproduced with curl: "Failed to connect
    # ... Could not connect to server" the moment both were active). whois
    # doesn't read proxy env vars itself, but the fix applies uniformly --
    # proxychains-wrapped calls never also get the env vars, full stop.
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["env"] = kwargs.get("env")
        proc = MagicMock()
        proc.returncode, proc.stdout, proc.stderr = 0, "", ""
        return proc

    with patch("reconai.tools.base.shutil.which", side_effect=_which_all_except(set())), \
         patch("reconai.tools.base.subprocess.run", side_effect=fake_run):
        base.run_command("whois", ["whois", "example.com"], proxy="socks5://127.0.0.1:9050")

    assert captured["cmd"][0] == "proxychains4"
    assert captured["cmd"][-2:] == ["whois", "example.com"]
    assert captured["env"] is None


def test_env_var_proxy_binaries_get_env_vars_and_no_proxychains_wrapping():
    # waybackurls/trufflehog: Go's default net/http transport reads these env
    # vars directly, and proxychains can't intercept their raw syscalls anyway
    # -- wrapping them would be a pointless proxychains4 dependency at best,
    # and per the regression above, actively wrong to combine with env vars.
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["env"] = kwargs.get("env")
        proc = MagicMock()
        proc.returncode, proc.stdout, proc.stderr = 0, "", ""
        return proc

    with patch("reconai.tools.base.shutil.which", side_effect=_which_all_except({"proxychains4"})), \
         patch("reconai.tools.base.subprocess.run", side_effect=fake_run):
        result = base.run_command(base._WAYBACKURLS_BIN, [base._WAYBACKURLS_BIN, "example.com"],
                                   proxy="socks5://127.0.0.1:9050")

    assert result.available is True
    assert captured["cmd"] == [base._WAYBACKURLS_BIN, "example.com"]  # not proxychains-wrapped
    assert captured["env"]["HTTPS_PROXY"] == "socks5://127.0.0.1:9050"
    assert captured["env"]["https_proxy"] == "socks5://127.0.0.1:9050"


def test_skips_when_proxychains_missing():
    with patch("reconai.tools.base.shutil.which", side_effect=_which_all_except({"proxychains4"})):
        result = base.run_command("whois", ["whois", "example.com"], proxy="socks5://127.0.0.1:9050")
    assert result.available is False
    assert "proxychains4" in result.skipped_reason


def test_unsupported_binary_skipped_even_when_proxychains_available():
    with patch("reconai.tools.base.shutil.which", side_effect=_which_all_except(set())):
        result = base.run_command("getjs", [base._GETJS_BIN, "-url", "https://example.com"],
                                   proxy="socks5://127.0.0.1:9050")
    assert result.available is False
    assert "was verified to not honor it" in result.skipped_reason


def test_proxy_flag_added_skips_proxychains_requirement_entirely():
    # subfinder-style: caller already added its own native --proxy flag, so
    # run_command should neither require proxychains4 nor wrap the command.
    with patch("reconai.tools.base.shutil.which", side_effect=_which_all_except({"proxychains4"})), \
         patch("reconai.tools.base.subprocess.run") as mock_run:
        mock_run.return_value.returncode, mock_run.return_value.stdout, mock_run.return_value.stderr = 0, "", ""
        result = base.run_command(
            "subfinder", ["subfinder", "-d", "example.com", "-proxy", "http://127.0.0.1:8080"],
            proxy="http://127.0.0.1:8080", proxy_flag_added=True,
        )
    assert result.available is True
    called_cmd = mock_run.call_args.args[0]
    assert called_cmd[0] == "subfinder"


def test_proxy_dns_false_omits_proxy_dns_directive(tmp_path):
    with patch("reconai.tools.base.tempfile.gettempdir", return_value=str(tmp_path)):
        cmd = base.wrap_with_proxychains(["dig", "example.com"], "socks5://127.0.0.1:9050", proxy_dns=False)
    config_path = cmd[cmd.index("-f") + 1]
    assert "proxy_dns" not in open(config_path).read()


def test_proxy_dns_true_includes_proxy_dns_directive(tmp_path):
    with patch("reconai.tools.base.tempfile.gettempdir", return_value=str(tmp_path)):
        cmd = base.wrap_with_proxychains(["whois", "example.com"], "socks5://127.0.0.1:9050", proxy_dns=True)
    config_path = cmd[cmd.index("-f") + 1]
    assert "proxy_dns" in open(config_path).read()


def test_no_proxy_leaves_command_and_env_untouched():
    with patch("reconai.tools.base.shutil.which", side_effect=_which_all_except(set())), \
         patch("reconai.tools.base.subprocess.run") as mock_run:
        mock_run.return_value.returncode, mock_run.return_value.stdout, mock_run.return_value.stderr = 0, "", ""
        base.run_command("whois", ["whois", "example.com"])
    assert mock_run.call_args.args[0] == ["whois", "example.com"]
    assert mock_run.call_args.kwargs["env"] is None


# ---- httpx_client / ProxyUnavailable (in-process tools) ----

def test_httpx_client_wraps_import_error_as_proxy_unavailable():
    with patch("reconai.tools.base.httpx.Client", side_effect=ImportError("no module named 'socksio'")):
        with pytest.raises(base.ProxyUnavailable):
            base.httpx_client(proxy="socks5://127.0.0.1:9050")


def test_httpx_client_returns_real_client_without_proxy():
    client = base.httpx_client()
    try:
        assert isinstance(client, httpx.Client)
    finally:
        client.close()


def test_cors_scan_tool_skips_cleanly_when_proxy_unavailable():
    with patch("reconai.tools.cors_scan_tool.httpx_client", side_effect=base.ProxyUnavailable("no socksio")):
        result = cors_scan_tool.run("https://example.com", proxy="socks5://127.0.0.1:9050")
    assert result.available is False
    assert "no socksio" in result.skipped_reason


def test_cors_scan_tool_forwards_proxy_to_httpx_client():
    with patch("reconai.tools.cors_scan_tool.httpx_client") as mock_client:
        mock_client.return_value.__enter__.return_value.get.side_effect = httpx.HTTPError("boom")
        cors_scan_tool.run("https://example.com", proxy="http://127.0.0.1:8080")
    assert mock_client.call_args.kwargs["proxy"] == "http://127.0.0.1:8080"


# ---- native --proxy-style flag injection ----

def test_subfinder_appends_native_proxy_flag():
    with patch("reconai.tools.subfinder_tool.run_command") as mock_run:
        mock_run.return_value = MagicMock()
        subfinder_tool.run("example.com", proxy="http://127.0.0.1:8080")
    cmd = mock_run.call_args.args[1]
    assert "-proxy" in cmd and "http://127.0.0.1:8080" in cmd
    assert mock_run.call_args.kwargs["proxy_flag_added"] is True


def test_nuclei_appends_native_proxy_flag():
    with patch("reconai.tools.nuclei_tool.run_command") as mock_run:
        mock_run.return_value = MagicMock()
        nuclei_tool.run("https://example.com", proxy="http://127.0.0.1:8080")
    cmd = mock_run.call_args.args[1]
    assert "-proxy" in cmd and "http://127.0.0.1:8080" in cmd


def test_projectdiscovery_httpx_appends_native_proxy_flag():
    with patch("reconai.tools.httpx_tool.run_command") as mock_run:
        mock_run.return_value = MagicMock()
        httpx_tool.run(["a.example.com"], dry_run=True, proxy="http://127.0.0.1:8080")
    cmd = mock_run.call_args.args[1]
    assert "-http-proxy" in cmd and "http://127.0.0.1:8080" in cmd


def test_gobuster_appends_native_proxy_flag():
    with patch("reconai.tools.gobuster_tool.run_command") as mock_run:
        mock_run.return_value = MagicMock()
        gobuster_tool.run("https://example.com", proxy="http://127.0.0.1:8080")
    cmd = mock_run.call_args.args[1]
    assert "--proxy" in cmd and "http://127.0.0.1:8080" in cmd


def test_ffuf_appends_native_proxy_flag():
    with patch("reconai.tools.ffuf_tool.run_command") as mock_run:
        mock_run.return_value = MagicMock()
        ffuf_tool.run("https://example.com", proxy="http://127.0.0.1:8080")
    cmd = mock_run.call_args.args[1]
    assert "-x" in cmd and "http://127.0.0.1:8080" in cmd


def test_sqlmap_appends_native_proxy_flag():
    with patch("reconai.tools.sqlmap_tool.run_command") as mock_run:
        mock_run.return_value = MagicMock()
        sqlmap_tool.run(["https://example.com/?id=1"], proxy="http://127.0.0.1:8080")
    cmd = mock_run.call_args.args[1]
    assert "--proxy=http://127.0.0.1:8080" in cmd


def test_nikto_appends_native_proxy_flag():
    with patch("reconai.tools.nikto_tool.run_command") as mock_run:
        mock_run.return_value = MagicMock()
        nikto_tool.run("https://example.com", proxy="http://127.0.0.1:8080")
    cmd = mock_run.call_args.args[1]
    assert "-useproxy" in cmd and "http://127.0.0.1:8080" in cmd


def test_nikto_falls_back_to_proxychains_for_socks_proxies():
    # Regression: nikto -useproxy mis-parses socks5:// URLs -- verified for
    # real against a live Tor SOCKS5 port ("can't connect: no port given for
    # proxy server socks5::80"). For socks4/socks5, skip the native flag and
    # let run_command's proxychains4 wrapping handle it instead.
    with patch("reconai.tools.nikto_tool.run_command") as mock_run:
        mock_run.return_value = MagicMock()
        nikto_tool.run("https://example.com", proxy="socks5://127.0.0.1:9050")
    cmd = mock_run.call_args.args[1]
    assert "-useproxy" not in cmd
    assert mock_run.call_args.kwargs["proxy_flag_added"] is False
    assert mock_run.call_args.kwargs["proxy"] == "socks5://127.0.0.1:9050"


def test_wafw00f_appends_native_proxy_flag():
    with patch("reconai.tools.wafw00f_tool.run_command") as mock_run:
        mock_run.return_value = MagicMock()
        wafw00f_tool.run("https://example.com", proxy="http://127.0.0.1:8080")
    cmd = mock_run.call_args.args[1]
    assert "--proxy=http://127.0.0.1:8080" in cmd


def test_whatweb_strips_scheme_for_its_proxy_flag():
    # whatweb's --proxy wants a bare hostname[:port], not a full URL.
    with patch("reconai.tools.whatweb_tool.run_command") as mock_run:
        mock_run.return_value = MagicMock()
        whatweb_tool.run("https://example.com", proxy="http://127.0.0.1:8080")
    cmd = mock_run.call_args.args[1]
    idx = cmd.index("--proxy")
    assert cmd[idx + 1] == "127.0.0.1:8080"


def test_whatweb_falls_back_to_proxychains_for_socks_proxies():
    # Regression: whatweb's --proxy only speaks HTTP CONNECT -- verified for
    # real against a live Tor SOCKS5 port, which replied 501 "Tor is not an
    # HTTP Proxy". For socks4/socks5, skip the native flag and let
    # run_command's proxychains4 wrapping handle it instead.
    with patch("reconai.tools.whatweb_tool.run_command") as mock_run:
        mock_run.return_value = MagicMock()
        whatweb_tool.run("https://example.com", proxy="socks5://127.0.0.1:9050")
    cmd = mock_run.call_args.args[1]
    assert "--proxy" not in cmd
    assert mock_run.call_args.kwargs["proxy_flag_added"] is False
    assert mock_run.call_args.kwargs["proxy"] == "socks5://127.0.0.1:9050"


def test_testssl_disables_proxy_dns():
    # Regression: testssl.sh shells out to dig internally, which fails
    # outright under proxychains' proxy_dns option (same root cause as
    # dns_tool/dns_axfr_tool) -- verified for real ("dig: parse of
    # /etc/resolv.conf failed" -> "Fatal error: No IPv4/IPv6 address(es)").
    from reconai.tools import testssl_tool
    with patch("reconai.tools.testssl_tool.run_command") as mock_run:
        mock_run.return_value = MagicMock()
        testssl_tool.run("example.com", proxy="socks5://127.0.0.1:9050")
    assert mock_run.call_args.kwargs["proxy_dns"] is False


def test_nmap_forces_tcp_connect_scan_when_proxied():
    # a SYN scan crafts raw packets below the socket layer -- no proxy
    # mechanism can intercept it, so proxying must force -sT.
    with patch("reconai.tools.nmap_tool.run_command") as mock_run:
        mock_run.return_value = MagicMock()
        nmap_tool.run("example.com", proxy="socks5://127.0.0.1:9050")
    cmd = mock_run.call_args.args[1]
    assert "-sT" in cmd


def test_nmap_does_not_force_scan_type_without_proxy():
    with patch("reconai.tools.nmap_tool.run_command") as mock_run:
        mock_run.return_value = MagicMock()
        nmap_tool.run("example.com")
    cmd = mock_run.call_args.args[1]
    assert "-sT" not in cmd


# ---- getJS / subjack: verified unproxyable, must not silently leak ----

def test_getjs_run_forwards_proxy_and_lets_run_command_skip_it():
    with patch("reconai.tools.getjs_tool.run_command") as mock_run:
        mock_run.return_value = MagicMock()
        getjs_tool.run("https://example.com", proxy="socks5://127.0.0.1:9050")
    assert mock_run.call_args.kwargs["proxy"] == "socks5://127.0.0.1:9050"
    # no native flag added -- getJS has none, relies entirely on run_command's
    # PROXY_UNSUPPORTED_BINARIES skip.
    assert "proxy_flag_added" not in mock_run.call_args.kwargs or not mock_run.call_args.kwargs["proxy_flag_added"]


def test_getjs_actually_skipped_end_to_end_when_proxied():
    with patch("reconai.tools.base.shutil.which", side_effect=_which_all_except(set())):
        result = getjs_tool.run("https://example.com", proxy="socks5://127.0.0.1:9050")
    assert result.available is False
    assert "was verified to not honor it" in result.skipped_reason


def test_subjack_actually_skipped_end_to_end_when_proxied():
    with patch("reconai.tools.base.shutil.which", side_effect=_which_all_except(set())):
        result = subjack_tool.run(["a.example.com"], proxy="socks5://127.0.0.1:9050")
    assert result.available is False
    assert "was verified to not honor it" in result.skipped_reason
