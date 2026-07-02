from unittest.mock import patch

from reconai.tools import (
    ffuf_tool,
    getjs_tool,
    gowitness_tool,
    httpx_tool,
    linkfinder_tool,
    nuclei_tool,
    subfinder_tool,
    subjack_tool,
    testssl_tool,
    wafw00f_tool,
)
from reconai.tools.base import GO_BIN, LINKFINDER_PYTHON


def test_parse_subdomains_splits_and_strips_blank_lines():
    stdout = "www.example.com\napi.example.com\n\n  \nstaging.example.com\n"
    assert subfinder_tool.parse_subdomains(stdout) == [
        "www.example.com", "api.example.com", "staging.example.com",
    ]


def test_parse_subdomains_empty_output():
    assert subfinder_tool.parse_subdomains("") == []


def test_httpx_dry_run_uses_real_binary_path_not_apt_httpx():
    with patch("reconai.tools.base.shutil.which", return_value=str(GO_BIN / "httpx")):
        result = httpx_tool.run(["a.example.com", "b.example.com"], dry_run=True)
    assert result.command[0] == str(GO_BIN / "httpx")
    assert "-l" in result.command


def test_httpx_writes_subdomains_to_temp_file_for_real_run(tmp_path):
    fake_bin = tmp_path / "httpx"
    fake_bin.write_text("#!/bin/sh\ncat \"$2\"\n")
    fake_bin.chmod(0o755)
    with patch("reconai.tools.base.shutil.which", return_value=str(fake_bin)), \
         patch("reconai.tools.httpx_tool._HTTPX_BIN", str(fake_bin)):
        result = httpx_tool.run(["a.example.com", "b.example.com"], dry_run=False)
    assert "a.example.com" in result.stdout
    assert "b.example.com" in result.stdout


def test_nuclei_dry_run_command():
    with patch("reconai.tools.base.shutil.which", return_value="/usr/bin/nuclei"):
        result = nuclei_tool.run("https://example.com", dry_run=True)
    assert result.command == ["nuclei", "-u", "https://example.com", "-silent", "-severity", "low,medium,high,critical"]


def test_ffuf_dry_run_command_includes_fuzz_keyword():
    with patch("reconai.tools.base.shutil.which", return_value="/usr/bin/ffuf"):
        result = ffuf_tool.run("https://example.com", dry_run=True)
    assert "https://example.com/FUZZ" in result.command


def test_wafw00f_dry_run_command():
    with patch("reconai.tools.base.shutil.which", return_value="/usr/bin/wafw00f"):
        result = wafw00f_tool.run("https://example.com", dry_run=True)
    assert result.command == ["wafw00f", "https://example.com"]


def test_testssl_targets_host_and_port():
    with patch("reconai.tools.base.shutil.which", return_value="/usr/bin/testssl"):
        result = testssl_tool.run("example.com", port=8443, dry_run=True)
    assert "example.com:8443" in result.command


def test_getjs_uses_go_bin_path():
    with patch("reconai.tools.base.shutil.which", return_value=str(GO_BIN / "getJS")):
        result = getjs_tool.run("https://example.com", dry_run=True)
    assert result.command[0] == str(GO_BIN / "getJS")


def test_linkfinder_uses_venv_python_and_script():
    with patch("reconai.tools.base.shutil.which", return_value=LINKFINDER_PYTHON):
        result = linkfinder_tool.run("https://example.com", dry_run=True)
    assert result.command[0] == LINKFINDER_PYTHON
    assert result.command[1].endswith("linkfinder.py")


def test_gowitness_unavailable_when_binary_missing(tmp_path):
    with patch("reconai.tools.base.shutil.which", return_value=None):
        result = gowitness_tool.run("https://example.com", tmp_path / "screenshots", dry_run=False)
    assert result.available is False


def test_gowitness_mock_does_not_touch_filesystem(tmp_path):
    screenshot_dir = tmp_path / "screenshots"
    with patch("reconai.tools.base.shutil.which", return_value="/usr/bin/gowitness"):
        result = gowitness_tool.run("https://example.com", screenshot_dir, mock=True)
    assert result.mocked is True
    assert not screenshot_dir.exists()


def test_subjack_dry_run_uses_go_bin_path_and_wordlist_flag():
    with patch("reconai.tools.base.shutil.which", return_value=str(GO_BIN / "subjack")):
        result = subjack_tool.run(["a.example.com", "b.example.com"], dry_run=True)
    assert result.command[0] == str(GO_BIN / "subjack")
    assert "-w" in result.command
    assert "-ssl" in result.command


def test_subjack_writes_subdomains_to_temp_file_for_real_run(tmp_path):
    fake_bin = tmp_path / "subjack"
    fake_bin.write_text("#!/bin/sh\ncat \"$2\"\n")
    fake_bin.chmod(0o755)
    with patch("reconai.tools.base.shutil.which", return_value=str(fake_bin)), \
         patch("reconai.tools.subjack_tool._SUBJACK_BIN", str(fake_bin)):
        result = subjack_tool.run(["a.example.com", "b.example.com"], dry_run=False)
    assert "a.example.com" in result.stdout
    assert "b.example.com" in result.stdout


def test_subjack_strips_ansi_color_codes_from_output(tmp_path):
    # subjack prints ANSI color codes unconditionally (no isatty check), so raw
    # escape sequences would otherwise show up as garbled text in the report/dashboard.
    fake_bin = tmp_path / "subjack"
    fake_bin.write_text('#!/bin/sh\nprintf "[\\033[31;1mNot Vulnerable\\033[0m] www.example.com\\n"\n')
    fake_bin.chmod(0o755)
    with patch("reconai.tools.base.shutil.which", return_value=str(fake_bin)), \
         patch("reconai.tools.subjack_tool._SUBJACK_BIN", str(fake_bin)):
        result = subjack_tool.run(["www.example.com"], dry_run=False)
    assert result.stdout == "[Not Vulnerable] www.example.com\n"
    assert "\x1b" not in result.stdout
