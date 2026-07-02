import subprocess
from unittest.mock import patch

from reconai.tools import base


def test_run_command_reports_unavailable_with_apt_hint():
    with patch("reconai.tools.base.shutil.which", return_value=None):
        result = base.run_command("nmap", ["nmap", "-sV", "example.com"])
    assert result.available is False
    assert "sudo apt install nmap" in result.skipped_reason


def test_run_command_dry_run_does_not_call_subprocess():
    with patch("reconai.tools.base.shutil.which", return_value="/usr/bin/nmap"), \
         patch("reconai.tools.base.subprocess.run") as mock_run:
        result = base.run_command("nmap", ["nmap", "-sV", "example.com"], dry_run=True)
    mock_run.assert_not_called()
    assert result.available is True
    assert "[DRY-RUN]" in result.stdout


def test_run_command_mock_output_does_not_call_subprocess():
    with patch("reconai.tools.base.shutil.which", return_value="/usr/bin/nmap"), \
         patch("reconai.tools.base.subprocess.run") as mock_run:
        result = base.run_command("nmap", ["nmap", "-sV", "example.com"], mock_output="fake nmap output")
    mock_run.assert_not_called()
    assert result.available is True
    assert result.mocked is True
    assert result.stdout == "fake nmap output"


def test_run_command_real_execution_when_available(tmp_path):
    with patch("reconai.tools.base.shutil.which", return_value="/bin/echo"):
        result = base.run_command("echo", ["echo", "hello"])
    assert result.available is True
    assert result.returncode == 0
    assert "hello" in result.stdout


def test_run_command_passes_devnull_stdin():
    # Regression: run_command executes inside a background worker thread of a
    # long-lived server process, where stdin isn't a real TTY. Some tools (e.g.
    # subjack) check os.Stdin.Stat() to decide "read targets from stdin instead
    # of my -w/-d flag", and an inherited non-TTY stdin with nothing written to
    # it makes them silently process zero input instead of erroring. Explicit
    # stdin=DEVNULL is the only way every tool interprets "no stdin" the same.
    with patch("reconai.tools.base.shutil.which", return_value="/bin/echo"), \
         patch("reconai.tools.base.subprocess.run") as mock_run:
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = ""
        base.run_command("echo", ["echo", "hello"])
    assert mock_run.call_args.kwargs["stdin"] == subprocess.DEVNULL


def test_apt_hint_unknown_binary_falls_back_to_name():
    assert base.apt_hint("some-unlisted-tool") == "some-unlisted-tool"


def test_run_command_timeout_decodes_bytes_stdout():
    # CPython quirk: subprocess.run(text=True) still raises TimeoutExpired with
    # raw bytes on .stdout/.stderr, since the timeout path never reaches the
    # text-decoding step. A run that times out must not leave ToolResult.stdout
    # as bytes, or every downstream "\n".join() over the report/results text
    # blows up the instant any tool legitimately times out.
    timeout_exc = subprocess.TimeoutExpired(cmd=["testssl"], timeout=300, output=b"partial raw \xc3\xa9 output")
    with patch("reconai.tools.base.shutil.which", return_value="/usr/bin/testssl"), \
         patch("reconai.tools.base.subprocess.run", side_effect=timeout_exc):
        result = base.run_command("testssl", ["testssl", "example.com:443"], timeout=300)

    assert result.available is True
    assert result.returncode is None
    assert isinstance(result.stdout, str)
    assert "partial raw" in result.stdout
    assert "Timed out after 300s" in result.stderr

    # the actual crash we hit in production: writing this result out must not
    # raise "sequence item N: expected str instance, bytes found"
    from reconai import results
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as tmp:
        results.write_tool_output(Path(tmp), "testssl", result)  # must not raise
