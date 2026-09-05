from __future__ import annotations

import argparse
import sys

from . import banner
from .config import Config
from .pipeline import run_pipeline
from .tools.gobuster_tool import WORDLIST_TIERS


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="recon",
        description="AI-assisted recon pipeline for authorized penetration testing / bug bounty work.",
    )
    parser.add_argument("target", nargs="?", help="Domain or IP to scan. Prompted for if omitted.")
    parser.add_argument("--llm", choices=["ollama", "claude", "groq"], default=None,
                         help="AI backend to use for summarization (default: ollama, or $RECON_LLM_BACKEND).")
    parser.add_argument("--ollama-model", default=None, help="Ollama model name (default: llama3.2:3b, or $OLLAMA_MODEL).")
    parser.add_argument("--ollama-host", default=None, help="Ollama host URL (default: http://localhost:11434, or $OLLAMA_HOST).")
    parser.add_argument("--claude-model", default=None, help="Claude model name (default: claude-opus-4-8, or $ANTHROPIC_MODEL).")
    parser.add_argument("--groq-model", default=None, help="Groq model name (default: llama-3.3-70b-versatile, or $GROQ_MODEL).")
    parser.add_argument("--pdf", action="store_true", help="Also render the summary report as a PDF.")
    parser.add_argument("--dry-run", action="store_true", help="Check tool availability and simulate the run without executing anything.")
    parser.add_argument("--mock", action="store_true", help="Use canned sample tool output instead of real binaries (for dev/testing off Kali).")
    parser.add_argument("--nmap-full", action="store_true", help="Scan all 65535 ports instead of the top 1000 (slower).")
    parser.add_argument("--wordlist", default=None,
                         help="Explicit wordlist path for gobuster/ffuf (overrides --wordlist-size).")
    parser.add_argument("--wordlist-size", choices=list(WORDLIST_TIERS), default="small",
                         help="Wordlist tier for gobuster/ffuf: small=dirb common (~4.6k words, fast), "
                              "medium=dirbuster (~220k words, thorough), large=SecLists raft-large "
                              "(needs 'sudo apt install seclists'). Default: small.")
    parser.add_argument("--yes", action="store_true", help="Skip the interactive authorization confirmation prompt.")
    parser.add_argument("--proxy", default=None,
                         help="Route scan traffic through this proxy (e.g. socks5://127.0.0.1:9050 or "
                              "http://127.0.0.1:8080). Off by default -- direct connections. See README "
                              "for per-tool coverage (a couple of Go-based tools can't be proxied and are "
                              "skipped instead of run unprotected).")
    parser.add_argument("--tor", action="store_true",
                         help="Shorthand for --proxy socks5://127.0.0.1:9050 (a local Tor daemon). "
                              "Free, no signup -- `sudo apt install tor && sudo systemctl start tor`.")
    parser.add_argument("--validate-secrets", action="store_true",
                         help="For Stripe/Slack secrets found by secret_scan, make one read-only "
                              "confirmatory call to the credential's own provider to check if it's "
                              "still live (mirrors github_secrets' use of trufflehog --only-verified). "
                              "Off by default -- does not post to Slack or touch Stripe account data.")
    parser.add_argument("--serve", action="store_true",
                         help="Start the live web dashboard instead of running a single scan.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host for --serve (default: 127.0.0.1, localhost-only).")
    parser.add_argument("--port", type=int, default=8765, help="Bind port for --serve (default: 8765).")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.serve:
        from .server.app import run_server
        print(f"[+] Live dashboard at http://{args.host}:{args.port}  (Ctrl+C to stop)")
        run_server(host=args.host, port=args.port)
        return 0

    if not args.target:
        args.target = input("Target (domain or IP): ").strip()
    if not args.target:
        print("No target provided.", file=sys.stderr)
        return 1

    if not banner.show_and_confirm(args.yes):
        print("Aborted.")
        return 1

    cfg = Config.from_args(args)

    if cfg.llm_backend == "ollama" and not cfg.dry_run and not cfg.mock:
        from .llm.ollama_backend import OllamaBackend
        try:
            OllamaBackend(model=cfg.ollama_model, host=cfg.ollama_host).preflight()
        except RuntimeError as exc:
            print(f"[!] {exc}", file=sys.stderr)
            return 1

    try:
        ctx = run_pipeline(cfg)
    except RuntimeError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

    print(f"\n[+] Done. Results saved to: {ctx.run_dir}")
    print(f"[+] Summary: {ctx.summary_path}")
    if ctx.pdf_path:
        print(f"[+] PDF report: {ctx.pdf_path}")
    elif ctx.pdf_error:
        print(f"[!] PDF export failed (scan itself completed fine): {ctx.pdf_error}", file=sys.stderr)
    return 0
