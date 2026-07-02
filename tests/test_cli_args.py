import os

from reconai.cli import build_arg_parser
from reconai.config import Config
from reconai.tools.gobuster_tool import WORDLIST_TIERS


def test_target_positional_parsed():
    args = build_arg_parser().parse_args(["example.com"])
    assert args.target == "example.com"


def test_llm_choices_restricted():
    args = build_arg_parser().parse_args(["example.com", "--llm", "claude"])
    assert args.llm == "claude"


def test_flags_default_false():
    args = build_arg_parser().parse_args(["example.com"])
    assert args.dry_run is False
    assert args.mock is False
    assert args.pdf is False
    assert args.yes is False


def test_flags_parsed():
    args = build_arg_parser().parse_args(
        ["example.com", "--dry-run", "--mock", "--pdf", "--yes", "--nmap-full"]
    )
    assert args.dry_run is True
    assert args.mock is True
    assert args.pdf is True
    assert args.yes is True
    assert args.nmap_full is True


def test_config_from_args_env_fallback(monkeypatch):
    monkeypatch.setenv("RECON_LLM_BACKEND", "claude")
    monkeypatch.setenv("OLLAMA_MODEL", "phi3:mini")
    args = build_arg_parser().parse_args(["example.com"])
    cfg = Config.from_args(args)
    assert cfg.llm_backend == "claude"
    assert cfg.ollama_model == "phi3:mini"


def test_config_from_args_cli_overrides_env(monkeypatch):
    monkeypatch.setenv("RECON_LLM_BACKEND", "claude")
    args = build_arg_parser().parse_args(["example.com", "--llm", "ollama"])
    cfg = Config.from_args(args)
    assert cfg.llm_backend == "ollama"


def test_wordlist_size_defaults_to_small():
    args = build_arg_parser().parse_args(["example.com"])
    cfg = Config.from_args(args)
    assert cfg.gobuster_wordlist == WORDLIST_TIERS["small"]


def test_wordlist_size_selects_tier():
    args = build_arg_parser().parse_args(["example.com", "--wordlist-size", "medium"])
    cfg = Config.from_args(args)
    assert cfg.gobuster_wordlist == WORDLIST_TIERS["medium"]


def test_explicit_wordlist_overrides_wordlist_size():
    args = build_arg_parser().parse_args(
        ["example.com", "--wordlist-size", "large", "--wordlist", "/custom/list.txt"]
    )
    cfg = Config.from_args(args)
    assert cfg.gobuster_wordlist == "/custom/list.txt"
