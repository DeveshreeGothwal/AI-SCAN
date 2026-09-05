from __future__ import annotations

import os
from dataclasses import dataclass

from .tools.gobuster_tool import WORDLIST_TIERS


@dataclass
class Config:
    target: str
    llm_backend: str = "ollama"
    ollama_model: str | None = None
    ollama_host: str | None = None
    claude_model: str | None = None
    groq_model: str | None = None
    render_pdf: bool = False
    dry_run: bool = False
    mock: bool = False
    nmap_full: bool = False
    gobuster_wordlist: str = WORDLIST_TIERS["small"]
    assume_yes: bool = False
    proxy: str | None = None
    validate_secrets: bool = False

    @classmethod
    def from_args(cls, args) -> "Config":
        # an explicit --wordlist path always wins over the --wordlist-size tier.
        wordlist = args.wordlist or WORDLIST_TIERS[args.wordlist_size]
        proxy = "socks5://127.0.0.1:9050" if args.tor else args.proxy
        return cls(
            target=args.target,
            llm_backend=args.llm or os.environ.get("RECON_LLM_BACKEND", "ollama"),
            ollama_model=args.ollama_model or os.environ.get("OLLAMA_MODEL"),
            ollama_host=args.ollama_host or os.environ.get("OLLAMA_HOST"),
            claude_model=args.claude_model or os.environ.get("ANTHROPIC_MODEL"),
            groq_model=args.groq_model or os.environ.get("GROQ_MODEL"),
            render_pdf=args.pdf,
            dry_run=args.dry_run,
            mock=args.mock,
            nmap_full=args.nmap_full,
            gobuster_wordlist=wordlist,
            assume_yes=args.yes,
            proxy=proxy,
            validate_secrets=args.validate_secrets,
        )
