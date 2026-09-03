from __future__ import annotations

from .base import ToolResult, run_command
from .mock_data import MOCK_OUTPUTS

NAME = "theharvester"


# "duckduckgo" and "threatcrowd" were dropped -- verified for real against a
# live target that neither can ever contribute anything: theHarvester's
# duckduckgo module only calls DuckDuckGo's "Instant Answer" API (a
# structured-fact widget endpoint, not general web search -- it isn't wired
# to return organic site listings for an obscure domain), and threatcrowd's
# API is defunct (every request logs "No response from ThreatCrowd API").
# "otx" was kept even though AlienVault now requires a free API key for its
# passive-DNS endpoint ("Anonymous access to this endpoint is limited")
# -- it fails gracefully (empty result, no exception) when unauthenticated,
# and upgrades for free the moment a key is added to
# /etc/theHarvester/api-keys.yaml. Every other source here is confirmed
# keyless and confirmed to return real data for a live target.
_SOURCES = "crtsh,rapiddns,subdomaincenter,urlscan,hackertarget,certspotter,waybackarchive,otx"


def run(target: str, dry_run: bool = False, mock: bool = False, proxy: str | None = None) -> ToolResult:
    cmd = ["theHarvester", "-d", target, "-b", _SOURCES, "-l", "200"]
    mock_output = MOCK_OUTPUTS[NAME] if mock else None
    # 8 sources over Tor measured at ~110s for a real target -- 120s left too
    # little headroom given Tor's variable latency, so this needs more room
    # than the previous 3-source list did.
    return run_command(NAME, cmd, timeout=180, dry_run=dry_run, mock_output=mock_output, proxy=proxy)
