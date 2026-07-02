# reconai

AI-assisted recon automation for **authorized** penetration testing / bug bounty work. Give it a
target, it runs a standard set of free, publicly-available Kali recon tools against it (passive
OSINT first, then active scanning if a web service is found), and uses a local Ollama model or the
Claude API to write a narrative summary report.

**Only run this against targets you own or have explicit written permission to test.**

## Tools run

| Stage | Tool | Purpose |
|-------|------|---------|
| Passive | whois | Domain registration |
| Passive | dnsrecon | DNS record enumeration |
| Passive | subfinder | Subdomain discovery |
| Passive | theHarvester | Email/host OSINT |
| Passive | httpx | Probes subfinder's discovered subdomains for live hosts (status, title, tech) |
| Passive | subjack | Checks discovered subdomains for takeover-able dangling CNAMEs |
| Active | nmap | Port scan + service/version detection |
| Active (web port found) | whatweb | Web tech fingerprinting |
| Active | nikto | Web vuln/misconfig scanner |
| Active | gobuster | Directory brute-forcing |
| Active | ffuf | Directory brute-forcing (second engine — different wildcard-detection heuristics catch different things) |
| Active | wafw00f | WAF detection |
| Active | nuclei | Template-based CVE/misconfig scanning |
| Active | getJS | Lists JS files referenced by the page |
| Active | LinkFinder | Extracts API endpoints/paths from page + JS |
| Active (https port found) | testssl | SSL/TLS configuration audit |
| Active | gowitness | Screenshot, embedded into `summary.md` |

Then a local Ollama model or the Claude API writes a narrative summary over all raw output.

## Setup (on Kali)

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Recon tools used (skip any you don't need — missing tools are skipped gracefully)
sudo apt install -y whois dnsutils dnsrecon theharvester nmap whatweb nikto gobuster \
  nuclei wafw00f gowitness testssl.sh ffuf
nuclei -update-templates

# subfinder isn't packaged on all Kali versions:
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# ProjectDiscovery's httpx -- NOT the apt "httpx" package, which is an unrelated
# Python HTTP client that happens to share the binary name. Installs to ~/go/bin,
# which the pipeline calls by absolute path to avoid the collision.
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# GetJS -- also installs to ~/go/bin
go install -v github.com/003random/getJS/v2@latest

# LinkFinder -- no apt/go package, runs from its own clone + venv
git clone https://github.com/GerbenJavado/LinkFinder.git ~/LinkFinder
cd ~/LinkFinder && python3 -m venv venv && venv/bin/pip install setuptools -r requirements.txt
cd -

# subjack -- subdomain takeover checking. Installs to ~/go/bin.
go install -v github.com/haccer/subjack@latest
```

gowitness screenshots reuse the system Chromium (`sudo apt install chromium` if not already present)
rather than downloading its own copy.

### Wordlists (gobuster/ffuf)

Pick a tier at runtime with `--wordlist-size {small,medium,large}` (default `small`), or pass an
exact path with `--wordlist /path/to/list.txt` (overrides the tier). `small` and `medium` ship with
Kali by default; `large` needs SecLists:

```bash
sudo apt install seclists   # only needed for --wordlist-size large
```

### AI backend

Pick one at runtime with `--llm ollama` (default) or `--llm claude`.

**Ollama (local, free, offline)** — recommended default for a Kali VM with limited RAM:

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.2:3b
ollama serve &
```

**Claude (cloud API, stronger summaries, needs internet + key):**

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

## Usage

```bash
python3 recon.py example.com
python3 recon.py example.com --llm claude --pdf
python3 recon.py example.com --dry-run          # check tool availability, no execution
python3 recon.py example.com --mock --llm ollama # exercise the pipeline with canned sample output
python3 recon.py example.com --wordlist-size medium
```

### Live dashboard

```bash
python3 recon.py --serve                # binds 127.0.0.1:8765 by default
```

Opens a web UI (same host as the pipeline) that streams per-tool progress in real time over SSE:
launch a scan from the form, or deep-link one with `?target=X&authorized=1&autostart=1`. From another
machine, reach it over an SSH tunnel rather than exposing the port:

```bash
ssh -L 8765:127.0.0.1:8765 <kali-host>
# then open http://127.0.0.1:8765 locally
```

Results are written to `results/<target>/<timestamp>/`: one `.txt` file per tool, a `screenshots/`
directory (gowitness), `summary.md` (AI narrative + raw findings, with the screenshot embedded),
optional `summary.pdf`, and `manifest.json` (run metadata).

## Development (off Kali)

None of the recon binaries exist outside Linux, so pipeline/report logic is developed and tested
here using `--dry-run` (exercises the "tool not found" path for every wrapper) and `--mock`
(exercises the full pipeline against canned realistic sample output). Run the test suite with:

```bash
pip install -r requirements.txt pytest
pytest tests/
```
