# Kali (not Debian/Ubuntu) as the base image specifically so the apt install
# below can be a near-verbatim copy of README.md's "Setup (on Kali)" section --
# every one of these tools is a curated Kali package, several of them (theHarvester,
# nuclei, SecLists-adjacent tooling) aren't packaged for Ubuntu/Debian at all
# (verified against packages.ubuntu.com while researching Ubuntu compatibility
# for this same project). Using the same base this project has been built and
# run against all along is the single biggest risk-reducer available here.
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
ENV HOME=/root
ENV PATH="/root/go/bin:${PATH}"

# --- Recon tools (mirrors README.md's Kali setup block) ---
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-venv python3-pip \
    whois dnsutils dnsrecon theharvester nmap whatweb nikto gobuster \
    nuclei wafw00f testssl.sh ffuf sqlmap \
    proxychains4 tor git curl golang-go ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN nuclei -update-templates

# Go-installed tools -- land in $GOPATH/bin (defaults to ~/go/bin, already on
# PATH above), matching GO_BIN in reconai/tools/base.py exactly.
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install -v github.com/003random/getJS/v2@latest \
    && go install -v github.com/haccer/subjack@latest \
    && go install -v github.com/tomnomnom/waybackurls@latest

# LinkFinder -- no apt/go package, runs from its own clone + venv (matches
# LINKFINDER_DIR/LINKFINDER_PYTHON in reconai/tools/base.py).
RUN git clone https://github.com/GerbenJavado/LinkFinder.git /root/LinkFinder \
    && cd /root/LinkFinder && python3 -m venv venv \
    && venv/bin/pip install --no-cache-dir setuptools -r requirements.txt

# trufflehog -- go install doesn't work here (go.mod replace directive), use
# their install script instead. Installs to ~/go/bin.
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
    | sh -s -- -b /root/go/bin

# --- App ---
WORKDIR /app
COPY requirements.txt .
RUN python3 -m venv venv && venv/bin/pip install --no-cache-dir -r requirements.txt
COPY . .

EXPOSE 8765

# Shell form so $PORT (the port Render assigns the container) is respected;
# falls back to 8765 for any other Docker host. --host 0.0.0.0 is required --
# recon.py's own --host default (127.0.0.1) would be unreachable from outside
# the container.
CMD ["/bin/sh", "-c", "venv/bin/python3 recon.py --serve --host 0.0.0.0 --port ${PORT:-8765}"]
