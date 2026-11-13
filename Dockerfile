# Submission image for the AISafe agentic CTF.
#
# The organizers run ONE container per challenge on their infra (challenge
# auto-started, their model endpoint injected, no internet at run time). So every
# tool the agent may use must be baked in here — this image IS the submission.
#
# Build it on a machine with Docker + internet (it cannot build in the no-internet
# run sandbox):   docker build -t ctf-harness:latest .
# Pinned versions below are chosen to be reproducible; bump them deliberately.
#
# Base: Debian stable. Swap to kali-rolling if you want Kali's metapackages, but
# Debian + explicit installs keeps the image reproducible and smaller.
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1 \
    LANG=C.UTF-8

# --- system analysis tooling ------------------------------------------------
# Static/rev/forensics/misc: debuggers, binutils, carving, stego, pcap, crypto.
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-pip python3-venv python3-dev \
      build-essential gdb gdbserver \
      binutils file xxd bsdextrautils \
      binwalk foremost steghide libimage-exiftool-perl \
      tshark tcpdump \
      radare2 \
      openssl \
      git curl wget unzip ca-certificates \
      ltrace strace netcat-openbsd \
      openjdk-17-jre-headless \
 && rm -rf /var/lib/apt/lists/*

# --- python tooling (in a venv; Debian is PEP 668 externally-managed) -------
# Put the venv first on PATH so the agent's `python3`/`shell` sees these libs.
ENV PATH="/opt/venv/bin:${PATH}"
RUN python3 -m venv /opt/venv \
 && pip install --upgrade pip \
 && pip install \
      "pwntools==4.13.1" \
      "z3-solver==4.13.0.0" \
      "angr==9.2.112" \
      "capstone==5.0.1" \
      "unicorn==2.0.1.post1" \
      "ROPGadget==7.5" \
      "pycryptodome==3.20.0" \
      "requests==2.32.3" \
      "scapy==2.5.0" \
      "volatility3==2.7.0" \
      "pwndbg==2024.08.29"

# Trusted pwndbg init, loaded explicitly by the gdb wrapper via CTF_GDB_INIT
# (the wrapper runs gdb with --nx so a planted ./.gdbinit is ignored).
RUN printf 'source /opt/venv/lib/python3.11/site-packages/pwndbg/gdbinit.py\n' > /opt/gdbinit-pwndbg \
 || true
ENV CTF_GDB_INIT=/opt/gdbinit-pwndbg

# --- Ghidra headless --------------------------------------------------------
# analyzeHeadless drives the ghidra_decompile tool. Pin a release.
ARG GHIDRA_VERSION=11.1.2
ARG GHIDRA_DATE=20240709
RUN cd /opt \
 && wget -q "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip" -O ghidra.zip \
 && unzip -q ghidra.zip && rm ghidra.zip \
 && ln -s /opt/ghidra_${GHIDRA_VERSION}_PUBLIC/support/analyzeHeadless /usr/local/bin/analyzeHeadless

# --- the harness ------------------------------------------------------------
WORKDIR /opt/ctf-harness
COPY . /opt/ctf-harness
RUN pip install -e .

# The agent runs non-interactively, one challenge per container. The exact
# command is finalized against the starter kit's interface; today it runs the
# harness, configured entirely from environment variables (model endpoint,
# budgets, platform) so nothing secret is baked into the image.
#
# Smoke-test the image before relying on it:
#   docker run --rm ctf-harness:latest python -m pytest -q
ENTRYPOINT ["/opt/ctf-harness/docker-entrypoint.sh"]
CMD []
