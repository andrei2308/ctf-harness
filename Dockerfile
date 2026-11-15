# Submission image for the AISafe agentic CTF — comprehensive CTF toolkit.
#
# The organizers run ONE container per challenge on their infra (challenge
# auto-started, their model endpoint injected, NO INTERNET at run time). Every
# tool the agent may use must be baked in here — this image IS the submission.
#
# Base: kali-rolling (matches Andrei's Kali workflow and the wordlist paths in
# ctf-notes). Tools are installed per-package in a loop so one package name this
# Kali snapshot happens not to have only skips that package instead of failing
# the whole build (names are best-effort; a skipped one prints WARN in the log).
#
# Build on a machine with Docker + internet (cannot build in the run sandbox):
#   docker build -t ctf-harness:latest .                                  # full
#   docker build --build-arg WITH_SAGE=0 --build-arg WITH_WORDLISTS=0 \
#     -t ctf-harness:slim .                                               # trimmed
#   docker run --rm ctf-harness:latest python -m pytest -q               # smoke
#   docker run --rm ctf-harness:latest ctf-tools                         # list what's present
#
# Run-time constraints no install changes: NO GPU (hashcat is CPU-only/slow —
# John is the CPU workhorse) and NO INTERNET (factordb / online RSA lookups are
# dead — factor locally with sage / yafu). The image is large; SageMath and
# SecLists are the bulk and sit behind the WITH_* args.
# Pinned by digest: with a bare tag, any `docker pull` of kali-rolling on the
# build machine changes the base and throws away every cached layer, turning a
# seconds-long contest-day rebuild into a full one that needs the network. Bump
# the digest deliberately, never on contest day.
FROM kalilinux/kali-rolling@sha256:1ff4a2be3849333687b3ed2b31bb5af0cd1b7c0a11ec7713feb5abe5a6b2795c

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1 \
    LANG=C.UTF-8

# --- core build deps (must succeed) ----------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-pip python3-venv python3-dev build-essential \
      git curl wget unzip ca-certificates ruby ruby-dev default-jdk-headless \
 && rm -rf /var/lib/apt/lists/*

# --- full apt toolkit (best-effort per package) ----------------------------
RUN apt-get update; \
    for p in \
      `# rev / pwn` \
      gdb gdbserver gdb-multiarch radare2 ghidra binutils file xxd bsdextrautils \
      patchelf ltrace strace checksec upx-ucl nasm yara qemu-user qemu-user-static \
      libc6-dbg elfutils \
      `# crypto` \
      sagemath pari-gp yafu \
      `# forensics` \
      volatility3 sleuthkit bulk-extractor testdisk scalpel foremost binwalk \
      exiftool tshark tcpdump poppler-utils qpdf imagemagick ffmpeg \
      p7zip-full unrar-free cabextract \
      `# stego` \
      steghide stegseek outguess stegsnow zbar-tools sox multimon-ng \
      `# cracking (CPU-only: no GPU in the run sandbox)` \
      john hashcat hashid hydra fcrackzip pdfcrack hcxtools \
      `# web` \
      sqlmap gobuster ffuf feroxbuster nikto whatweb wfuzz commix nmap wafw00f \
      `# mobile / apk` \
      apktool jadx dex2jar apksigner \
      `# networking` \
      aircrack-ng socat ngrep tcpflow dnsutils hping3 netcat-traditional \
      `# ocr` \
      tesseract-ocr tesseract-ocr-eng \
      `# blockchain (solc; foundry/web3/slither added below)` \
      solidity \
      `# misc / archives / encodings` \
      jq zip xz-utils zstd lz4 bzip2 \
      ; do \
        apt-get install -y --no-install-recommends "$p" || echo "WARN: apt skip $p"; \
      done; \
    rm -rf /var/lib/apt/lists/*; \
    (ln -sf /usr/share/ghidra/support/analyzeHeadless /usr/local/bin/analyzeHeadless || true)

# --- ruby gems (not apt-packaged) ------------------------------------------
RUN for g in zsteg one_gadget seccomp-tools; do \
      gem install --no-document "$g" || echo "WARN: gem skip $g"; \
    done

# --- python toolkit (venv; Kali pip is PEP 668 externally-managed) ----------
# venv first on PATH so the agent's python3/shell see these libs; Kali apt tools
# use absolute /usr/bin/python3 shebangs, so they are unaffected.
ENV PATH="/opt/venv/bin:${PATH}"
RUN python3 -m venv /opt/venv && pip install --upgrade pip && \
    pip install \
      pwntools ROPgadget angr z3-solver capstone unicorn \
      pycryptodome pycryptodomex sympy numpy gmpy2 requests scapy
# ropper: its dependency filebytes 0.10.2 (latest release) uses ast.Str, removed
# in Python 3.14 (Kali's python3). Upstream fixed it but has not released, so
# take filebytes from the pinned fix commit. Best-effort: ROPgadget is the
# critical ROP tool.
RUN (pip install "filebytes @ git+https://github.com/sashs/filebytes@ff7492d750140288e2c3ff25b8a648719be470ce" \
      && pip install ropper) || echo "WARN: pip skip ropper"
# extended python tooling, best-effort per package
RUN for p in \
      fpylll cysignals roca-detect xortool primefac libnum \
      flask-unsign factordb-pycli paddingoracle frida-tools objection \
      oletools uncompyle6 decompyle3 yara-python flare-floss capa \
      `# forensics: Kali has no volatility3 package any more` volatility3 \
      wfuzz dirsearch arpy \
      `# ocr` pytesseract \
      `# blockchain` web3 eth-abi eth-account eth-utils slither-analyzer solc-select vyper ; do \
        pip install "$p" || echo "WARN: pip skip $p"; \
      done \
 && (solc-select install 0.8.26 && solc-select use 0.8.26 || echo "WARN: solc-select skip")
# solc-select keeps compilers under $HOME/.solc-select (here /root) and its
# `solc` shim looks there at run time; the agent's HOME is the work dir, so the
# shim finds nothing. Install the real binary at a fixed path and point the
# venv's `solc` (first on PATH) at it.
RUN b="$(find /root/.solc-select /opt/venv/.solc-select -type f -name 'solc-0.8.26' 2>/dev/null | head -1)"; \
    if [ -n "$b" ]; then install -m 755 "$b" /usr/local/bin/solc-0.8.26 \
      && ln -sf /usr/local/bin/solc-0.8.26 /opt/venv/bin/solc; \
    else echo "WARN: solc binary not found, solc unavailable to the agent"; fi

# pwndbg: not on PyPI (the `pwndbg` name there is an old Python 2 upload) and
# not packaged by Kali, so use the official portable release. It bundles its own
# gdb and Python, so it does not depend on the system Python or on HOME. Pinned
# by version and checksum. Both gdb tools launch CTF_GDB and fall back to plain
# gdb when it is not on PATH (harness/agents/exttools.py:gdb_binary).
ARG PWNDBG_VERSION=2026.10.28
ARG PWNDBG_SHA256=17049a23ba8cbcf4780c4bc9b4aeb519f2801ceabe7304b55d3d622acca03b8c
RUN wget -q "https://github.com/pwndbg/pwndbg/releases/download/${PWNDBG_VERSION}/pwndbg_${PWNDBG_VERSION}_x86_64-portable.tar.xz" \
      -O /tmp/pwndbg.tar.xz \
 && echo "${PWNDBG_SHA256}  /tmp/pwndbg.tar.xz" | sha256sum -c - \
 && tar xJf /tmp/pwndbg.tar.xz -C /opt \
 && ln -sf /opt/pwndbg/bin/pwndbg /usr/local/bin/pwndbg \
 || echo "WARN: pwndbg skip"; \
    rm -f /tmp/pwndbg.tar.xz
ENV CTF_GDB=pwndbg

# --- git-based tools --------------------------------------------------------
RUN git clone --depth 1 https://github.com/RsaCtfTool/RsaCtfTool /opt/RsaCtfTool \
      && (pip install -r /opt/RsaCtfTool/requirements.txt || true) \
      && printf '#!/usr/bin/env bash\nexec python3 /opt/RsaCtfTool/RsaCtfTool.py "$@"\n' > /usr/local/bin/RsaCtfTool \
      && chmod +x /usr/local/bin/RsaCtfTool || echo "WARN: RsaCtfTool skip"; \
    git clone --depth 1 https://github.com/ticarpi/jwt_tool /opt/jwt_tool \
      && (pip install -r /opt/jwt_tool/requirements.txt || true) \
      && printf '#!/usr/bin/env bash\nexec python3 /opt/jwt_tool/jwt_tool.py "$@"\n' > /usr/local/bin/jwt_tool \
      && chmod +x /usr/local/bin/jwt_tool || echo "WARN: jwt_tool skip"

# pwninit (prebuilt release binary; CONFIRM version)
ARG PWNINIT_VERSION=3.3.1
RUN wget -q "https://github.com/io12/pwninit/releases/download/${PWNINIT_VERSION}/pwninit" \
      -O /usr/local/bin/pwninit && chmod +x /usr/local/bin/pwninit || echo "WARN: pwninit skip"

# --- Foundry (forge / cast / anvil) for blockchain challenges ---------------
ENV PATH="/root/.foundry/bin:${PATH}"
RUN (curl -L https://foundry.paradigm.xyz | bash && /root/.foundry/bin/foundryup) \
      || echo "WARN: foundry skip"

# --- heavy optional layers (toggle off to shrink toward a size limit) -------
ARG WITH_SAGE=1
RUN if [ "$WITH_SAGE" = "1" ]; then apt-get update && \
      apt-get install -y --no-install-recommends sagemath && rm -rf /var/lib/apt/lists/* \
      || echo "WARN: sagemath skip"; fi

ARG WITH_WORDLISTS=1
RUN if [ "$WITH_WORDLISTS" = "1" ]; then apt-get update && \
      for p in wordlists seclists; do apt-get install -y --no-install-recommends "$p" || echo "WARN: apt skip $p"; done; \
      rm -rf /var/lib/apt/lists/*; \
      ([ -f /usr/share/wordlists/rockyou.txt.gz ] && gunzip -kf /usr/share/wordlists/rockyou.txt.gz || true); fi

# --- the harness ------------------------------------------------------------
# Its Python dependencies go in their own layer BEFORE the source is copied, so
# a rebuild after editing contest.env or the platform adapter needs no network
# and takes seconds. Without the model SDK every model call fails with "SDK not
# installed". pytest is for the in-image smoke test; setuptools/wheel let the
# editable install below run without fetching a build backend.
RUN pip install "openai>=1.40" "anthropic>=0.40" "pytest>=8.0" "setuptools>=68" wheel
WORKDIR /opt/ctf-harness
COPY . /opt/ctf-harness
RUN pip install --no-index --no-deps --no-build-isolation -e .
# Contest settings (backend, model id, limits, platform adapter) live in
# contest.env, copied in above and read at start-up. Edit that file and rebuild;
# only this last layer reruns. `docker run -e NAME=value` overrides it.
# Offline knowledge base the `knowledge` tool greps (the web-search substitute).
# `knowledge/` is copied in above; sync your ctf-notes into it before building
# (python scripts/sync_knowledge.py ../ctf-notes) for the biggest gain.
ENV CTF_KNOWLEDGE_DIR=/opt/ctf-harness/knowledge
# Convenience: `ctf-tools` prints what the probe sees (sanity-check the build).
RUN printf '#!/usr/bin/env bash\npython -c "from harness.agents.exttools import probe_tools; from harness.agents.tools import LocalExecutor; from pathlib import Path; print(sorted(probe_tools(LocalExecutor(), Path(\"/tmp\"))))"\n' \
      > /usr/local/bin/ctf-tools && chmod +x /usr/local/bin/ctf-tools

# One challenge per container, non-interactive; config from env (model endpoint,
# budgets, platform) so nothing secret is baked in. See docker-entrypoint.sh.
ENTRYPOINT ["/opt/ctf-harness/docker-entrypoint.sh"]
CMD []
