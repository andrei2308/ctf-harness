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
#   docker run --rm -e CTF_BACKEND=rule ctf-harness:latest python -m pytest -q   # smoke
#   docker run --rm ctf-harness:latest ctf-tools                         # list what's present
#
# Run-time constraints no install changes: NO GPU (hashcat is CPU-only/slow —
# John is the CPU workhorse) and NO INTERNET (factordb / online RSA lookups are
# dead — factor locally with sage / yafu). The image is large; SageMath and
# SecLists are the bulk and sit behind the WITH_* args.
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1 \
    LANG=C.UTF-8

# --- core build deps (must succeed) ----------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-pip python3-venv python3-dev build-essential \
      git curl wget unzip ca-certificates ruby ruby-dev openjdk-17-jre-headless \
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
      pwntools ROPgadget ropper angr z3-solver capstone unicorn pwndbg \
      pycryptodome pycryptodomex sympy numpy gmpy2 requests scapy
# extended python tooling, best-effort per package
RUN for p in \
      fpylll cysignals roca-detect xortool primefac libnum \
      flask-unsign factordb-pycli paddingoracle frida-tools objection \
      oletools uncompyle6 decompyle3 yara-python flare-floss capa \
      wfuzz dirsearch arpy \
      `# ocr` pytesseract \
      `# blockchain` web3 eth-abi eth-account eth-utils slither-analyzer solc-select vyper ; do \
        pip install "$p" || echo "WARN: pip skip $p"; \
      done \
 && (solc-select install 0.8.26 && solc-select use 0.8.26 || echo "WARN: solc-select skip")

# pwndbg init, loaded explicitly by the gdb wrapper via CTF_GDB_INIT (the wrapper
# runs gdb --nx so a planted ./.gdbinit is ignored). Resolve the real path.
RUN printf 'source %s\n' \
      "$(/opt/venv/bin/python -c 'import os,pwndbg;print(os.path.join(os.path.dirname(pwndbg.__file__),"gdbinit.py"))' 2>/dev/null)" \
      > /opt/gdbinit-pwndbg || true
ENV CTF_GDB_INIT=/opt/gdbinit-pwndbg

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
WORKDIR /opt/ctf-harness
COPY . /opt/ctf-harness
# The model SDKs are extras, not core deps: without them every model call fails
# with "SDK not installed". pytest is here for the in-image smoke test.
RUN pip install -e ".[openai,anthropic,dev]"
# Image defaults: talk to an OpenAI-compatible endpoint (OPENAI_BASE_URL /
# OPENAI_API_KEY from the run environment). Set CTF_FAST_MODEL and CTF_PLATFORM
# here once the organizers publish the model id and the starter-kit interface.
ENV CTF_BACKEND=openai \
    CTF_LOG_MIRROR=1
# Offline knowledge base the `knowledge` tool greps (the web-search substitute).
# `knowledge/` is copied in above; drop your ctf-notes there before building
# (cp -r ../ctf-notes/* knowledge/) for the biggest gain.
ENV CTF_KNOWLEDGE_DIR=/opt/ctf-harness/knowledge
# Convenience: `ctf-tools` prints what the probe sees (sanity-check the build).
RUN printf '#!/usr/bin/env bash\npython -c "from harness.agents.exttools import probe_tools; from harness.agents.tools import LocalExecutor; from pathlib import Path; print(sorted(probe_tools(LocalExecutor(), Path(\"/tmp\"))))"\n' \
      > /usr/local/bin/ctf-tools && chmod +x /usr/local/bin/ctf-tools

# One challenge per container, non-interactive; config from env (model endpoint,
# budgets, platform) so nothing secret is baked in. See docker-entrypoint.sh.
ENTRYPOINT ["/opt/ctf-harness/docker-entrypoint.sh"]
CMD []
