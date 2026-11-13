# Submission image for the AISafe agentic CTF.
#
# The organizers run ONE container per challenge on their infra (challenge
# auto-started, their model endpoint injected, NO INTERNET at run time). So every
# tool the agent may use must be baked in here — this image IS the submission.
#
# Base: kali-rolling. Andrei runs Kali, and his ctf-notes use Kali defaults
# (/usr/share/wordlists/rockyou.txt, ghidra, sagemath, zsteg, stegseek, ...), so
# Kali packages almost the whole toolkit in one apt layer. Trade-off: it's a
# rolling release (pin a snapshot if you need reproducibility) and a large image
# (SageMath + SecLists are most of the bulk — see the WITH_* build args).
#
# Build on a machine with Docker + internet (cannot build in the run sandbox):
#   docker build -t ctf-harness:latest .
#   docker build --build-arg WITH_SAGE=0 --build-arg WITH_WORDLISTS=0 -t ctf-harness:slim .
#   docker run --rm ctf-harness:latest python -m pytest -q      # smoke test
#
# Two run-time constraints no install changes: NO GPU (hashcat is CPU-only/slow;
# John is the CPU cracking workhorse) and NO INTERNET (factordb / online RSA
# lookups are dead — use local factoring: sage, yafu).
#
# Package/URL names are best-effort for Kali; verify at build (marked CONFIRM).
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1 \
    LANG=C.UTF-8

# --- system toolkit (Kali apt) ---------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
      # core
      python3 python3-pip python3-venv python3-dev build-essential \
      git curl wget unzip ca-certificates ruby ruby-dev openjdk-17-jre-headless \
      # rev / debug
      gdb gdbserver radare2 ghidra binutils file xxd bsdextrautils \
      patchelf ltrace strace checksec \
      # pwn helpers (gems added below: one_gadget, seccomp-tools)
      # forensics
      volatility3 exiftool tshark tcpdump poppler-utils foremost binwalk sox \
      # stego
      steghide stegseek \
      # cracking (CPU: no GPU in the run sandbox)
      john hashcat hashid hydra fcrackzip pdfcrack hcxtools \
      # web
      sqlmap gobuster ffuf nmap \
      # mobile / apk
      apktool jadx dex2jar \
      # wifi (offline pcap cracking)
      aircrack-ng \
      # misc
      openssl netcat-traditional \
 && rm -rf /var/lib/apt/lists/* \
 # analyzeHeadless on PATH for the ghidra_decompile tool (CONFIRM path).
 && (ln -sf /usr/share/ghidra/support/analyzeHeadless /usr/local/bin/analyzeHeadless || true)

# --- Ruby gems (zsteg etc. are not apt-packaged) ----------------------------
RUN gem install --no-document zsteg one_gadget seccomp-tools || true

# --- Python toolkit (venv; Kali pip is PEP 668 externally-managed) ----------
# Put the venv first on PATH so the agent's `python3`/`shell` see these libs.
# (Kali's own apt tools use absolute /usr/bin/python3 shebangs, so they are
# unaffected by the venv PATH.)
ENV PATH="/opt/venv/bin:${PATH}"
RUN python3 -m venv /opt/venv \
 && pip install --upgrade pip \
 && pip install \
      pwntools ROPgadget ropper angr z3-solver capstone unicorn pwndbg \
      pycryptodome sympy numpy gmpy2 fpylll cysignals roca-detect xortool \
      requests scapy flask-unsign factordb-pycli paddingoracle frida-tools

# Trusted pwndbg init, loaded explicitly by the gdb wrapper via CTF_GDB_INIT
# (the wrapper runs gdb with --nx so a planted ./.gdbinit is ignored). Resolve
# the real path so it survives python-version bumps.
RUN printf 'source %s\n' \
      "$(/opt/venv/bin/python -c 'import os,pwndbg;print(os.path.join(os.path.dirname(pwndbg.__file__),"gdbinit.py"))' 2>/dev/null)" \
      > /opt/gdbinit-pwndbg || true
ENV CTF_GDB_INIT=/opt/gdbinit-pwndbg

# --- git-based tools (RsaCtfTool, jwt_tool) --------------------------------
RUN git clone --depth 1 https://github.com/RsaCtfTool/RsaCtfTool /opt/RsaCtfTool \
 && (pip install -r /opt/RsaCtfTool/requirements.txt || true) \
 && printf '#!/usr/bin/env bash\nexec python3 /opt/RsaCtfTool/RsaCtfTool.py "$@"\n' > /usr/local/bin/RsaCtfTool \
 && chmod +x /usr/local/bin/RsaCtfTool \
 && git clone --depth 1 https://github.com/ticarpi/jwt_tool /opt/jwt_tool \
 && (pip install -r /opt/jwt_tool/requirements.txt || true) \
 && printf '#!/usr/bin/env bash\nexec python3 /opt/jwt_tool/jwt_tool.py "$@"\n' > /usr/local/bin/jwt_tool \
 && chmod +x /usr/local/bin/jwt_tool

# --- pwninit (prebuilt release binary; CONFIRM version) ---------------------
ARG PWNINIT_VERSION=3.3.1
RUN wget -q "https://github.com/io12/pwninit/releases/download/${PWNINIT_VERSION}/pwninit" \
      -O /usr/local/bin/pwninit && chmod +x /usr/local/bin/pwninit || true

# --- heavy, optional layers (toggle off to shrink toward a size limit) ------
ARG WITH_SAGE=1
RUN if [ "$WITH_SAGE" = "1" ]; then \
      apt-get update && apt-get install -y --no-install-recommends sagemath \
      && rm -rf /var/lib/apt/lists/*; fi

ARG WITH_WORDLISTS=1
RUN if [ "$WITH_WORDLISTS" = "1" ]; then \
      apt-get update && apt-get install -y --no-install-recommends wordlists seclists \
      && rm -rf /var/lib/apt/lists/* \
      && ([ -f /usr/share/wordlists/rockyou.txt.gz ] && gunzip -kf /usr/share/wordlists/rockyou.txt.gz || true); fi

# --- the harness ------------------------------------------------------------
WORKDIR /opt/ctf-harness
COPY . /opt/ctf-harness
RUN pip install -e .

# One challenge per container, non-interactive; config from env (model endpoint,
# budgets, platform) so nothing secret is baked in. See docker-entrypoint.sh.
ENTRYPOINT ["/opt/ctf-harness/docker-entrypoint.sh"]
CMD []
