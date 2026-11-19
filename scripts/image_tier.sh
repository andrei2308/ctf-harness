#!/usr/bin/env bash
# Build steps for the smaller image tiers (Dockerfile.slim).
#
#   ctf-image-tier <stage>      stage: base apt gems python extras wordlists heavy finish
#
# Each stage is one layer of the image. What a tier contains is data, in
# scripts/tiers/<tier>.conf (copied to /etc/ctf-image-tier.conf); this script is
# the same for every tier. It repeats the install fixes of the main Dockerfile
# (venv first on PATH, the filebytes pin for ropper, solc at a fixed path, the
# pinned pwndbg release, file capabilities removed) because the main Dockerfile
# is frozen and must not change.
#
# Two differences from the main Dockerfile, both on purpose:
#   * a critical tool that fails to install stops the build here, instead of
#     producing an image that fails scripts/check_image.py twenty minutes later;
#   * every skipped optional package is written to /var/log/ctf-image-skips.log
#     inside the image, so it can be read after the build.
set -u
STAGE="${1:?usage: ctf-image-tier <stage>}"
export DEBIAN_FRONTEND=noninteractive PIP_NO_CACHE_DIR=1

# shellcheck disable=SC1091
. /etc/ctf-image-tier.conf

: "${ROCKYOU:=1}"      # 0 in a specialist tier that cracks nothing

VENV=/opt/venv
VPIP="$VENV/bin/pip"
SKIPS=/var/log/ctf-image-skips.log

# Versions of Python packages, when scripts/tiers/constraints.txt has any.
PIPC=()
if grep -qE '^[A-Za-z0-9]' /etc/ctf-pip-constraints.txt 2>/dev/null; then
  PIPC=(-c /etc/ctf-pip-constraints.txt)
fi

# The lists of SecLists worth their size. Patterns for `find -path`; a pattern
# that matches nothing in this SecLists release is simply not kept.
if [ -z "${SECLISTS_KEEP+x}" ]; then
  SECLISTS_KEEP=(
    '*/Discovery/Web-Content/common.txt'
    '*/Discovery/Web-Content/big.txt'
    '*/Discovery/Web-Content/raft-small-*.txt'
    '*/Discovery/Web-Content/raft-medium-directories.txt'
    '*/Discovery/Web-Content/raft-medium-files.txt'
    '*/Discovery/Web-Content/*directory-list-2.3-small.txt'
    '*/Discovery/Web-Content/*directory-list-2.3-medium.txt'
    '*/Discovery/Web-Content/quickhits.txt'
    '*/Discovery/Web-Content/burp-parameter-names.txt'
    '*/Discovery/Web-Content/api/*'
    '*/Discovery/DNS/subdomains-top1million-5000.txt'
    '*/Fuzzing/LFI/*'
    '*/Fuzzing/SQLi/*'
    '*/Fuzzing/XSS/*'
    '*/Fuzzing/special-chars.txt'
    '*/Passwords/Common-Credentials/10k-most-common.txt'
    '*/Passwords/Common-Credentials/*-10000.txt'
    '*/Passwords/Common-Credentials/best1050.txt'
    '*/Passwords/Common-Credentials/top-passwords-shortlist.txt'
    '*/Passwords/Default-Credentials/*'
    '*/Usernames/top-usernames-shortlist.txt'
    '*/Usernames/Names/names.txt'
  )
fi

warn() { echo "WARN: $*"; echo "$*" >> "$SKIPS"; }
die()  { echo "FATAL: $*" >&2; exit 1; }
on()   { [ "${1:-0}" = "1" ]; }

apt_update() { apt-get update || die "apt-get update failed (network?)"; }
apt_try() {
  local p
  for p in "$@"; do
    apt-get install -y --no-install-recommends "$p" || warn "apt skip $p"
  done
}
# Leave nothing in the layer that only the build needed.
cleanup() {
  apt-get clean
  rm -rf /var/lib/apt/lists/* /root/.cache /tmp/* /var/tmp/* 2>/dev/null
  return 0
}
need() {
  local t
  for t in "$@"; do
    command -v "$t" >/dev/null || die "critical tool missing after install: $t"
  done
}

stage_base() {
  # Documentation, man pages and translations: tens to hundreds of MB the agent
  # never reads (it uses --help). Licences are kept.
  cat > /etc/dpkg/dpkg.cfg.d/01-ctf-nodoc <<'EOF'
path-exclude=/usr/share/doc/*
path-include=/usr/share/doc/*/copyright
path-exclude=/usr/share/man/*
path-exclude=/usr/share/info/*
path-exclude=/usr/share/locale/*
path-include=/usr/share/locale/locale.alias
EOF
  apt_update
  # cmake and pkg-config: pinned Python packages without a wheel for this
  # Python (unicorn 2.1.2) build from source. The full image has both as
  # dependencies of its other packages.
  apt-get install -y --no-install-recommends \
      python3 python3-pip python3-venv python3-dev build-essential \
      git curl wget unzip ca-certificates xz-utils libcap2-bin \
      cmake pkg-config \
    || die "core packages failed to install"
  cleanup
}

stage_apt() {
  apt_update
  apt_try "${APT[@]}"
  cleanup
  # scripts/check_image.py's critical set, as far as apt provides it. A
  # specialist tier (one category's tools only) names its own in NEED.
  if [ -z "${NEED+x}" ]; then
    NEED=(gdb objdump readelf strings file xxd binwalk exiftool tshark john curl nmap socat)
  fi
  need "${NEED[@]}"
  command -v nc >/dev/null || command -v netcat >/dev/null || die "critical tool missing: nc"
}

stage_gems() {
  local g
  [ "${#GEMS[@]}" -gt 0 ] || return 0
  command -v gem >/dev/null || { warn "gems skipped: ruby is not installed"; return 0; }
  for g in "${GEMS[@]}"; do
    gem install --no-document "$g" || warn "gem skip $g"
  done
  cleanup
}

stage_python() {
  local p b
  python3 -m venv "$VENV" && "$VPIP" install --upgrade pip || die "venv"
  "$VPIP" install "${PIPC[@]}" \
      pwntools ROPgadget z3-solver capstone unicorn \
      pycryptodome pycryptodomex sympy numpy gmpy2 requests scapy \
    || die "core Python packages failed to install"
  if on "$WITH_ANGR"; then
    "$VPIP" install "${PIPC[@]}" angr || die "angr failed to install"
  fi
  # The harness's own dependencies (see the main Dockerfile for why each).
  "$VPIP" install "${PIPC[@]}" "openai>=1.40" "anthropic>=0.40" "pytest>=8.0" \
      "setuptools>=68" wheel || die "harness dependencies failed to install"
  # ropper needs filebytes from the fix commit (ast.Str is gone in Python 3.14).
  ( "$VPIP" install "filebytes @ git+https://github.com/sashs/filebytes@ff7492d750140288e2c3ff25b8a648719be470ce" \
      && "$VPIP" install "${PIPC[@]}" ropper ) || warn "pip skip ropper"
  for p in "${PIP_PKGS[@]}"; do
    "$VPIP" install "${PIPC[@]}" "$p" || warn "pip skip $p"
  done
  # solc: the real compiler at a fixed path, because solc-select's shim looks
  # under $HOME and the agent's HOME is its work dir.
  if [ -x "$VENV/bin/solc-select" ]; then
    ( "$VENV/bin/solc-select" install 0.8.26 && "$VENV/bin/solc-select" use 0.8.26 ) \
      || warn "solc-select could not fetch solc 0.8.26"
    b="$(find /root/.solc-select "$VENV/.solc-select" -type f -name 'solc-0.8.26' 2>/dev/null | head -1)"
    if [ -n "$b" ]; then
      install -m 755 "$b" /usr/local/bin/solc-0.8.26 \
        && ln -sf /usr/local/bin/solc-0.8.26 "$VENV/bin/solc"
      rm -rf /root/.solc-select "$VENV/.solc-select"
    else
      warn "solc binary not found, solc unavailable to the agent"
    fi
  fi
  cleanup
}

# Clone a tool at a known commit when one is given, at the default branch's
# head otherwise; the history is not kept.
clone() {   # clone <url> <dir> [ref]
  git clone --depth 1 "$1" "$2" || return 1
  if [ -n "${3:-}" ]; then
    git -C "$2" fetch --depth 1 origin "$3" && git -C "$2" checkout -q FETCH_HEAD || return 1
  fi
  git -C "$2" rev-parse HEAD > "$2/.ctf-commit"
  rm -rf "$2/.git"
}

stage_extras() {
  if on "$WITH_PWNDBG"; then
    local v="${PWNDBG_VERSION:-2026.10.28}"
    local s="${PWNDBG_SHA256:-17049a23ba8cbcf4780c4bc9b4aeb519f2801ceabe7304b55d3d622acca03b8c}"
    ( wget -q "https://github.com/pwndbg/pwndbg/releases/download/${v}/pwndbg_${v}_x86_64-portable.tar.xz" \
          -O /tmp/pwndbg.tar.xz \
        && echo "${s}  /tmp/pwndbg.tar.xz" | sha256sum -c - \
        && tar xJf /tmp/pwndbg.tar.xz -C /opt \
        && ln -sf /opt/pwndbg/bin/pwndbg /usr/local/bin/pwndbg ) || warn "pwndbg skip"
  fi
  if on "$WITH_RSACTFTOOL"; then
    ( clone https://github.com/RsaCtfTool/RsaCtfTool /opt/RsaCtfTool "${RSACTFTOOL_REF:-}" \
        && "$VPIP" install "${PIPC[@]}" /opt/RsaCtfTool ) || warn "RsaCtfTool skip"
  fi
  if on "$WITH_JWT_TOOL"; then
    ( clone https://github.com/ticarpi/jwt_tool /opt/jwt_tool "${JWT_TOOL_REF:-}" \
        && { "$VPIP" install "${PIPC[@]}" -r /opt/jwt_tool/requirements.txt || true; } \
        && printf '#!/usr/bin/env bash\nexec python3 /opt/jwt_tool/jwt_tool.py "$@"\n' > /usr/local/bin/jwt_tool \
        && chmod +x /usr/local/bin/jwt_tool ) || warn "jwt_tool skip"
  fi
  if on "$WITH_PWNINIT"; then
    ( wget -q "https://github.com/io12/pwninit/releases/download/${PWNINIT_VERSION:-3.3.1}/pwninit" \
          -O /usr/local/bin/pwninit && chmod +x /usr/local/bin/pwninit ) \
      || { rm -f /usr/local/bin/pwninit; warn "pwninit skip"; }
  fi
  if on "$WITH_FOUNDRY"; then
    # One copy, where every user can run it (the main image has a second one
    # under /root/.foundry).
    ( curl -L https://foundry.paradigm.xyz | bash && /root/.foundry/bin/foundryup \
        && for b in forge cast anvil; do install -m 755 "/root/.foundry/bin/$b" /usr/local/bin/; done ) \
      || warn "foundry skip"
    rm -rf /root/.foundry
  fi
  if on "$WITH_CYBEREDU_MCP"; then
    # CyberEDU's MCP server in its own venv, off the agent's PATH; dormant
    # unless CTF_PLATFORM=cyberedu. Same commits as scripts/image_extras.sh.
    local c="${CYBEREDU_CLIENT_REF:-913ccf1750f3da0c8a2c520b3d24ef56b83d8785}"
    local m="${CYBEREDU_MCP_REF:-f81b6899ad83c2f5abad75c63fde05751335c1c0}"
    ( /usr/bin/python3 -m venv /opt/cyberedu-mcp \
        && /opt/cyberedu-mcp/bin/pip install "mcp<2" \
             "cyberedu-client @ git+https://github.com/CyberEDU-Cyber-Range/cyberedu-client@${c}" \
             "cyberedu-mcp @ git+https://github.com/CyberEDU-Cyber-Range/cyberedu-mcp@${m}" \
    ) || warn "cyberedu-mcp skip"
  fi
  cleanup
}

stage_wordlists() {
  local keep=() pat first=1 dst
  if [ "${ROCKYOU}" != "1" ] && [ "${SECLISTS}" = "none" ]; then
    echo "no wordlists in this tier"; return 0
  fi
  apt_update
  [ "${ROCKYOU}" = "1" ] && apt_try wordlists dirb
  # rockyou.txt, unpacked (stegseek, john and the notes all name this path).
  if [ -f /usr/share/wordlists/rockyou.txt.gz ]; then
    gunzip -f /usr/share/wordlists/rockyou.txt.gz
  fi
  [ "${ROCKYOU}" != "1" ] || [ -s /usr/share/wordlists/rockyou.txt ] || warn "rockyou.txt is missing"
  case "${SECLISTS}" in
    full)
      apt_try seclists ;;
    subset)
      apt_try seclists
      if [ -d /usr/share/seclists ]; then
        for pat in "${SECLISTS_KEEP[@]}"; do
          [ "$first" = 1 ] || keep+=(-o)
          keep+=(-path "$pat"); first=0
        done
        find /usr/share/seclists \( -type f -o -type l \) ! \( "${keep[@]}" \) -delete
        find /usr/share/seclists -depth -type d -empty -delete
        echo "SecLists kept: $(find /usr/share/seclists -type f | wc -l) files," \
             "$(du -sh /usr/share/seclists | cut -f1)"
      else
        warn "seclists did not install"
      fi ;;
    none) ;;
    *) die "SECLISTS must be subset, full or none (got '${SECLISTS}')" ;;
  esac
  # The paths the notes use, when the package that owns them is not installed.
  dst=/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
  if [ ! -e "$dst" ] && [ -d /usr/share/seclists ]; then
    pat="$(find /usr/share/seclists -name '*directory-list-2.3-medium.txt' | head -1)"
    if [ -n "$pat" ]; then
      rm -f /usr/share/wordlists/dirbuster        # a dangling link to the dirbuster package
      mkdir -p /usr/share/wordlists/dirbuster && ln -sf "$pat" "$dst"
    fi
  fi
  cleanup
}

stage_heavy() {
  on "$WITH_GHIDRA" || on "$WITH_SAGE" || return 0
  apt_update
  if on "$WITH_GHIDRA"; then
    apt_try ghidra
    ln -sf /usr/share/ghidra/support/analyzeHeadless /usr/local/bin/analyzeHeadless
    [ -e /usr/share/ghidra/support/analyzeHeadless ] || warn "ghidra: analyzeHeadless is missing"
  fi
  if on "$WITH_SAGE"; then
    apt_try sagemath
  fi
  cleanup
}

stage_finish() {
  local f
  # File capabilities make a binary unrunnable when the sandbox drops them from
  # the bounding set (nmap under --cap-drop NET_RAW). See image_extras.sh.
  getcap -r / 2>/dev/null | awk '{print $1}' | while read -r f; do
    setcap -r "$f" && echo "file capabilities removed: $f" || warn "setcap -r $f"
  done
  # What this image is, for scripts/check_image.py and for whoever inspects it.
  {
    echo "tier=${TIER:-unknown}"
    for f in WITH_ANGR WITH_PWNDBG WITH_RSACTFTOOL WITH_JWT_TOOL WITH_PWNINIT \
             WITH_FOUNDRY WITH_CYBEREDU_MCP WITH_GHIDRA WITH_SAGE SECLISTS ROCKYOU; do
      echo "$f=${!f}"
    done
  } > /etc/ctf-image-tier
  touch "$SKIPS"
  cleanup
  echo "=== tier summary ==="; cat /etc/ctf-image-tier
  echo "=== skipped ($(wc -l < "$SKIPS")) ==="; cat "$SKIPS"
  echo "=== where the space is (MB) ==="
  du -xsm /opt/* /usr/lib /usr/share /usr/bin /usr/local /var 2>/dev/null | sort -rn | head -25
  echo "=== total ==="; du -xsh / 2>/dev/null | tail -1
}

case "$STAGE" in
  base)      stage_base ;;
  apt)       stage_apt ;;
  gems)      stage_gems ;;
  python)    stage_python ;;
  extras)    stage_extras ;;
  wordlists) stage_wordlists ;;
  heavy)     stage_heavy ;;
  finish)    stage_finish ;;
  *)         die "unknown stage: $STAGE" ;;
esac
