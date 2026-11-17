#!/usr/bin/env bash
# Tools added to the image after the CyberEDU rehearsal (2026-11-17).
#
# One definition, two ways in:
#   * the main Dockerfile runs this as a late layer, so a from-scratch build
#     produces the same image;
#   * Dockerfile.tools runs it on top of the existing ctf-harness:base, which
#     takes minutes and does not depend on the build cache.
#
# Every install is best-effort and prints WARN on a miss, like the rest of the
# image; scripts/check_image.py says afterwards what the agent can really see.
set -u
export DEBIAN_FRONTEND=noninteractive

apt-get update
for p in \
    `# hidden-cipher: no ssh client; the agent scripted SSH with paramiko` \
    openssh-client sshpass \
    `# other clients a "box with a service" challenge expects` \
    telnet ftp lftp smbclient default-mysql-client postgresql-client redis-tools sqlite3 \
    `# puzzled: wanted to run leaked PHP. JS challenges want node` \
    php-cli nodejs \
    `# run 32-bit ELF binaries natively (entry-level pwn and rev)` \
    libc6-i386 lib32stdc++6 \
    `# small forensics helpers` \
    pngcheck \
    `# found missing in the rehearsal logs: ss/ip (2 runs), ping (1 run)` \
    iproute2 iputils-ping \
    ; do
  apt-get install -y --no-install-recommends "$p" || echo "WARN: apt skip $p"
done
rm -rf /var/lib/apt/lists/*

# Python, in the venv the agent and the harness share.
#   mcp<2          the client library, in case the starter kit is an MCP server
#                  (the 2.x SDK breaks CyberEDU's server)
#   pillow         view_image resizes with it (falls back to raw PNG/JPEG)
#   the rest       everyday web-challenge helpers
#   matplotlib     zodiac (rehearsal) reached for it to plot a mouse trail;
#                  pairs with view_image. scipy: also reached for, general.
for p in "mcp<2" pillow beautifulsoup4 pyjwt websocket-client matplotlib scipy; do
  /opt/venv/bin/pip install --no-cache-dir "$p" || echo "WARN: pip skip $p"
done

# CyberEDU's own MCP server, in its own venv, off the agent's PATH. The contest
# runs on CyberEDU; if the starter kit turns out to be this server, switching
# to it is then a settings change (CTF_PLATFORM=cyberedu, CTF_CONTEST_ID=<slug>)
# with no install at the venue. It does nothing unless that setting is on.
# Pinned to the commits validated in rehearsal. WITH_CYBEREDU_MCP=0 leaves it out.
if [ "${WITH_CYBEREDU_MCP:-1}" = "1" ]; then
  CLIENT_REF="${CYBEREDU_CLIENT_REF:-913ccf1750f3da0c8a2c520b3d24ef56b83d8785}"
  MCP_REF="${CYBEREDU_MCP_REF:-f81b6899ad83c2f5abad75c63fde05751335c1c0}"
  ( /usr/bin/python3 -m venv /opt/cyberedu-mcp \
    && /opt/cyberedu-mcp/bin/pip install --no-cache-dir "mcp<2" \
         "cyberedu-client @ git+https://github.com/CyberEDU-Cyber-Range/cyberedu-client@${CLIENT_REF}" \
         "cyberedu-mcp @ git+https://github.com/CyberEDU-Cyber-Range/cyberedu-mcp@${MCP_REF}" \
  ) || echo "WARN: cyberedu-mcp skip"
fi
# File capabilities make a binary unrunnable when the sandbox's capability
# bounding set lacks them: Kali's nmap (cap_net_raw,cap_net_admin=eip) fails
# with "exec: Operation not permitted" under `docker run --cap-drop NET_RAW`
# (seen in final-round task 1). The container runs as root, so the file
# capabilities add nothing; a connect scan (-sT) needs no raw socket.
command -v getcap >/dev/null && getcap -r / 2>/dev/null | awk '{print $1}' | while read -r f; do
  setcap -r "$f" && echo "file capabilities removed: $f" || echo "WARN: setcap -r $f"
done

# Foundry was installed under /root/.foundry (mode 700): under
# `docker run --user 1000:1000` forge and cast vanished. Put them on a path
# every user can read.
for b in /root/.foundry/bin/*; do
  [ -f "$b" ] && install -m 755 "$b" /usr/local/bin/ || true
done

exit 0
