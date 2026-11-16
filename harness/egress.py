"""Egress allowlist for rehearsal runs on shared infrastructure.

In rehearsal the agent port-scanned the host of its CyberEDU instance and
opened other users' instances on it, mostly from Python socket loops that no
command filter can recognise. The boundary therefore has to be the network.
With CTF_EGRESS_LOCKDOWN=1 (and the container started with --cap-add
NET_ADMIN), the harness installs iptables rules before the agent starts that
allow only:

  * loopback and replies on established connections,
  * DNS,
  * the challenge's own service address(es),
  * the model endpoint, and the platform API the harness itself uses.

Everything else is rejected. The agent's commands run with NET_ADMIN and
NET_RAW removed from their capability bounding set (see
tools.agent_argv_prefix), so even as root they cannot change the rules or send
raw packets. Lockdown fails closed: if the rules cannot be installed the run
stops before the agent starts.

Not for the contest image: the organizers' sandbox does its own network
isolation, and the image has no iptables.
"""

from __future__ import annotations

import os
import socket
import subprocess
from urllib.parse import urlsplit

from .platforms.base import ConnInfo

ENV_FLAG = "CTF_EGRESS_LOCKDOWN"
# Hosts the harness process itself must reach, besides the model endpoint.
PLATFORM_HOSTS = ("api.cyber-edu.co:443", "sso.cyber-edu.co:443")


class EgressError(RuntimeError):
    pass


def enabled() -> bool:
    return os.environ.get(ENV_FLAG, "").strip().lower() in ("1", "true", "yes")


def targets(conn: ConnInfo | None) -> list[tuple[str, int]]:
    """The challenge's own service addresses as (host, port)."""
    out: list[tuple[str, int]] = []
    if conn is None:
        return out
    if conn.host and conn.port:
        out.append((conn.host, int(conn.port)))
    for a in (conn.meta or {}).get("addresses") or []:
        host, _, port = str(a.get("address", "")).rpartition(":")
        if host and port.isdigit():
            out.append((host, int(port)))
    if conn.url and not out:
        u = urlsplit(conn.url)
        if u.hostname:
            out.append((u.hostname, u.port or (443 if u.scheme == "https" else 80)))
    return sorted(set(out))


def harness_endpoints() -> list[tuple[str, int]]:
    """The model endpoint and the platform API, as (host, port)."""
    out = []
    base = os.environ.get("OPENAI_BASE_URL") or os.environ.get("ANTHROPIC_BASE_URL")
    if base:
        u = urlsplit(base)
        if u.hostname:
            out.append((u.hostname, u.port or (443 if u.scheme == "https" else 80)))
    for hp in PLATFORM_HOSTS:
        host, _, port = hp.rpartition(":")
        out.append((host, int(port)))
    return out


def _resolve(host: str) -> list[str]:
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(host, None, socket.AF_INET)})
    except OSError as e:
        raise EgressError(f"cannot resolve {host}: {e}") from e


def rules(allowed: list[tuple[str, int]]) -> list[list[str]]:
    """iptables commands (IPv4) for an allowlist of (ip, port). IPv6 is closed
    entirely apart from loopback."""
    v4 = [["iptables", "-F", "OUTPUT"],
          ["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
          ["iptables", "-A", "OUTPUT", "-m", "conntrack", "--ctstate",
           "ESTABLISHED,RELATED", "-j", "ACCEPT"],
          ["iptables", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "ACCEPT"],
          ["iptables", "-A", "OUTPUT", "-p", "tcp", "--dport", "53", "-j", "ACCEPT"]]
    for ip, port in sorted(set(allowed)):
        v4.append(["iptables", "-A", "OUTPUT", "-p", "tcp", "-d", ip,
                   "--dport", str(port), "-j", "ACCEPT"])
    v4.append(["iptables", "-A", "OUTPUT", "-j", "REJECT"])
    v6 = [["ip6tables", "-F", "OUTPUT"],
          ["ip6tables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
          ["ip6tables", "-A", "OUTPUT", "-j", "REJECT"]]
    return v4 + v6


def lockdown(conn: ConnInfo | None, run=subprocess.run) -> list[tuple[str, int]]:
    """Install the allowlist. Returns the (ip, port) pairs allowed. Raises
    EgressError if any rule fails; the caller must not start the agent then."""
    allowed: list[tuple[str, int]] = []
    for host, port in targets(conn) + harness_endpoints():
        for ip in _resolve(host):
            allowed.append((ip, port))
    for cmd in rules(allowed):
        try:
            r = run(cmd, capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.SubprocessError) as e:
            raise EgressError(f"{' '.join(cmd)}: {e}") from e
        if r.returncode != 0:
            if cmd[0] == "ip6tables" and "Address family not supported" in (r.stderr or ""):
                continue            # no IPv6 in this container: nothing to close
            raise EgressError(f"{' '.join(cmd)}: {(r.stderr or r.stdout).strip()[:200]}")
    return sorted(set(allowed))
