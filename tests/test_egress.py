"""Egress lockdown: rule generation, fail-closed behaviour, and the agent's
capability drop. Nothing here touches the real firewall."""

import subprocess

import pytest

from harness import egress
from harness.agents.tools import agent_argv_prefix
from harness.platforms.base import ConnInfo

T = ConnInfo(host="35.242.202.105", port=32287, url="http://35.242.202.105:32287",
             meta={"addresses": [{"address": "35.242.202.105:32287"},
                                 {"address": "35.242.202.105:32288"}]})


def test_targets_are_the_instance_addresses_only():
    assert egress.targets(T) == [("35.242.202.105", 32287), ("35.242.202.105", 32288)]
    assert egress.targets(None) == []


def test_rules_allow_only_the_list_and_reject_the_rest():
    rs = egress.rules([("35.242.202.105", 32287), ("1.2.3.4", 443)])
    accepts = [r for r in rs if r[0] == "iptables" and "-d" in r]
    assert {(r[r.index("-d") + 1], r[r.index("--dport") + 1]) for r in accepts} == \
        {("35.242.202.105", "32287"), ("1.2.3.4", "443")}
    assert rs[[r[0] for r in rs].index("ip6tables") - 1][-2:] == ["-j", "REJECT"]
    assert rs[-1][-2:] == ["-j", "REJECT"]               # IPv6 closed too


def test_harness_endpoints_include_model_and_platform(monkeypatch):
    monkeypatch.setenv("OPENAI_BASE_URL", "https://api.z.ai/api/coding/paas/v4")
    eps = egress.harness_endpoints()
    assert ("api.z.ai", 443) in eps and ("api.cyber-edu.co", 443) in eps


def test_lockdown_fails_closed_when_a_rule_fails(monkeypatch):
    monkeypatch.setattr(egress, "_resolve", lambda h: ["10.0.0.1"])

    def failing(cmd, **kw):
        return subprocess.CompletedProcess(cmd, 4, "", "Permission denied (you must be root)")

    with pytest.raises(egress.EgressError, match="Permission denied"):
        egress.lockdown(T, run=failing)


def test_agent_processes_drop_net_admin_only_under_lockdown(monkeypatch):
    monkeypatch.delenv("CTF_EGRESS_LOCKDOWN", raising=False)
    assert agent_argv_prefix() == []
    monkeypatch.setenv("CTF_EGRESS_LOCKDOWN", "1")
    assert agent_argv_prefix()[:2] == ["setpriv", "--bounding-set=-net_admin,-net_raw"]
