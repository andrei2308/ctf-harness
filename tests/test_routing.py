"""Category-aware routing to specialists, and profile sanity."""

from harness.agents.specialists import (CryptoSpecialist, ForensicsSpecialist,
                                        GeneralistSpecialist, MobileSpecialist,
                                        PwnSpecialist, RevSpecialist, WebSpecialist,
                                        BlockchainSpecialist, PyjailSpecialist,
                                        route, _REV, _PWN, _CRYPTO, _FORENSICS,
                                        _WEB, _MOBILE, _BLOCKCHAIN, _PYJAIL, _GENERALIST)
from harness.platforms.base import Challenge, ChallengeKind, ConnInfo


def _ch(category="", kind=ChallengeKind.UNKNOWN):
    return Challenge(id="c", name="c", category=category, kind=kind)


def test_category_routing():
    assert route(_ch("pwn"), None) is _PWN
    assert route(_ch("Reversing"), None) is _REV
    assert route(_ch("crypto"), None) is _CRYPTO
    assert route(_ch("forensics"), None) is _FORENSICS
    assert route(_ch("Steganography"), None) is _FORENSICS
    assert route(_ch("web"), None) is _WEB
    assert route(_ch("mobile/android"), None) is _MOBILE
    assert route(_ch("blockchain"), None) is _BLOCKCHAIN
    assert route(_ch("Smart Contract"), None) is _BLOCKCHAIN
    # "web3" must go to blockchain, not web (order matters).
    assert route(_ch("web3"), None) is _BLOCKCHAIN
    assert route(_ch("pyjail"), None) is _PYJAIL


def test_pyjail_profile_has_service_tools():
    assert {"connect", "send", "recv"} <= set(PyjailSpecialist().profile().by_name())


def test_fallback_by_connection_and_kind():
    # No category: a URL => web, a host:port => pwn.
    assert route(_ch(""), ConnInfo(url="http://t/")) is _WEB
    assert route(_ch(""), ConnInfo(host="t", port=1)) is _PWN
    assert route(_ch("", ChallengeKind.WEB), None) is _WEB
    assert route(_ch("", ChallengeKind.INTERACTIVE), None) is _PWN
    # Truly unknown -> generalist.
    assert route(_ch("misc"), None) is _GENERALIST
    assert route(_ch(""), None) is _GENERALIST


def test_every_profile_has_shell_and_valid_schemas():
    for spec in (RevSpecialist(), PwnSpecialist(), CryptoSpecialist(),
                 ForensicsSpecialist(), WebSpecialist(), MobileSpecialist(),
                 BlockchainSpecialist(), PyjailSpecialist(), GeneralistSpecialist()):
        prof = spec.profile()
        names = set(prof.by_name())
        assert "shell" in names and "write_file" in names
        for schema in prof.schemas():          # every tool advertises a JSON schema
            assert schema["name"] and "input_schema" in schema
        assert spec.system_prompt()            # non-empty playbook


def test_pwn_profile_has_service_tools_and_gdb():
    names = set(PwnSpecialist().profile().by_name())
    assert {"connect", "send", "recv", "gdb"} <= names


def test_web_profile_has_http():
    assert "http" in set(WebSpecialist().profile().by_name())


def test_network_challenges_go_to_forensics_not_pwn():
    # hidden-cipher (rehearsal): "Network" + a live box went to pwn by its port.
    from harness.platforms.base import ConnInfo
    ch = Challenge(id="c", name="hidden-cipher", category="Network, D-CTF 2025 Quals")
    spec = route(ch, ConnInfo(host="10.0.0.1", port=2222))
    assert spec.profile().name == "forensics"


def test_a_live_target_brings_its_tools_whatever_the_specialist():
    from harness.platforms.base import ConnInfo
    ch = Challenge(id="c", name="x", category="forensics")
    spec = route(ch, None)
    names = lambda p: {t.name for t in p.tools}
    assert "connect" not in names(spec.profile_for(None))
    assert {"connect", "send", "recv"} <= names(spec.profile_for(ConnInfo(host="h", port=1)))
    assert "http" in names(spec.profile_for(ConnInfo(url="http://h:1")))
