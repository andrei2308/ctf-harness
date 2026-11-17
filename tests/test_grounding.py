"""The confab guard is the most important rule: a flag counts only if it is in
real tool output. These tests pin that behaviour."""

from harness.flags.grounding import (EvidenceStore, extract_grounded,
                                      verify_candidate)

FLAG = "CTF{e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855}"


def test_flag_grounded_from_output():
    store = EvidenceStore()
    found = store.record("shell:cat flag", f"here it is: {FLAG}\n")
    assert len(found) == 1
    assert found[0].flag == FLAG
    assert found[0].source == "shell:cat flag"
    assert [g.flag for g in extract_grounded(store)] == [FLAG]


def test_model_prose_flag_rejected():
    """A flag the model merely wrote, never seen in output, must NOT verify."""
    store = EvidenceStore()
    store.record("shell:ls", "file1\nfile2\n")  # real output, no flag
    assert verify_candidate(store, FLAG) is None


def test_model_claim_verified_only_when_in_evidence():
    store = EvidenceStore()
    store.record("svc:recv", f"well done: {FLAG}")
    gf = verify_candidate(store, FLAG)
    assert gf is not None and gf.flag == FLAG


def test_flag_split_across_reads_is_caught():
    store = EvidenceStore()
    half = FLAG[: len(FLAG) // 2]
    rest = FLAG[len(FLAG) // 2:]
    assert store.record("svc:recv", half) == []           # not complete yet
    found = store.record("svc:recv", rest)                # completes across boundary
    assert any(g.flag == FLAG for g in found)


def test_latched_flag_survives_trim():
    store = EvidenceStore(max_bytes=512)
    store.record("svc:recv", FLAG)
    # Flood with more than max_bytes of junk to force trimming of old evidence.
    for _ in range(50):
        store.record("svc:recv", "x" * 100)
    assert any(g.flag == FLAG for g in store.grounded_flags())


def test_duplicate_flag_reported_once():
    store = EvidenceStore()
    first = store.record("a", FLAG)
    second = store.record("b", FLAG)
    assert len(first) == 1 and second == []  # latched; not re-reported


def test_a_flag_body_cannot_span_prose_with_braces():
    # Rehearsal: a run-log line (one long JSON line) gave "CTF{, flag{, ...}".
    from harness.flags.grounding import EvidenceStore, flag_pattern
    s = EvidenceStore(pattern=flag_pattern())
    got = [g.flag for g in s.record("t", b'formats like CTF{, flag{, HTB{x} ... and CTF{real_one}')]
    assert "CTF{real_one}" in got and not any("flag{" in g for g in got)


def test_harness_source_examples_are_decoys():
    from harness.flags.decoys import known_decoys
    assert "CTF{...}" in known_decoys()           # e.g. the submit_flag description


def test_a_stated_hash_format_rules_out_lookalike_flags():
    # investigator (rehearsal): a planted "DCTF{Try Hard...}" sat next to the
    # real flag and went out as a wrong submission. Format: DCTF{sha256}.
    from harness.flags.grounding import EvidenceStore, flag_pattern, format_check
    real = "DCTF{" + "82c149f2" * 8 + "}"
    check = format_check("Flags to find:\n1. What is the flag? (format: DCTF{sha256})")
    s = EvidenceStore(pattern=flag_pattern(), accept=check)
    got = [g.flag for g in s.record("t", f"DCTF{{Try Hard Harder}} ... {real}".encode())]
    # The default pattern yields bare and prefixed forms; both are judged.
    assert real in got and not any("Try Hard" in g for g in got)
    assert s.rejected and all("Try Hard" in r for r in s.rejected)


def test_format_check_reads_common_hints_and_stays_out_of_the_way_otherwise():
    from harness.flags.grounding import format_check
    assert format_check("format: ctf{sha256(flag)}")("ctf{" + "a" * 64 + "}")
    assert not format_check("format: ctf{sha256(flag)}")("ctf{password}")
    assert format_check("CTF{md5}")("CTF{" + "0" * 32 + "}")
    assert format_check("Find the flag.") is None
    assert format_check("Flag format: CTF{...}") is None


def test_format_check_reads_sha256sum():
    # DefCamp CTF 2025 (task 8, read-only): "format: ctf{sha256sum}".
    from harness.flags.grounding import format_check
    chk = format_check("1. What is the flag? (format: ctf{sha256sum})")
    assert chk and chk("ctf{" + "a" * 64 + "}") and not chk("ctf{try_harder}")


def test_a_letters_prefix_is_tried_first_and_digits_padding_last(monkeypatch):
    # Contest mode on investigator: bare CTF{...} went out first and was wrong;
    # the DCTF{...} the program printed was right.
    from harness.flags.grounding import EvidenceStore, flag_pattern
    monkeypatch.delenv("CTF_FLAG_REGEX", raising=False)
    got = [g.flag for g in EvidenceStore(pattern=flag_pattern()).record("t", b"x DCTF{abc} y")]
    assert got == ["DCTF{abc}", "CTF{abc}"]
    got = [g.flag for g in EvidenceStore(pattern=flag_pattern()).record("t", b"00de3CTF{abc}")]
    assert got[0] == "CTF{abc}"


def test_junk_bodies_are_never_candidates():
    # luma-lacks-love: a whitespace placeholder and a bytes repr went out.
    from harness.flags.grounding import EvidenceStore, flag_pattern
    s = EvidenceStore(pattern=flag_pattern())
    got = [g.flag for g in s.record("t", b"CTF{" + b" " * 27 + b"} b'CTF{\\x98\\xb8\\x01}' CTF{4dm1t_real}")]
    assert got == ["CTF{4dm1t_real}"]


def test_a_stated_length_regex_is_enforced():
    from harness.flags.grounding import format_check
    chk = format_check("1. What is the flag? (format: CTF{.{27}} (a regex for the length))")
    assert chk("CTF{" + "a" * 27 + "}") and not chk("CTF{this_is_a_decoy}")


def test_a_value_the_command_itself_carried_does_not_ground():
    # zodiac (pre-freeze, offline suite): the model printed its own guesses,
    # `python3 -c "for f in ['ctf{a}', ...]: print(f)"` and `echo "ctf{b}"`;
    # each was latched as grounded and auto-submitted (7 wrong).
    from harness.flags.grounding import EvidenceStore
    s = EvidenceStore()
    assert s.record("shell:echo", b"ctf{my_guess}\n", cmd='echo "ctf{my_guess}"') == []
    assert s.record("shell:python3", b"ctf{one}\nctf{two}\n",
                    cmd='{"cmd":"python3 -c \\"for f in [\'ctf{one}\', \'ctf{two}\']: print(f)\\"","timeout":30}') == []
    assert s.contains("ctf{my_guess}") is None          # a prose claim of it is not grounded either
    assert s.contains_independent("ctf{one}") is None
    # A command that did not contain it grounds it, even after the echo.
    got = s.record("shell:./chall", b"you win: ctf{my_guess}\n", cmd="./chall < in.txt")
    assert [g.flag for g in got] == ["ctf{my_guess}"]
    assert s.contains("ctf{my_guess}") is not None
    # Quotes inside a value are matched in JSON-escaped arguments too.
    t = EvidenceStore()
    assert t.record("shell:x", b'ctf{say "hi"}', cmd='{"cmd":"echo \'ctf{say \\"hi\\"}\'","timeout":5}') == []
    # Decoding something is not printing a literal: grounded.
    cmd = "python3 -c \"print(bytes.fromhex('6374667b6465636f6465647d').decode())\""
    assert [g.flag for g in t.record("shell:py", b"ctf{decoded}", cmd=cmd)] == ["ctf{decoded}"]
