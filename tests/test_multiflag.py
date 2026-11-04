"""Multi-flag / staged submission — the exact gap that beat the organizers' own
agent (it found flags it could not submit). These pin the new behaviour."""

import tempfile

from harness.flags.grounding import GroundedFlag
from harness.flags.submit import FlagSubmitter
from harness.platforms.base import Platform, SubmitResult
from harness.telemetry.run_log import RunLog


class _Plat(Platform):
    """Grades against a fixed set of acceptable flags; stateless per call."""

    def __init__(self, accept: set[str], solved_on=None):
        self.accept = accept
        self.solved_on = solved_on  # flag that makes the platform report challenge_solved
        self.calls = []

    def list_challenges(self): return []
    def get_challenge(self, cid): ...
    def download_files(self, cid, dest): return []
    def start_instance(self, cid): ...
    def get_conn_info(self, cid): ...

    def submit_flag(self, cid, flag):
        self.calls.append(flag)
        ok = flag in self.accept
        return SubmitResult(accepted=ok,
                            challenge_solved=(flag == self.solved_on))


def _gf(flag):
    return GroundedFlag(flag=flag, raw=flag.encode(), source="file:x", evidence_seq=1)


def test_challenge_not_solved_until_all_flags_in():
    with tempfile.TemporaryDirectory() as d:
        log = RunLog(d)
        plat = _Plat(accept={"CTF{a}", "CTF{b}"})
        sub = FlagSubmitter(plat, log)
        sub.register("c1", flags_required=2)

        sub.submit("c1", _gf("CTF{a}"))
        assert not sub.is_solved("c1")            # one of two
        assert sub.accepted_count("c1") == 1

        sub.submit("c1", _gf("CTF{b}"))
        assert sub.is_solved("c1")                # both in
        assert sub.accepted_count("c1") == 2
        log.close()


def test_platform_challenge_solved_flag_short_circuits_count():
    with tempfile.TemporaryDirectory() as d:
        log = RunLog(d)
        # required says 3, but the platform reports the challenge done after one.
        plat = _Plat(accept={"CTF{only}"}, solved_on="CTF{only}")
        sub = FlagSubmitter(plat, log)
        sub.register("c1", flags_required=3)
        sub.submit("c1", _gf("CTF{only}"))
        assert sub.is_solved("c1")
        log.close()


def test_rejected_flag_retried_when_not_penalized():
    with tempfile.TemporaryDirectory() as d:
        log = RunLog(d)
        plat = _Plat(accept=set())                # grader rejects everything
        sub = FlagSubmitter(plat, log, penalize_wrong=False, max_submits_per_flag=3)
        for _ in range(5):
            sub.submit("c1", _gf("CTF{x}"))
        assert len(plat.calls) == 3               # bounded retries, then suppressed
        log.close()


def test_penalize_wrong_submits_each_flag_once():
    with tempfile.TemporaryDirectory() as d:
        log = RunLog(d)
        plat = _Plat(accept=set())
        sub = FlagSubmitter(plat, log, penalize_wrong=True)
        for _ in range(5):
            sub.submit("c1", _gf("CTF{x}"))
        assert len(plat.calls) == 1               # exactly one attempt per flag
        log.close()


def test_accepted_flag_not_resubmitted():
    with tempfile.TemporaryDirectory() as d:
        log = RunLog(d)
        plat = _Plat(accept={"CTF{a}"})
        sub = FlagSubmitter(plat, log)
        sub.register("c1", flags_required=2)
        sub.submit("c1", _gf("CTF{a}"))
        sub.submit("c1", _gf("CTF{a}"))           # already accepted
        assert plat.calls == ["CTF{a}"]
        log.close()
