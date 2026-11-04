import tempfile

from harness.flags.grounding import GroundedFlag
from harness.flags.submit import FlagSubmitter
from harness.platforms.base import Platform, SubmitResult
from harness.telemetry.run_log import RunLog

FLAG = "CTF{abc}"


class _RecordingPlatform(Platform):
    def __init__(self, accept=True):
        self.calls = []
        self._accept = accept

    def list_challenges(self): return []
    def get_challenge(self, cid): ...
    def download_files(self, cid, dest): return []
    def start_instance(self, cid): ...
    def get_conn_info(self, cid): ...

    def submit_flag(self, cid, flag):
        self.calls.append((cid, flag))
        return SubmitResult(accepted=self._accept)


def _gf(flag=FLAG):
    return GroundedFlag(flag=flag, raw=flag.encode(), source="svc:recv", evidence_seq=1)


def test_submits_grounded_flag_and_marks_solved():
    with tempfile.TemporaryDirectory() as d:
        log = RunLog(d)
        plat = _RecordingPlatform(accept=True)
        sub = FlagSubmitter(plat, log)
        res = sub.submit("c1", _gf())
        assert res.accepted and sub.is_solved("c1")
        assert plat.calls == [("c1", FLAG)]
        log.close()


def test_rejected_flag_retry_is_bounded():
    # A not-yet-accepted (rejected) flag may be retried for staged challenges,
    # but only up to max_submits_per_flag, then it is suppressed.
    with tempfile.TemporaryDirectory() as d:
        log = RunLog(d)
        plat = _RecordingPlatform(accept=False)
        sub = FlagSubmitter(plat, log, max_submits_per_flag=2)
        for _ in range(5):
            sub.submit("c1", _gf())
        assert len(plat.calls) == 2
        log.close()


def test_penalize_wrong_disables_resubmit():
    with tempfile.TemporaryDirectory() as d:
        log = RunLog(d)
        plat = _RecordingPlatform(accept=False)
        sub = FlagSubmitter(plat, log, penalize_wrong=True)
        sub.submit("c1", _gf())
        sub.submit("c1", _gf())                 # suppressed: one attempt per flag
        assert len(plat.calls) == 1
        log.close()


def test_short_circuits_when_already_solved():
    with tempfile.TemporaryDirectory() as d:
        log = RunLog(d)
        plat = _RecordingPlatform(accept=True)
        sub = FlagSubmitter(plat, log)
        sub.submit("c1", _gf("CTF{one}"))       # solves c1
        sub.submit("c1", _gf("CTF{two}"))       # different flag, but already solved
        assert len(plat.calls) == 1             # no second platform call
        log.close()


def test_dry_run_never_calls_platform():
    with tempfile.TemporaryDirectory() as d:
        log = RunLog(d)
        plat = _RecordingPlatform(accept=True)
        sub = FlagSubmitter(plat, log, dry_run=True)
        res = sub.submit("c1", _gf())
        assert res.accepted and plat.calls == []
        log.close()
