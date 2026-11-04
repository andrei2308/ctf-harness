import pytest

from harness.inference.base import Usage
from harness.scheduler.budget import Budget, BudgetExceeded, Caps


def test_global_token_cap_raises():
    b = Budget(Caps(total_tokens=100))
    b.charge_usage("c1", Usage(input=60, output=50))  # 110 > 100
    with pytest.raises(BudgetExceeded) as ei:
        b.check("c1")
    assert ei.value.scope == "global" and ei.value.resource == "tokens"


def test_per_challenge_cutoff():
    b = Budget(Caps(per_challenge_tokens=100))
    b.charge_usage("c1", Usage(input=80, output=40))
    assert b.challenge_exhausted("c1")
    assert not b.challenge_exhausted("c2")


def test_per_attempt_park_signal():
    b = Budget(Caps(per_attempt_tokens=100))
    b.start_attempt("c1")
    b.charge_usage("c1", Usage(input=90, output=5))
    assert b.should_park("c1", floor=0.1)        # <=10% of attempt slice left
    b.start_attempt("c1")                         # resume resets the attempt slice
    assert not b.should_park("c1", floor=0.1)


def test_cached_input_excluded_when_configured():
    b = Budget(Caps(total_tokens=1000, count_cached_input=False))
    b.charge_usage("c1", Usage(input=500, output=10, cached_in=480))  # billable_in=20
    snap = b.snapshot()
    assert snap["global_tokens"] == 30  # 20 billable in + 10 out


def test_per_challenge_totals_persist_across_attempts():
    b = Budget(Caps())
    b.start_attempt("c1")
    b.charge_usage("c1", Usage(input=10, output=10))
    b.start_attempt("c1")                         # new attempt slice
    b.charge_usage("c1", Usage(input=5, output=5))
    assert b.snapshot()["per_challenge"]["c1"]["tokens"] == 30
