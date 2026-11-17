# Last check before the freeze: instructions for Claude Code

You are on Andrei's Kali machine, in the `ctf-harness` repo. `main` holds the
work of `FINAL_REPORT.md`. Branch `contest-readiness` is one commit ahead of it,
written after reviewing that report, without Docker and without a real model.
Verify that commit, answer one question from the logs, then merge and freeze.

The freeze is still 18 November, 20:00. This should take a few hours, not a day.
The ground rules of the earlier briefs apply.

## Review of the final round

The round is accepted as it stands: the image, the sandbox shapes, the offline
suite, the measurements and the drill are what was asked for. Two things came
out of the review.

**1. The background-scanner guard (`3e41a13`) refused ordinary web commands.**
It looked for a lone `&` anywhere in the command, including inside quotes:

| Command | Was |
|---|---|
| `hydra -l admin -P p.txt h http-post-form "/login:user=^USER^&pass=^PASS^:F=bad"` | refused |
| `ffuf -u 'http://h/?a=FUZZ&b=2' -w w.txt` | refused |
| `wfuzz -d "a=FUZZ&b=1" http://h/` | refused |

Every hydra form attack contains an `&`. Fixed: quoted strings are set aside
before the test. This is the second guard to misfire on normal commands (the
scope guard was the first). When adding a guard, test it against the ordinary
commands of that tool family, not only against the case that motivated it.

**2. The timeouts are probably not hangs.** The report counts 20 model calls
that "hung" to the 300 s limit, about 6,000 s, and lowers the limit to 180 s.
The numbers point somewhere else:

- Completed turns: p99 132 s, and only 9 between 180 and 300 s, yet 20 beyond
  300 s. A plain slow tail would not look like that.
- The longest completed turn before the cap was 647 s. At roughly 50 output
  tokens a second, that is a full 32,768-token reply, which is rung 3's cap.
  A full rung 2 reply (16,384) would take about 330 s: past the limit.
- They cluster on pwn (baby heap 8, string-comparer 5), where the model
  reasons longest, and baby heap ran long enough to reach the upper rungs.

So the likely cause is the reply itself: a long chain of reasoning at a 16K or
32K output cap that cannot finish inside the request limit. If so, lowering
the limit to 180 s kills such a turn sooner but does not stop it recurring,
and the solver then re-sent the identical request, up to five times.

## What the new commit changes

- **Scanner guard:** an `&` inside quotes is data (`harness/agents/tools.py`).
- **Timeouts** (`harness/agents/base.py`): a timed-out call is no longer
  retried as it was. The model is told once that its reply took too long and
  asked for a short plan and a tool call; the output cap is halved, not below
  8192; the lower cap carries to later rungs and bounds the cut-off raise.
  Three in a row still end the attempt as an error. Adapters raise
  `ModelTimeout` for this case.
- **Preflight check 8** (a warning): estimates output tokens per second and
  says whether a full-length reply fits inside `CTF_MODEL_TIMEOUT`, with the
  `CTF_MAX_OUTPUT_TOKENS` value that would.

280 tests pass on the host.

## Tasks

### 1. Verify

```bash
git fetch origin && git checkout contest-readiness && git pull
python -m pytest -q                                  # expect 280 passed
docker build -f Dockerfile.contest -t ctf-harness:latest .
docker run --rm ctf-harness:latest python -m pytest -q
docker run --rm ctf-harness:latest python scripts/check_image.py
```

- In the rehearsal image, against one live web instance: a hydra form attack
  and an `ffuf` with a quoted `&` run; `nohup ffuf ... &` is still refused.
- With the hanging endpoint from the last round and `CTF_TOTAL_SECONDS=120`:
  the run still ends on time, the log shows `solver.model_timeout` events and
  no `solver.model_retry` for them.
- `python -m harness.preflight` against GLM: read check 8. Is its speed
  estimate near what the logs say (next task)?

### 2. Settle the timeout question from the logs

No new runs needed. From the logs of both rounds:

- For each timed-out call: the challenge, the rung and its `max_tokens`, the
  input size, and whether the next call was the same turn again (and whether
  that one timed out too).
- Output tokens per second over completed turns, by rung: median and range.
- The completed turns longer than 120 s: their output and reasoning tokens.
  Are they near their rung's cap?

Then state which it is: replies too long to finish, or an endpoint that stops
answering. If the first, the fix in this commit is the right one and
`CTF_MAX_OUTPUT_TOKENS` for GLM is roughly 0.8 x speed x 180: write that
number into the comment in `contest.env`. Leave the setting commented out:
it depends on the contest model, and preflight check 8 gives it on the day. If
the second, say so plainly; the note to the model is then harmless but the cap
reduction is not helping, and it should be reported.

### 3. One live confirmation

baby heap and string-comparer are unsolved on the account, so they can be run
again. Run each once at 1200 s on the new commit. Count the timeout events and
the seconds lost to them, against 8 and 5 before. boogie-woogie lost its run
to a rate limit and never got a result: give it its run too.

A solve is not the pass condition here. Less time lost to calls that return
nothing is.

### 4. Regression, merge, freeze

- Run the offline suite once on the new commit: it should solve what it
  solved before (zodiac excepted).
- Add a short addendum to `FINAL_REPORT.md`: what tasks 1 to 3 showed.
- Rebuild with `Dockerfile.contest`; `check_image.py` and the in-image tests
  one last time.
- With Andrei's go-ahead, fast-forward `main` to this branch and push.

After that, only `contest.env` and `harness/platforms/starter_kit.py` change.

## If something here is wrong

If the timeout change makes the offline suite or the live runs worse, revert
that part (`_after_timeout` and the `ModelTimeout` branch in `Solver.run`),
keep the scanner-guard fix and the preflight check, and say what you saw.

## Still open, for Andrei rather than for you

- Rotate the CyberEDU session cookie once the last run is done.
- The upload: 15 GB as an image, 5.75 GB compressed. Time a 6 GB upload on a
  phone connection before the day.
- No Kali upgrade and no Docker prune before the contest.
