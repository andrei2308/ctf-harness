# Final report: the round before the freeze

Work done per `CLAUDE_CODE_FINAL.md` on 2026-11-17, branch
`contest-readiness`. The freeze is 18 November, 20:00; the contest is on 19
and 20 November. Earlier rounds are in `VALIDATION_REPORT.md` and
`REHEARSAL_REPORT.md`.

**Verdict: ready to freeze.**
- The changes made after the rehearsal are verified on a real machine.
- The image carries the missing tools and runs in every sandbox shape tried.
- The contest configuration and the restart path have run with a real model.
- An adapter can be written from the skeleton in minutes.
- 15 harness defects were found and fixed in this round, each with a test
  (266 pass).
- Remaining: merging to `main`, which needs Andrei's go-ahead (question 5).

## Tasks

| # | Task | Result | Key numbers |
|---|---|---|---|
| 1 | Verify the post-rehearsal changes | PASS, 3 defects fixed | Guards: an ordinary `curl … 2>/dev/null` runs; another port, a whole-host scan and the harness tree are refused. A hanging model stops at 121 s of 120. Starts and solves under `--read-only`, `--user 1000:1000`, and both |
| 2 | Tools and new base | PASS | Base 14.27 → 15.09 GB (tools layer 95 s, no WARN). `check_image` 74/74 as root, read-only, uid 1000 and `--cap-drop NET_RAW`. Backup 5.75 GB in 645 s; old base kept as `base-1115` |
| 3 | Offline suite | PASS | 6 challenges, hashes only (each verified against the logged accepted preview), outside the repo. Network: the model only |
| 4 | Measure time; test the prompt change | DONE | 1,556 turns: median 9 s, p99 132 s. Old vs new: 10/12 solved each; median solve 132 s (new) vs 220 s (old); tool calls per turn 1.12 vs 1.13 |
| 5 | Contest mode and restarts, offline | DONE, 2 defects fixed | Contest mode 5/6 solved. The handover notes carry exact facts; a fresh context at every rung change doubles wall time |
| 6 | Second CyberEDU batch | DONE, 4 defects fixed | 4 of 10 new challenges solved (crypto 3/3, rev 1/3, pwn 0/2, web 0/2; 1 run invalidated by a GLM rate limit); 0 of 2 re-runs |
| 7 | Adapter drill | PASS, 3 frictions fixed | `adapter_check` passed about 25 s after the adapter was saved; a full solve with GLM in 40 s |
| 8 | Contest mode, read-only | PASS, 1 fix | DefCamp CTF 2025 Quals: 26 challenges, a file and the questions read; 0 failed |
| 9 | Freeze | see the end | |

## Changes, each with its reason

| Commit | Failure seen | Change |
|---|---|---|
| `c35d92d` | Ghidra could not start on a read-only root (`/root/.config`) | Its settings live in the work dir |
| `f487b9f` | nmap failed to `exec` under `--cap-drop NET_RAW` (file capabilities); forge and cast missing under `--user 1000`; ping, ss, ip, matplotlib and scipy missing (rehearsal logs) | File capabilities stripped; Foundry copied to `/usr/local/bin`; the tools added; `check_image` entries for each |
| `66ac91c` | Drill: a kit with `MOCK{…}` flags looked fine to `adapter_check`, so no flag would ever have been auto-submitted; one `submit_flag` over two questions got HTTP 429; the skeleton showed only a single submit | `adapter_check` warns on a format/pattern mismatch; `kit.Pacer`; per-question recipe; worked example `example_http.py` with its mock and tests |
| `5059c11` | Drill lessons | HANDOFF contest-day steps updated |
| `dd92fcd` | DefCamp 2025 states `ctf{sha256sum}`; the format check only knew `sha256` | `…sum` accepted |
| `81ac6b4` | Contest mode: bare `CTF{}` submitted before the printed `DCTF{}`; 22 guessed spellings on one challenge | A lettered prefix goes first; `CTF_MAX_GUESSES` (8) |
| `4af9b47` | Decisions needed numbers | `CTF_MODEL_TIMEOUT=180` and the rest in `contest.env`; reasoning tokens logged per turn |
| `e96972d` | luma-lacks-love: a whitespace placeholder and a bytes repr submitted | Junk bodies are never candidates; a stated `.{N}` length is enforced |
| `de3d9e5` | The GLM endpoint answered 429 for 2 minutes; the ladder burnt its rungs in a second | Rate limits back off 15 → 60 s, about 4.75 min, within the budget |
| `8454c22` | metar-station: a planted `CTF{try_harder…}` went out through `submit_flag` against a stated `UNBRK{sha256}` | A flag-shaped `submit_flag` value must meet the stated format |
| `3e41a13` | stayin-alive: `nohup ffuf -t 40 &` knocked the challenge service over | Backgrounded scanners refused; the web prompt asks for gentle scans |
| `424d348` | — | HANDOFF reflects the measured settings; `REHEARSAL_PROGRESS.md` removed |

## Task 4: time

From all logs of both rounds (1,556 completed model turns, GLM 5.3 Flash):

- **Seconds per turn:** median 9, p90 46, p95 70, p99 132, max 647.
- **Wall time:** 85% in model calls, 9% in tools, 6% elsewhere. The harness's
  own overhead is negligible.
- **Hung calls:** 20 timed out at 300 s, about 6,000 s with nothing returned.
  One 2400 s run (baby heap) lost over half its time this way.
- **Input tokens over a long run** (hidden-cipher, 72 turns): 3K → about
  30K. Growth is bounded, with visible dips where the history limits trim,
  but not flat.
- **Tool calls per turn:** about 1.0 in rehearsal. This was the baseline for
  batching.

Old (`3160925`) against new, on the offline suite, two runs of each challenge
per side, side by side:

| | Solved | Median time to solve | Median turns to solve | Tool calls / turn | Tokens |
|---|---|---|---|---|---|
| Old | 10/12 | 220 s | 7 | 1.13 | 3.67M |
| New | 10/12 | 132 s | 6 | 1.12 | 3.29M |

Both sides failed zodiac (a handwriting-reading variance; see below).
Per-challenge times move both ways at n = 2, so the faster median is
suggestive, not proven.

Decisions (in `contest.env`, with these numbers):

- **`CTF_MODEL_TIMEOUT=180`** (was 300). It keeps 99.4% of completed turns,
  and each hung call costs 120 s less.
- **Reasoning effort off.** GLM honours it (3.7 s and 83 output tokens per
  turn, against 6–16 s and 156–675 without), but erratically: 3 of 4 runs
  solved fast, and 1 collapsed (89 shallow turns, 7 wrong flags, token cap) on
  a challenge that always solves without it. It is a lever only for a very
  short time limit.
- **Batching prompt kept.** It had no measurable effect on tool calls per
  turn and did not make results worse.

## Task 5: the contest configuration and restarts

**Contest mode** (`CTF_PENALIZE_WRONG=0`, default flag pattern, offline
suite): 5 of 6 solved.
- **Wrong submissions:** investigator 1, a prefixed variant (bare `CTF{}`
  before the printed `DCTF{}`; fixed). zodiac 22, guessed spellings through
  prose and `submit_flag` (now capped at 8). All others 0.
- **Behaviour after feedback:** after a "NOT accepted" note the model
  re-examined its reading. After the late time note it kept working. Neither
  made it give up.

**Restarts** (`CTF_LADDER_DEPTHS=3,3,3,3`, 3 top-rung restarts):
- **Do the handover notes carry the right facts? Yes.** They hold exact values
  (file names and sizes, stream numbers, ZIP offsets, the commands that
  produced them, what failed, rejected spellings).
- **Does the next attempt use them? Yes.** Each attempt built on the last
  (carving → ADB framing interleaved → clean payloads via `tcpflow`) and
  never redid the triage.
- **Limit:** images do not cross a restart, so visual work is redone (zodiac).
- **Cost:** one note-writing call per restart, 17–28 s.
- **Do clean-context restarts help?** As the last resort after the ladder,
  yes: progress continued across all three. A clean context at **every** rung
  change (`CTF_FRESH_CONTEXT=1`) gave the same 21 turns in 677 s against
  345 s, for similar progress. It stays off.

## Task 6: second CyberEDU batch

Mostly Medium, at least 3 each of pwn, rev and crypto, plus 2 Easy web, run
one at a time with the firewall on and `CTF_PENALIZE_WRONG=1`.

| Challenge | Category | Result | Time | Tokens | What decided it |
|---|---|---|---|---|---|
| merchandise | crypto | **solved** | 188 s | 27K | — |
| luma-lacks-love | crypto | **solved** | 1110 s | 431K | 3 junk submissions first (fixed `e96972d`) |
| binary-stuff | crypto | **solved** | 920 s | 326K | — |
| friendly-admin | rev | **solved** | 460 s | 155K | — |
| crack-me | rev | unsolved | 1202 s | 775K | Model limit (a C++ keygen); the time note focused it |
| lost_message_v2 | rev | unsolved | 1202 s | 1.17M | Model limit (two-layer cipher) |
| baby heap | pwn | unsolved | 2401 s | 568K | 8 model timeouts at 300 s, over half the run (180 s cap now) |
| string-comparer | pwn | unsolved | 1202 s | 224K | Model limit (ROP under a `tolower` constraint); 5 timeouts |
| boogie-woogie | pwn | invalid | — | 26K | GLM rate limit (429) hit the run; not a result |
| metar-station | web | unsolved | 1202 s | 320K | A planted flag pushed through `submit_flag` (fixed `8454c22`) |
| stayin-alive | web | unsolved | 1203 s | 199K | A background `ffuf` knocked the service over (fixed `3e41a13`) |
| badimg (re-run, 2400 s) | web | unsolved | 2402 s | 1.11M | Further than both 1200 s runs (the exact include logic, the DB seed file), no solve |
| fair-dice (re-run) | misc | unsolved | 1202 s | 396K | Now routed to the generalist; model limit (bot socket handling, game maths) |

**What 2400 s buys:** on baby heap and badimg, deeper progress but no solve; on baby heap, 8 hung model calls ate over half of it. Every unsolved run in both batches ended on time while still working, so a longer contest limit should help, but no challenge here flipped by doubling it.

## What is still unverified

- **The contest model, its limits and the starter kit.** All settings were
  measured on GLM 5.3 Flash. Re-check `CTF_MODEL_TIMEOUT` against the contest
  model's preflight timings.
- **CyberEDU contest mode beyond reading.** Starting a contest service and
  submitting were not exercised.
- **The contest configuration on live challenges.** It ran offline only, to
  keep junk off the account.
- **The agent runs as the same user as the harness.** Secrets are scrubbed and
  the boundaries held in every test; a separate user would close it (out of
  scope).
- **gdb cannot disable ASLR** under Docker's default seccomp profile.
- **Optional MCP-over-HTTP drill:** not done.
- **zodiac is a noisy benchmark.** Its answer depends on reading handwriting
  exactly, punctuation included. It failed offline on both sides alike; the
  stored hash matches the live accepted flag's preview.

## Where things are

- **Branch:** `contest-readiness`; `main` untouched.
- **Images:** `ctf-harness:base` (new), `ctf-harness:base-1115` (old),
  `ctf-harness:latest`, `ctf-harness:rehearsal`.
- **Backups:** `~/ctf-harness-base.tar.gz` (new) and
  `~/ctf-harness-base-1115.tar.gz`.
- **Offline suite and all logs:** `~/Desktop/ctf-rehearsal/` (outside the
  repo).

## Freeze

Done on 2026-11-17, well ahead of the 18 November 20:00 deadline:

- **`contest.env`:** the measured recommendations, each commented with its
  numbers (timeout, effort, batching, fresh context, output floor, guesses).
- **`HANDOFF.md`:** brought up to date; its contest-day steps were checked
  against the adapter drill.
- **`REHEARSAL_PROGRESS.md`:** deleted.
- **Last rebuild:** `docker build --no-cache -f Dockerfile.contest` took 2 s.
  `check_image.py` passes 74/74 with 0 critical failures; the tests pass
  266/266 on the host and in the image.
- **Base:** unchanged since its backup (`03a62b9…`, saved at 11:51), so
  `~/ctf-harness-base.tar.gz` is current.
- **Merge:** fast-forwarding `main` to this branch waits for Andrei's
  go-ahead (question 5).

After the freeze, only `contest.env` and `harness/platforms/starter_kit.py`
change.

## Addendum: the pre-freeze check (`CLAUDE_CODE_PREFREEZE.md`)

Done on the evening of 17 November, on `a820595` and the fixes below.

### Task 1: verifying the new commit

- **Tests:** 280 pass on the host and in the image; `check_image` 74/74.
- **Scanner guard, live** (badimg instance, firewall on):
  - these now run: a hydra `http-post-form` attack with a quoted `&`,
    `ffuf -u 'http://h/?a=FUZZ&b=2'` and `wfuzz -d "a=FUZZ&b=1"`;
  - `nohup ffuf … &` is still refused.
- **Hanging endpoint, `CTF_TOTAL_SECONDS=120`:** the run ended at 121 s, with
  20 `solver.model_timeout` events and no `solver.model_retry`.
- **Preflight check 8 against GLM:** "about 29 tokens/s … set
  `CTF_MAX_OUTPUT_TOKENS=4096`". Two problems:
  - **The estimate reads low.** One 275-token reply includes about 5 s of
    fixed latency. Replies that ran to their cap in the logs went at
    40–63 tokens/s (median over turns of 20 s or more: 42).
  - **The advice was harmful.** The cap wins over `CTF_MIN_OUTPUT_TOKENS`, so
    4096 would undo check 6's 8192 floor and bring back the turns GLM thinks
    away. Fixed (`8dd0c7d`): check 8 never advises less than the floor.

### Task 2: the timeouts, from the logs

80 runs, 1,986 turns, both rounds:

| | |
|---|---|
| "Timed out" retries in the logs | 48 |
| … calls cut short by the time left, at the end of a run (1–94 s) | 37 |
| … calls that ran to the full limit (300 s ×8, 180 s ×3), in 7 episodes | 11 |
| Output cap of those 11 | 8192 in every case (rungs 0–1); none at 16K or 32K |
| Same request sent again after a full-length timeout | answered in 8–126 s (392–4,743 tokens) in 6 of 7 episodes; the 7th (boogie-woogie) was just before the 429 outage |
| Output speed, completed turns ≥ 20 s | median 42 tokens/s (p10 31, p90 51); the same on every rung |
| Turns that ran to the 8192 cap | 7, taking 130–202 s |
| Completed turns over 300 s | turns whose `seconds` include their failed tries (647 s = 300 + 302 + a 45 s reply of 1,505 tokens), or a single call at 2–17 tokens/s on the first night. None was a 32K reply |

**Verdict: an endpoint that stops answering, not replies too long to
finish.** At 42 tokens/s a full 8192-token reply ends well inside 300 s, and
the same request answered quickly when sent again.

What that means for the new commit:

- **The note to the model is harmless.** The call after it is what recovers
  a stall, as the identical retry did before.
- **The cap reduction does not help.** Every stall happened at the 8192
  floor, so nothing is halved.
- **One side effect, deliberate in the commit and asserted by its test, so
  left for Mythos to decide:** after one stall at the floor,
  `output_ceiling` stays at 8192 for the rest of the challenge. That clamps
  rungs 2 and 3 and the cut-off raise. In the logs no rung-2 turn used more
  than 6,876 tokens, so the cost is small, but it buys nothing.
- **`CTF_MODEL_TIMEOUT=180` stays.** It cuts a stall sooner. The comment in
  `contest.env` now says what the timeouts were (`ea7f773`), and no
  `CTF_MAX_OUTPUT_TOKENS` is set for GLM.

### Task 3: three live pwn runs at 1200 s

| Challenge | Before | Now | Result |
|---|---|---|---|
| baby heap | 5 timeouts at 300 s (about 1,500 s lost, in a 2400 s run) | 2 at 180 s (360 s lost) | unsolved |
| string-comparer | 5 timeouts at 180 s | 1 at 180 s (180 s lost) | unsolved |
| boogie-woogie | 3 at 300 s (900 s lost), then a 429 outage | 2 at 180 s (360 s lost) | unsolved |

- **Pass condition:** less time lost to calls that return nothing. Met on
  all three.
- **The note:** after it, the next call answered in 4.5 s with 155 tokens on
  baby heap. That fits a stall that cleared and is also what the note asks
  for.
- **No cap was halved;** all stalls happened at the floor.

**A defect these runs exposed, fixed (`e728c60`).** In the last 20 s (the
reserve) every model request got a 1 s timeout and failed. Three in a row end
an attempt, so the ladder climbed through every rung and restart in seconds:
string-comparer started 19 of its 21 attempts in its last 20 s. This made
about 20 doomed requests to the shared endpoint at the end of every challenge,
and the summaries reported `top_rung 3` for runs that never worked past rung
1. The solver now ends the attempt as exhausted once less than 5 s remains
beyond the reserve, after flushing any pending flag.

### Task 4: regression

**Offline suite on `ea7f773`: 5 of 6 solved, as before, zodiac excepted.**

| Challenge | Time | Wrong submissions |
|---|---|---|
| encryptor | 61 s | 0 |
| bdlp | 108 s | 0 |
| investigator | 351 s | 0 |
| adding-in-parts | 475 s | 2: grounded bare strings through `submit_flag`, allowed since no format is stated; model variance |
| wifi-get-me | 59 s | 0 |

**Zodiac exposed a defect, fixed (`cfc1ec9`).**
- **What happened:** 7 of its 10 wrong submissions were the model printing
  its own guesses (`python3 -c "for f in ['ctf{…}', …]: print(f)"`,
  `echo "ctf{…}"`). Each printed value was latched as grounded and
  auto-submitted, getting past both the penalty guard and
  `CTF_MAX_GUESSES`.
- **The fix:** a value the producing command itself carries no longer
  grounds a flag, whether found automatically or claimed in prose.
  `submit_flag` already had this rule.
- **Tests:** the test fakes that echoed their argument now take it
  hex-wrapped (`tests/echo_fake.py`).

**Final suite run on `e728c60`:**

| Challenge | Result | Wrong submissions |
|---|---|---|
| encryptor | solved, 75 s | 0 |
| bdlp | solved, 58 s | 0 |
| wifi-get-me | solved, 55 s | 0 |
| adding-in-parts | solved, 785 s | 4: format guesses for recovered data, including a `CTF{…}` computed from it, which correctly still grounds; no format is stated |
| investigator | unsolved (1.5M token cap), then solved on a re-run in 322 s | 0 |
| zodiac | unsolved, as expected | 3 (instead of 10) |

- **investigator:** the first run is model variance, not the fix. The real
  flag never appeared in tool output; the only flag-shaped string was the
  planted decoy, which its command did not contain.
- **zodiac:** all 3 wrong submissions were built from words read off the
  image, the only route to an image-read answer. No literal guesses remain.
  It ended at 1180 s on "time left is the reserve" after 3 attempts,
  against 22 that churned at the end before. Both fixes are visible.

**Note on the 429s:** the suite and the live runs shared the GLM quota in
parallel. Both runs that ended on "429" did so in their last seconds, where
the 15 s backoff cannot fit, by design.

### Freeze state

- **Commits after `a820595`, each with a regression test:**
  - `8dd0c7d` check 8 never advises a cap below the floor
  - `ea7f773` the `contest.env` timeout comment matches the logs
  - `cfc1ec9` a value the command itself carried never grounds a flag
  - `e728c60` no model call inside the reserve
- **Checks:** 283 tests pass on the host and in the image. The no-cache
  contest rebuild took 2 s; `check_image` 74/74.
- **Base:** unchanged (`03a62b9…`), so `~/ctf-harness-base.tar.gz` is still
  current.
- **Tokens this round:** about 21M of the 30M agreed.
- **Merge:** fast-forwarding `main` to this branch waits for Andrei's
  go-ahead.
- **After that,** only `contest.env` and `harness/platforms/starter_kit.py`
  change.
- **Still for Andrei:**
  - rotate the CyberEDU session cookie (the last run is done);
  - time a 6 GB upload on the phone connection;
  - no Kali upgrade and no Docker prune before the contest.

### After the addendum: the decision left open (Mythos, 17 November)

The logs settled it: the timeouts were endpoint stalls, so the pre-freeze
commit's reaction to a timeout was aimed at the wrong cause. Changed on
`contest-readiness`:

- **One timeout is retried as it was, at once.** No note to the model, no
  change to the output cap. This is what recovered 6 of 7 episodes.
- **From the second timeout in a row** the request is the suspect: the model
  is told once, and a cap above 8192 is halved.
- **A cap that was not lowered leaves no ceiling.** A stall at the 8192 floor
  no longer clamps rungs 2 and 3 or the cut-off raise for the rest of the
  challenge.

Verified the same evening (Claude Code):

- **Tests and image:** 283 pass on the host and in the rebuilt image;
  `check_image` 74/74.
- **Hanging endpoint** (`CTF_TOTAL_SECONDS=120`, `CTF_MODEL_TIMEOUT=10`):
  - each attempt went T1 (retried unchanged), T2, T3, then ended as an
    error; after three such attempts the ladder moved up a rung;
  - the run stopped at 100 s, on reaching the reserve, with no requests
    inside it;
  - the cap (4096) was never lowered, as it was at or below 8192.
- **Real model (GLM):** wifi-get-me solved in 32 s and encryptor in 70 s,
  1 submission each, no wrong ones.

