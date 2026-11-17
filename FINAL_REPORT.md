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
