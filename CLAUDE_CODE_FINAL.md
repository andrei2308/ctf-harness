# Final preparation before the freeze: instructions for Claude Code

You are on Andrei's Kali machine, in the `ctf-harness` repo, on branch
`contest-readiness`. The contest is on 19 and 20 November. This is the last
round of work: verify the changes made after your rehearsal report, add the
missing tools to the image, test the paths the rehearsal never reached, and
freeze.

Read `REHEARSAL_REPORT.md` (yours), then `HANDOFF.md`, whose "Contest day, step
by step" section is new. The ground rules of `CLAUDE_CODE_REHEARSAL.md` still
apply.

## Review of the rehearsal work

The rehearsal did its job: 20 defects found on real challenges, each fixed with
a test, and a report that separates harness failures from model limits. All of
it is kept. The review found six things to correct or finish.

| # | Finding | Status |
|---|---|---|
| 1 | **The shell guard refuses ordinary commands.** `curl -s http://host 2>/dev/null` and `ping -c 1 host 2>&1` were refused because the `2` of a redirection was read as a port. It also refused `nmap` against a target given as a whole host. It is on in the contest image | Fixed, with a setting (`CTF_TARGET_SCOPE`). Verify live (task 1) |
| 2 | **Fix 18 (model calls capped by the time left) was half a fix.** The SDK client had `max_retries=1` and retries a timeout, so a capped call could still take twice its cap. The plan and handover-note calls were not capped at all | Fixed: no SDK retries, all three call sites capped. Verify (task 1) |
| 3 | **The model was never told what happened to a flag.** Submission is automatic and the result was dropped, so a rejected flag and an accepted one looked the same to it. A candidate dropped by the stated-format check vanished silently | Fixed: each result is appended to the tool output |
| 4 | **"Nothing in the harness" would help the out-of-time runs** is too strong. The prompt told the model to take "one concrete action per step" while turns were the binding limit, and the model could not see the clock | Changed: batched steps, the time budget in the task, one late note. Unmeasured (task 4) |
| 5 | **The contest configuration never ran.** All 23 runs used `CTF_PENALIZE_WRONG=1`. With it off, the harness submits ungrounded claims, both forms of a prefixed flag, and up to 20 explicit answers: code that has only met unit tests | Open (task 5) |
| 6 | **Two questions from the brief are unanswered:** whether clean-context restarts help and whether handover notes carry the right facts. No run got past rung 2. The contest's time limit is unknown, so that path may well run there | Open; now cheap to reach (task 5) |

The report also gives "15 to 30 s per turn" without a distribution. Task 4
asks for one, because the model timeout and the ladder depend on it.

## What changed since your last commit

One commit on `contest-readiness`, written without Docker and without a real
model. 253 tests pass on the host. Treat everything below as unverified.

- **Guards** (`harness/agents/tools.py`): the scope guard fix and setting; a new
  guard that refuses shell commands aimed at the harness's own tree (the
  knowledge base and the work dir are allowed; `CTF_GUARD_HARNESS=0` turns it
  off).
- **Solver** (`harness/agents/base.py`): submission results shown to the model;
  the time note; request caps on every model call.
- **Prompt** (`harness/agents/specialists.py`): batched steps; "the answer is
  never in the runner itself".
- **Submission** (`harness/flags/submit.py`): at least one second between two
  calls to the grader (`CTF_SUBMIT_MIN_INTERVAL`).
- **Robustness** (`harness/paths.py`): an unwritable work or log directory
  falls back to a temporary one; a failed log write no longer ends the run.
- **Settings** (`contest.env`): the work dir and the logs now live **outside the
  harness tree** (`/tmp/ctf-work`, `/var/tmp/ctf-logs`). New: `CTF_TARGET_SCOPE`,
  `CTF_LADDER_DEPTHS`, `CTF_VISION`.
- **Contest-day kit:** `harness/platforms/kit.py` (HTTP, downloads, address
  parsing, question text), a rewritten `starter_kit.py` skeleton carrying the
  rehearsal lessons, `python -m harness.adapter_check`, and a vision check in
  preflight (check 7, a warning).
- **Image:** `scripts/image_extras.sh` and `Dockerfile.tools` (task 2).

## Ground rules

- **Freeze: 18 November, 20:00.** After it, only `contest.env` and
  `harness/platforms/starter_kit.py` change. If a task cannot finish by then,
  stop it and report where it stands.
- Work on `contest-readiness`. Do not merge to `main` before task 9.
- No secret in any file, command line or committed log.
- Do not prune Docker. Keep the old base image tagged until the new one passes.
- One CyberEDU run at a time, firewall on, as before. Stay inside the token
  ceiling Andrei gives you.
- Every harness fix gets a regression test. No tuning to a single challenge.
- If something here is wrong or cannot work as written, fix it and say so in
  the report. Do not work around it silently.

## Tasks

### 1. Take the changes and verify them

```bash
git pull
python -m pytest -q                         # expect 253 passed
docker build -f Dockerfile.contest -t ctf-harness:latest .
docker run --rm ctf-harness:latest python -m pytest -q
docker run --rm ctf-harness:latest python scripts/check_image.py
```

**First, your run scripts.** `contest.env` now sends logs to
`/var/tmp/ctf-logs` and work to `/tmp/ctf-work`. If `rehearse.sh` mounts a host
directory at the old log path, the logs of your next run will be missing. Point
the mount at the new path, or pass `-e CTF_RUN_DIR`.

Then check, in the rehearsal image against one live instance:

- The agent can run `curl -s http://<target> 2>/dev/null`, `ping`, and
  `nmap -sV -p <its port> <host>`; another port on that host is still refused.
- A shell command naming `/opt/ctf-harness/fixtures` is refused; one running a
  script under `/opt/ctf-harness/knowledge` is not.
- The agent's working directory is under `/tmp/ctf-work`.
- With a model endpoint that hangs (a local listener that accepts and never
  answers), a run with `CTF_TOTAL_SECONDS=120` ends within about 125 s.
- Start a container with `--read-only --tmpfs /tmp` and another with
  `--user 1000:1000`. The run must start in both; the log should show
  `run.log_dir_fallback` or `challenge.work_dir_fallback` where it applied.
  Report what else breaks under each (tools that need to write to `HOME`, for
  one). The contest sandbox may look like either.

**Pass:** all of the above, with anything that failed fixed and tested.

### 2. Add the tools and renew the base image

`Dockerfile.tools` adds `scripts/image_extras.sh` on top of the current base:
an ssh client and `sshpass`, telnet, ftp, smbclient, database clients, PHP,
node, 32-bit libraries, the `mcp` client library, Pillow, and CyberEDU's MCP
server in its own venv. The commands are in the header of `Dockerfile.tools`.

- Before building, look for anything else a run reached for and did not find.
  Search the 23 logs for `command not found` and `No module named`, and add
  what is small and general to `image_extras.sh`. Leave Wine out.
- `check_image.py` has an entry for each addition. Zero critical failures is
  required; explain every optional miss.
- Record the size before and after, and the new backup's size and time.
- Rebuild `ctf-harness:rehearsal`. `Dockerfile.rehearsal` now repeats installs
  the base already has; trim it to what only rehearsal needs (iptables and its
  three settings).

**The MCP server in the submission image is a change of policy.** The earlier
brief said never to add it. The reason for adding it: the contest runs on
CyberEDU, the server is the organizers' own public package, and if the starter
kit turns out to be this server, using it becomes a settings change rather than
an install at the venue. It is idle unless `CTF_PLATFORM=cyberedu`. Andrei
decides (question 4); `--build-arg WITH_CYBEREDU_MCP=0` leaves it out.

**Pass:** new `:base` tagged and backed up, old one kept as
`ctf-harness:base-1115`, `check_image.py` clean, in-image tests pass.

### 3. Build the offline suite

A challenge solved on the account answers "already solved" to any value, so a
solved challenge can never be re-run through CyberEDU. Without an offline suite
there is no way to tell whether a change helped or hurt.

Make fixture directories (layout in `BENCHMARKS.md`) for the static challenges
solved in rehearsal: encryptor, bdlp, investigator, adding-in-parts, zodiac,
wifi-get-me. Each holds the files, the description **with the flag questions
exactly as the agent saw them**, the category, and `flag_sha256` only. Keep the
suite outside the repo.

The accepted flags are needed once, to hash them. They are not in the logs
(previews only). Getting them means reading Andrei's own accepted submissions
back from CyberEDU, which the adapter is forbidden to do. Ask Andrei first
(question 1). If he agrees: do it in a one-off operator script, hash at once,
write no plaintext anywhere, and leave the adapter's rule as it is.

**Pass:** the suite runs with `CTF_PLATFORM=files` in the contest image with
`--network none` apart from the model, and the current branch solves what it
solved live.

### 4. Measure time, then test the prompt change

From the 23 existing logs, with no new runs:

- Seconds per model turn: median, 90th percentile, maximum, per run and overall.
- Share of wall time spent in model calls, in tools, and elsewhere.
- Input tokens per turn over the course of a long run (hidden-cipher). Does it
  level off once the history limits bite, or keep growing?
- Tool calls per model turn. This is the baseline for batching.

Then, on the offline suite, compare the commit before this round (`3160925`)
with the current branch: two runs of each challenge on each side, same budget.
Report turns to solve, time to solve, tool calls per turn and tokens. A single
run of a sampling model is noise; do not conclude from one.

Also try `CTF_OPENAI_SEND_EFFORT=1` on two challenges. If GLM honours
`reasoning_effort`, the low rungs may get much faster turns.

**Decide from the data, and write the decision into `contest.env` as a comment
with the numbers behind it:** `CTF_MODEL_TIMEOUT` (now 300 s; a turn that long
is a quarter of a 20-minute run), whether to send effort, and whether the
batching prompt stays. If batching makes results worse, revert that one
paragraph in `_EFFICIENCY` and say so.

### 5. Run the contest configuration and the restart path, offline

Both are safe on the offline suite: nothing reaches Andrei's account.

- **Contest mode.** Run the suite with `CTF_PENALIZE_WRONG=0` and the default
  flag pattern. For each run count the submissions and classify the wrong ones
  (lookalike, prefixed variant, prose guess, harness artefact). Read what the
  model does after a "NOT accepted" note and after the late time note. Fix
  anything that submits junk in volume or that makes the model give up early.
- **Restarts.** `CTF_LADDER_DEPTHS=3,3,3,3` with `CTF_TOP_RUNG_RESTARTS=3` on
  a challenge the agent needs more than 12 turns for (investigator, zodiac)
  climbs the ladder and restarts within minutes. Read each handover note
  (`solver.recap` in the log) against the transcript before it: are the
  established facts in it, with exact values? Does the next attempt use them or
  start over? Run one more with `CTF_FRESH_CONTEXT=1` (a clean context at
  every rung change, off by default) to compare the two ways of escalating.

**Pass:** the two unanswered questions from the rehearsal brief are answered
with evidence, and the contest configuration has run end to end on every
suite challenge.

### 6. Second batch on CyberEDU

The first batch was Entry Level and Easy, with one pwn, two rev and one crypto.
Those three categories are where Andrei's notes are strongest, and they are
barely tested.

- About 10 new challenges: mostly Medium, at least three each of pwn, rev and
  crypto, plus two Easy web. None written up in `ctf-notes`, none with external
  file links, none that are site questions. Andrei approves the list.
- Re-run badimg and fair-dice once each with the current branch.
- Two of the runs at 2400 s, to see what a longer limit buys.
- Same procedure as before: read every transcript, classify, fix harness
  defects with tests. Stop at the freeze whatever the count.

### 7. Adapter drill

On the day the adapter is written under time pressure from documentation
nobody has seen. Rehearse that once.

- Write a small mock "starter kit" outside the harness: an HTTP service with a
  token, one challenge with a file, a service address in `nc HOST PORT` form,
  two flags as questions, and a submit endpoint that answers 200 for correct,
  400 for wrong and 429 when called twice within a second.
- Starting from the skeleton, write the adapter using only `kit.py` and the
  skeleton's comments, and time it. Then run `python -m harness.adapter_check`
  with and without `--submit`, and one full solve.
- Every place where the skeleton, `kit.py` or `adapter_check` was unclear,
  missing or wrong: fix it. That is the point of the drill.
- Commit the result as a worked example with its mock and a test
  (`harness/platforms/example_http.py`), and put `starter_kit.py` back to the
  skeleton.

If there is time, do the same for an MCP-shaped kit over HTTP rather than
stdio: `cyberedu_mcp.py` only has a stdio transport, and a hosted MCP server
is a plausible interface.

**Pass:** a working adapter from the skeleton in under 20 minutes, and the
friction found is fixed.

### 8. CyberEDU contest mode, read-only

The adapter's contest mode is written from the server source and has never met
a contest. If Andrei can name a contest his account can see (question 3), run
`python -m harness.adapter_check` against it in the image with
`CTF_PLATFORM=cyberedu` and `CTF_CONTEST_ID=<slug>`. No `--submit`. Fix what it
shows.

### 9. Freeze

- Update `contest.env` comments with the measured recommendations.
- Bring `HANDOFF.md` up to date and check its "Contest day, step by step"
  against what you learned in task 7.
- Delete `REHEARSAL_PROGRESS.md`; `REHEARSAL_REPORT.md` supersedes it.
- Write `FINAL_REPORT.md`: a verdict line, a table of these tasks with the key
  number for each, every change with its reason, the answers to tasks 4 and 5,
  and what is still unverified.
- Rebuild with `Dockerfile.contest`, run `check_image.py` and the in-image
  tests one last time, and renew the base backup if the base changed.
- With Andrei's go-ahead (question 5), fast-forward `main` to this branch and
  push.

## If time runs short

In order of value: tasks 1 and 2 (the image must be right), 5 (untested code
that will run in the contest), 7 (the first hour of the contest), 3 and 4, 6,
then 8.

## Out of scope

- Writing the real starter-kit adapter, and filling in `contest.env` with the
  real model and limits. Both wait for the contest.
- Running the agent's shell as a separate user. It would close the remaining
  exposure of the model key, and it is too large a change this close to the
  contest unless task 1's `--user` test shows it is needed anyway.
- Wine. Trimming the image.

## Questions for Andrei

1. May the accepted flags of the challenges you solved in rehearsal be read
   back from your CyberEDU account once, by a script and not by the agent, to
   store their SHA-256 in an offline test suite? (task 3)
2. Token ceiling for this round. 10.6M of the earlier 25M is spent. (tasks 4 to 6)
3. Is there a CyberEDU contest, past or present, that your account can open,
   for a read-only check of contest mode? (task 8)
4. CyberEDU's MCP server inside the image you upload: keep it (default) or
   leave it out? (task 2)
5. Approve the second-batch list (task 6), and the merge to `main` at the end
   (task 9).

## Done means

- The new guards, caps and fallbacks are verified on a real machine.
- `ctf-harness:base` holds the added tools and has a fresh backup.
- The contest configuration and the restart path have each run with a real
  model, and the two open questions are answered.
- An adapter has been written from the skeleton against a mock, in under 20
  minutes.
- `FINAL_REPORT.md` is committed, and `main` is fast-forwarded with Andrei's
  approval.
