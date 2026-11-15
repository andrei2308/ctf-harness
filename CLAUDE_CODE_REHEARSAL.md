# Rehearsal on real challenges: instructions for Claude Code

You are on Andrei's Kali machine, in the `ctf-harness` repo. The image is built
and validated (`VALIDATION_REPORT.md`). What is still unknown is whether the
agent solves real challenges, because so far it has only met three toy
fixtures. Your job is to rehearse on real CyberEDU challenges, find out how the
agent fails, fix the harness defects behind those failures, and report.

Read `HANDOFF.md` and `VALIDATION_REPORT.md` first. The contest facts, the
harness map and the ground rules in `CLAUDE_CODE_TASKS.md` still apply.

## Why this matters

At the contest, full logs are visible only **after** a challenge is solved. A
failure there shows as "unsolved" and nothing else. This rehearsal is the only
place to watch the agent fail and learn from it. The contest is organized by
the people behind CyberEDU, so its practice catalogue is the closest available
stand-in for the real challenges.

## Ground rules

- **Branch:** work on `contest-readiness`. Do not push to `main`.
- **Secrets:** the GLM key and the CyberEDU cookie are passed as environment
  variables only. Never write either into a file in this repo, a command line,
  a log you commit, or the report.
- **Never use a flag-retrieval tool.** If the CyberEDU server exposes any way to
  read a challenge's flag or solution, the adapter must not call it and the
  agent must not be able to reach it.
- **The agent must not reach the MCP server or the cookie.** Only the harness
  process talks to CyberEDU.
- **Be a polite client.** These are Andrei's account and CyberEDU's
  infrastructure. One run at a time, no parallel hammering, stop service
  instances when a run ends, and keep wrong submissions low (see step 2).
- **Only CyberEDU challenge instances are targets.** The agent attacks the
  service the platform hands it and nothing else.
- **Do not cold-rebuild the image.** Use `Dockerfile.contest` for source
  changes. Do not prune Docker.
- **Fix the harness, not the scoreboard.** Do not tune a prompt to one
  challenge, hard-code anything about a specific task, or add solved flags to
  the notes. Every fix must be something that helps on unseen challenges.
- **Every harness fix gets a regression test.**

## Tasks

### 1. Verify what was added since validation

These were written without Docker and are untested on a real machine:

```bash
git fetch origin && git checkout contest-readiness && git pull
python -m pytest -q                                   # expect 136 passed
python scripts/sync_knowledge.py ../ctf-notes

# cache-independent rebuild
docker tag ctf-harness:latest ctf-harness:base
time docker build -f Dockerfile.contest -t ctf-harness:latest .
docker run --rm ctf-harness:latest python scripts/check_image.py
docker run --rm ctf-harness:latest python -m pytest -q

# backup of the base image (install pigz first: sudo apt install -y pigz)
time sh -c 'docker save ctf-harness:base | pigz > ~/ctf-harness-base.tar.gz'
ls -lh ~/ctf-harness-base.tar.gz
```

Then with the GLM endpoint set as in `HANDOFF.md`:

```bash
docker run --rm -e OPENAI_API_KEY -e OPENAI_BASE_URL -e CTF_FAST_MODEL \
  ctf-harness:latest python -m harness.preflight
```

Check 6 is new: it should report GLM as a reasoning model, and say whether it is
cut off at rung 0's cap. Rerun with `-e CTF_MIN_OUTPUT_TOKENS=8192` and compare.

**Pass:** `Dockerfile.contest` builds in seconds and the result passes
`check_image.py` 57/57 and the in-image tests; the backup exists (keep it, tell
Andrei where it is and its size); preflight exits 0. Fix anything that does
not. If `Dockerfile.contest` cannot work as written, fix it: the goal is a
rebuild that survives a lost build cache.

### 2. Make the CyberEDU adapter work

`harness/platforms/cyberedu_mcp.py` does not match the real server; the
mismatches are listed under Known gaps in `HANDOFF.md`. The server source is at
`~/Desktop/cyberedu-mcp`. Read it for the real tool names, arguments and
response shapes; do not guess.

Requirements:

- Covers the **practice catalogue**, not only contests.
- Implements the six `Platform` methods: list, get, download files, start
  instance, connection info, submit flag. Stop or release the instance when the
  run ends.
- Reads the cookie from the environment variable the server actually uses.
- `submit_flag` returns `accepted` correctly and raises `PlatformError` on
  transport failures.
- Tested with a fake transport (the adapter already takes a `transport`
  argument), so the tests need no network.

Where it runs: the agent should run **inside the image**, since that is what the
contest runs. The MCP server is not in the image and must not be added to the
submission. Build a separate rehearsal image on top of it, for example a
`Dockerfile.rehearsal` that starts `FROM ctf-harness:latest` and installs the
server in its own venv with `mcp<2`. Never upload that image. If this proves
impractical, running the harness on the host against the server is an
acceptable fallback; say so in the report, because host tools differ from the
image's.

Submission policy for rehearsal: set `CTF_PENALIZE_WRONG=1`. That limits the
harness to one submission per flag and to flags actually seen in tool output,
which keeps junk off Andrei's account. If CyberEDU's flags have a fixed shape,
also set `CTF_FLAG_REGEX` to it, which stops the default from submitting both a
bare and a prefixed form of every match. Note in the report that the contest
setting for wrong flags is the opposite.

**Pass:** one easy practice challenge goes end to end in the rehearsal image:
listed, files downloaded, instance started if it has one, solved or not, flag
submitted through the real platform, instance stopped.

### 3. Choose the rehearsal set

About 15 challenges. Ask Andrei to approve the list before running.

- Spread across categories: rev, pwn, crypto, forensics, stego, web, misc, and
  mobile or blockchain if the catalogue has them.
- Mostly easy and medium. Include two or three hard ones to see how the agent
  spends a full budget when it cannot solve.
- Prefer past DefCamp, ROCSC and UNbreakable challenges: closest in style.
- Include both static (files only) and live-service challenges.
- **Exclude anything covered in `ctf-notes`.** A challenge whose writeup is in
  the image's knowledge base tells you nothing. Search the notes for each
  candidate's name before adding it.

### 4. Run the set

One at a time, each in a fresh container, with a budget like the contest's
might be. Agree the numbers with Andrei; a reasonable start is:

```
CTF_TOTAL_SECONDS=1200
CTF_TOTAL_TOKENS=1500000
CTF_PENALIZE_WRONG=1
```

Keep every run's log (`runs/logs/`, mounted out of the container). For each run
record: challenge, category, difficulty, solved, wall time, tokens, model
turns, attempts and top rung reached, and how it ended.

Watch the GLM spend. Ask Andrei for a total token or cost ceiling before
starting, and stop when you reach it.

### 5. Read every transcript and classify the failure

```bash
python -m harness.judge runs/logs/<run>.jsonl --transcript
```

For each unsolved run, decide which of these it was. Be specific and quote the
turn that shows it.

| Class | What it looks like |
|---|---|
| Harness defect | A tool wrapper errors or returns nothing; output cut where the answer was; a flag seen but not submitted; a timeout killing useful work; the agent told a tool is missing when it is installed |
| Context loss | After trimming, compaction or a restart, the agent redoes work or forgets a fact it had established |
| Budget shape | Ran out of turns on a rung while making progress; or burned the budget repeating one approach; or quit with budget left |
| Wrong routing | Sent to the wrong specialist, or the right one lacked a tool it needed |
| Prompt gap | The agent never tried a standard technique for the category that a competent player would try first |
| Notes not used | A relevant note existed and the agent never opened it; or the index pointed at the wrong note |
| Environment | No route to the service, a tool needs a privilege the container lacks, something needs the internet |
| Model limit | The harness did its job and the model could not find the idea |

Also read at least three **solved** transcripts. Look for wasted turns and
tokens even in success.

### 6. Fix and re-run

Fix in this order: harness defects, context loss, budget shape, routing,
then prompt gaps and notes usage. "Model limit" is not fixable; record it.

After a batch of fixes, re-run the challenges that failed for a fixable reason,
plus two that passed, to catch regressions. A challenge that passed once and
fails after a change is a signal worth a careful look, but a single run of a
sampling model is noisy: re-run before concluding.

Specific questions this rehearsal should answer, because they decide contest
settings:

- With GLM, what `CTF_MIN_OUTPUT_TOKENS` avoids cut-off turns without wasting
  budget?
- How many model turns does a solved challenge take, by category? Are the
  ladder depths (12, 25, 40, 60) sensible?
- Do clean-context restarts ever help, or only burn budget?
- Does the handover note written before a restart carry the right facts?
- Is 8 KB per tool result too tight for any category (forensics, rev)?
- How often is the notes index used, and does it help?
- Do `gdb`, `strace` and `ltrace` work inside the container as run by Docker's
  default security profile?

### 7. Offline regression suite (if time allows)

For each static challenge solved in rehearsal, write a fixture directory
(layout in `BENCHMARKS.md`) with its files and description and **only the
SHA-256 of the accepted flag** (`flag_sha256`; see `scripts/hash_flags.py`).
Keep the suite outside this repo, since the challenges are CyberEDU's. It gives
Andrei a repeatable benchmark that needs no network and no account.

### 8. Report

Write `REHEARSAL_REPORT.md`, commit and push the branch.

- Verdict in one line: solve rate before and after fixes.
- Results table: one row per challenge, with the columns from step 4 and the
  failure class from step 5.
- Each fix made, the failure that motivated it, and the test that covers it.
- Answers to the questions in step 6, with the evidence.
- Recommended `contest.env` values and any ladder change, with reasons.
- Failures you could not fix, and what would.
- Where the backup image and any offline suite are.

## Questions for Andrei

1. Is it acceptable to submit flags on your CyberEDU account during rehearsal?
   (step 2; do not submit anything before a yes)
2. What is the ceiling on GLM spend for this rehearsal? (step 4)
3. Approve the list of challenges. (step 3)
4. What per-run time and token budget should the rehearsal assume? (step 4)

## Out of scope

- The contest's starter-kit adapter: still unknown until the contest starts.
- Trimming the image.
- Running the agent's shell as a separate user (noted in Known gaps).
- Anything that requires the CyberEDU cookie to leave this machine.

## Done means

- `Dockerfile.contest` verified and a backup of the base image saved.
- The CyberEDU adapter works against the real server and has offline tests.
- About 15 real challenges run, every transcript read, every failure classified.
- Fixable failures fixed with tests and re-run.
- `REHEARSAL_REPORT.md` committed and pushed on `contest-readiness`.
- `main` untouched.
