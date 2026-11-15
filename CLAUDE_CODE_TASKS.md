# Local validation: instructions for Claude Code

> **Completed 2026-11-15.** Results are in `VALIDATION_REPORT.md`. The next
> brief is `CLAUDE_CODE_REHEARSAL.md`. Kept for reference.

You are running on Andrei's Kali machine, inside a clone of
`github.com/andrei2308/ctf-harness` (private). Your job is to build the
submission image, prove it works from the agent's point of view, fix what is
broken, and write a report. Nothing here has been done before: the image has
never been built and the harness has never met a real model.

Read this file fully before running anything. `HANDOFF.md` has the settings
reference; `README.md` has the architecture.

## Context

### The contest

DefCamp 2026 Agentic CTF, run by AISafe. What the organizers have said so far:

- Each team uploads a **Docker image** containing its agent to the platform.
  Uploads are also allowed during the contest.
- The organizers run the image on their infrastructure: **one run per
  challenge**, with the challenge started automatically. Tools must be inside
  the image. Assume no internet at run time.
- **One model for everyone**, through the organizers' endpoint. The model and
  its limits are announced at the contest.
- The agent submits flags itself. **A wrong flag costs nothing.**
- Full logs are visible to the team **only after a challenge is solved**.
- The starter kit and documentation appear on the platform when the contest
  starts.

Two consequences shape this work. A misconfigured image gives no feedback at the
event, so everything testable must be tested now. And the starter-kit adapter
cannot be written yet, so it is out of scope here.

### The harness

A Python package, stdlib-only at its core, that drives an LLM through a
tool-calling loop to solve one CTF challenge.

| Path | What it is |
|---|---|
| `harness/single.py` | Production entry point: solve one challenge, then exit. The image's entrypoint runs it |
| `harness/agents/base.py` | The solver loop: model turn, tool calls, flag handling, context management |
| `harness/agents/tools.py`, `exttools.py` | Tools the model can call (`shell`, `gdb`, file I/O, network) and `LocalExecutor`, the agent's shell |
| `harness/agents/specialists.py` | Per-category prompts and tool sets; routing by challenge category |
| `harness/agents/knowledge.py` | Offline notes: search, read by path, index placed in the prompt |
| `harness/agents/limits.py` | Size and time limits, each with a `CTF_*` override |
| `harness/inference/openai_client.py` | Adapter for the OpenAI-compatible model endpoint |
| `harness/flags/` | Flag detection in tool output, and submission with retry |
| `harness/platforms/` | Where challenges come from. `files_target.py` serves local fixtures; `starter_kit.py` is an unfilled skeleton for the contest |
| `harness/scheduler/ladder.py`, `budget.py` | Effort ladder (4 rungs) and token/time budgets |
| `harness/preflight.py` | Checks a model endpoint through the real adapter |
| `harness/judge.py` | Reads a run log; `--transcript` replays what the agent did |
| `contest.env` | The one settings file. Baked into the image; real env vars override it |
| `scripts/check_image.py` | Checks the built image through the agent's own shell |
| `scripts/sync_knowledge.py` | Copies Andrei's notes into `knowledge/ctf-notes/` (git-ignored) |
| `fixtures/` | Three toy challenges: `warmup-01`, `locked-02`, `multi-03` |
| `tests/` | 115 tests, all offline |

How the agent's shell differs from yours: `LocalExecutor` runs `bash -c` with an
environment containing **only `PATH`**, and `HOME` set to the challenge work
dir. A tool can be installed and still invisible to the agent. Always test
through `scripts/check_image.py` or `ctf-tools`, not a plain `docker run ... bash`.

### What was verified before you, and what was not

Verified in a sandbox without Docker: the test suite, and a full solve of a
fixture through the real `openai` SDK against a fake endpoint.

Never verified: anything about the Docker image, and anything against a real
model. Treat every claim in `README.md` about the image as unproven.

## Ground rules

- **Work on the `local-validation` branch.** Do not push to `main`. Andrei
  merges when the report is green.
- **Never commit secrets or notes.** No API keys in any file, including
  `contest.env`. `knowledge/ctf-notes/` is git-ignored; keep it that way.
- **Do not run `docker system prune`** or delete build cache. The cached layers
  are what make rebuilds fast on contest day.
- **Do not hide failures.** If a tool will not install, say so in the report.
  Do not delete a check or a test to make something pass.
- **Fix causes, keep changes small.** A missing tool is fixed in the
  `Dockerfile`; a harness bug gets a regression test in `tests/`.
- **Ask Andrei** before anything that costs money, needs a credential, or
  takes a decision that is his (see "Questions for Andrei").
- Keep the full image. Do not trim tools to save build time.

## Tasks

Do them in order. Each has a pass condition. Record the result of every step
for the report, including timings and sizes.

### 1. Prepare

```bash
git fetch origin && git checkout local-validation && git pull
uname -m                      # expect x86_64
docker version && docker info | grep -i 'storage driver'
df -h /var/lib/docker .       # the full image is large; note free space
```

- If `uname -m` is not `x86_64`, stop and tell Andrei: the image must be
  `linux/amd64` and an emulated build is far slower.
- If free space under Docker's data root is below about 60 GB, tell Andrei
  before building.

**Pass:** on the branch, x86_64, Docker working, space noted.

### 2. Host tests

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev,openai]"
python -m pytest -q
```

**Pass:** 115 passed. If the count differs, find out why before continuing.

### 3. Sync the notes

Ask Andrei for the path to his `ctf-notes` clone if it is not at `../ctf-notes`.

```bash
python scripts/sync_knowledge.py ../ctf-notes
git status --short            # knowledge/ctf-notes must NOT appear
```

**Pass:** files copied, nothing new shows in `git status`.

### 4. Build the full image

```bash
time docker build -t ctf-harness:latest . 2>&1 | tee build.log
grep -n "WARN" build.log
docker images ctf-harness:latest
```

The Dockerfile installs most packages one at a time and prints `WARN: ... skip`
instead of failing, so **a successful build does not mean the tools are there**.
List every `WARN` line in the report.

If the build fails outright, fix the Dockerfile and rebuild. Common causes are
a package renamed in the current Kali snapshot or a download URL that moved.

**Pass:** build completes; build time, image size and all `WARN` lines recorded.
`build.log` is not committed.

### 5. Check the image as the agent sees it

```bash
docker run --rm ctf-harness:latest python scripts/check_image.py
docker run --rm ctf-harness:latest ctf-tools
docker run --rm ctf-harness:latest python -m pytest -q
```

`check_image.py` exits with the number of critical failures. Its critical set
is the minimum the agent needs: the venv's `python3` with pwntools, z3,
pycryptodome, angr; gdb; binutils; ROPgadget; binwalk, exiftool, tshark; john;
curl, nmap, netcat; the `openai` SDK; `contest.env` present.

For every `FAIL` and every `miss`:

1. Find the cause (not installed, installed but off `PATH`, needs `HOME`,
   wrong binary name in the check).
2. Fix it in the `Dockerfile`, or fix the check if the check is wrong.
3. Rebuild and rerun.

Known suspects, flagged in review but never tested:

- **`PATH` in the agent shell.** The agent must get `/opt/venv/bin/python3`.
  If "python3 is the venv's" fails, that is the top priority.
- **pwndbg.** `/opt/gdbinit-pwndbg` is generated with a guess at pwndbg's
  path, and system gdb's Python may not see the venv. If it does not load,
  either fix it properly or make plain gdb the documented fallback.
- **`solc`.** `solc-select` installs under `/root`, but the agent's `HOME` is
  the work dir. If `solc --version` fails, install the compiler somewhere
  `HOME`-independent.
- **SageMath, Ghidra, Foundry, volatility3.** Large installs that may have been
  skipped. Each matters for a whole category.
- **`rockyou.txt`.** Should exist unpacked at `/usr/share/wordlists/rockyou.txt`.

An optional tool that cannot be installed after a reasonable attempt is
acceptable: record it and move on. A critical failure is not.

**Pass:** zero critical failures, in-image pytest passes, and every optional
miss is either fixed or explained in the report.

### 6. Offline end-to-end run in the image

This is the production path with the built-in rule model, no network at all.

```bash
docker run --rm --network none \
  -e CTF_BACKEND=rule -e CTF_PLATFORM=files \
  -e CTF_FIXTURES=/opt/ctf-harness/fixtures \
  ctf-harness:latest --challenge warmup-01
```

**Pass:** stdout is a JSON summary with `"solved": true`, and stderr carries
the event log (lines of JSON with `"kind"`). Run `multi-03` the same way and
confirm it reports `"flags_accepted": 2`. `locked-02` is expected to stay
unsolved with the rule model.

### 7. Rebuild loop

On contest day the loop is: edit `contest.env` or `starter_kit.py`, rebuild,
upload. It must be fast and must not need the network.

```bash
echo "# touch $(date +%s)" >> contest.env
time docker build -t ctf-harness:latest .
time docker build --network none -t ctf-harness:latest .   # after another touch
git checkout contest.env
```

**Pass:** each rebuild takes well under two minutes and the `--network none`
one succeeds. If it does not, the layer order in the Dockerfile is wrong: the
harness's Python dependencies must be installed before `COPY . /opt/ctf-harness`.

### 8. Export size and time

The upload format is unknown. Measure the worst case, a full tarball.

```bash
time sh -c 'docker save ctf-harness:latest | gzip > /tmp/ctf-harness.tar.gz'
ls -lh /tmp/ctf-harness.tar.gz
```

**Pass:** compressed size and time recorded. Also record the uncompressed image
size. Delete the tarball afterwards unless Andrei wants it.

### 9. Rehearsal against a real model

This is the most valuable step and needs an endpoint from Andrei: any
OpenAI-compatible server whose model supports tool calling (a hosted API, or a
local server such as Ollama or vLLM). Ask him for the base URL, model id and
key, and pass them as environment variables only.

```bash
export CTF_BACKEND=openai OPENAI_BASE_URL=... OPENAI_API_KEY=... CTF_FAST_MODEL=...
python -m harness.preflight
```

Fix anything preflight reports before going on. Then, on the host (not in the
image, so iteration is quick):

```bash
export CTF_TOTAL_SECONDS=900
python -m harness.single --platform files --fixtures fixtures --challenge warmup-01
python -m harness.single --platform files --fixtures fixtures --challenge multi-03
python -m harness.single --platform files --fixtures fixtures --challenge locked-02
python -m harness.judge runs/logs/<newest>.jsonl --transcript
```

Read every transcript, solved or not. You are looking for harness defects, not
judging the model:

- The model's tool calls are malformed or ignored.
- The same command is repeated, or the agent stalls after a few turns.
- A flag is visible in tool output but not submitted.
- A flag is submitted in the wrong form.
- Token use per turn grows without bound (compare `tokens_in` across turns).
- A tool times out or returns nothing where it should not.
- The notes index in the first prompt is missing or irrelevant.

Then repeat one run inside the image, with the same variables passed by `-e`,
to confirm the image behaves like the host.

If Andrei has real challenges available locally, convert a few to the fixture
layout described in `BENCHMARKS.md` and run those too. Harder tasks expose more.

**Pass:** preflight exits 0; `warmup-01` and `multi-03` solved by the real
model; each transcript reviewed; each defect found is either fixed with a test
or listed in the report.

If Andrei has no endpoint available, skip this step and say so prominently in
the report. It is the largest remaining risk.

### 10. Report

Write `VALIDATION_REPORT.md` at the repo root and commit it on the branch:

- A one-line verdict: ready to merge, or not, and why.
- A table of the tasks above with pass/fail and the key number for each (build
  time, image size, tarball size, rebuild time, check counts).
- Every `WARN` from the build, and what you did about it.
- The final `check_image.py` output.
- Every change you made, with the reason.
- What the real-model rehearsal showed, or that it was skipped.
- Open items Andrei must decide.

Then push the branch and tell Andrei it is ready for review:

```bash
git push -u origin local-validation
```

## Out of scope

- **The starter-kit adapter** (`harness/platforms/starter_kit.py`). Its
  interface is unknown until the contest starts.
- **Filling in `contest.env`** with the real model id and limits. Also unknown.
- **Trimming the image.** Andrei has decided to keep the full toolset for now.
  If the measured size looks unworkable, report the number; do not cut.
- **Tuning prompts or the ladder** without transcript evidence from step 9.

## Questions for Andrei

Ask these when you reach the step that needs them, not all up front:

1. Where is the `ctf-notes` clone? (step 3)
2. Is there a model endpoint for the rehearsal, and what are its URL, model id
   and key? (step 9)
3. Are there real challenges on this machine to rehearse on? (step 9)
4. If an important optional tool cannot be installed, is it acceptable to ship
   without it? (step 5, only if it comes up)

## Done means

- `docker run --rm ctf-harness:latest python scripts/check_image.py` exits 0.
- The offline end-to-end run solves `warmup-01` with `--network none`.
- A rebuild after touching `contest.env` works with `--network none`.
- `VALIDATION_REPORT.md` is committed and pushed on `local-validation`.
- `main` is untouched.
