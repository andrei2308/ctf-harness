# ctf-harness — DefCamp 2026 Agentic CTF

An autonomous harness that plays a sealed CTF on its own: no internet, no human at
the controls, no mid-run steering. A lean orchestrator routes each challenge to a
per-category specialist, which works it through a tool loop behind a hard
flag-grounding guard, streams flags the instant they verify, and logs everything
for the between-run dev loop.

It runs today, fully offline (**283 passing tests**, no network, no credentials),
behind two swappable interfaces (`Platform`, `Model`) so the remaining organizer
unknowns don't block anything — you drop real values in as they land.

## Competition setup (confirmed by the AISafe organizers)

- **Submission = a Docker image we build** and upload; the organizers run it on
  their infra. We put whatever tools we want in it → the image *is* the submission
  (`Dockerfile`).
- **One container run per challenge**, challenge auto-started. So the production
  path is single-challenge (`harness/single.py`); the multi-challenge `Scheduler`
  is the local benchmark/dev harness.
- **One shared model for everyone, via the organizers' endpoint**, announced with
  its limits at the event → single-model, effort-based ladder; point the
  OpenAI-compatible adapter at their endpoint via env.
- **A wrong flag costs nothing** → `penalize_wrong=False`; submit aggressively.
- **Starter kit + docs arrive at event start** — they define the exact
  challenge-read / flag-submit interface, which slots behind `Platform`.

Still pending from the organizers: the model id + exact token/time limits, and the
starter-kit platform interface. Everything else is wired and swappable.

## Why it's shaped this way (the rules drive the design)

| Rule | Design consequence |
|---|---|
| Fixed, equal concurrency | Edge is in *what each slot does* → the escalation-ladder scheduler |
| Hard token+time limits, "no burning tokens" | Budget gates every attempt; prompts are terse; output is summarized; stalls bail early |
| Retries + update-between-runs, no mid-run steering | The dev/observability loop *is* the competition → JSONL logging + the run-log judge |
| Dynamic scoring, rare flags worth most | Breadth-first first pass banks easy/rare flags; escalation targets resisters |
| Tiebreak = earliest last-flag | Flags stream the instant they verify, never batched |
| No internet; stay in scope | Network tools are bound to the challenge target; a baked-in knowledge base replaces web search |
| Confabulated flags are worthless | A flag counts only if it traces to real tool output (`flags/grounding.py`) |
| Keep secrets out of the submission | Credentials read from env only; logs redact; `.gitignore` guards cookies |

## Layout

```
harness/
  platforms/     Platform interface + adapters (files/benchmark, CyberEDU MCP)
  inference/     Model interface + adapters (offline rule/scripted, Anthropic, OpenAI-compatible)
  scheduler/     Escalation ladder + fixed-concurrency pool + park/resume + budget
  flags/         Evidence-grounded flag extraction (confab guard) + streaming multi-flag submit
  agents/        Solver loop + category specialists + tool wrappers + knowledge retrieval
  telemetry/     Append-only JSONL run log with secret redaction
  config.py      Every organizer unknown as a knob with a sane default
  single.py      PRODUCTION path: solve one challenge (one container/challenge)
  bench.py       Local benchmark runner + score report (dev/measurement)
  judge.py       Run-log analyzer: between-run improvement report
  run.py         Multi-challenge runner (dev convenience)
knowledge/       Offline knowledge base the `knowledge` tool greps (drop ctf-notes here)
scripts/         convert_benchmark.py (CTFTiny/NYU/InterCode -> suite layout)
Dockerfile       Kali-based submission image: harness + full CTF toolset
BENCHMARKS.md    How to run/convert benchmarks and read the judge report
fixtures/        Self-contained demo challenges for the offline rig
tests/           pytest (283): grounding, budget, submit, solver, routing, tools, e2e, review regressions
```

> **Start with [HANDOFF.md](HANDOFF.md)**: what you must supply for a run to work,
> how to check the model endpoint (`python -m harness.preflight`), and what is
> still unverified.
> Image validation (done, see [VALIDATION_REPORT.md](VALIDATION_REPORT.md)):
> [CLAUDE_CODE_TASKS.md](CLAUDE_CODE_TASKS.md). Rehearsal on real challenges (done,
> see [REHEARSAL_REPORT.md](REHEARSAL_REPORT.md)). Before the freeze:
> [CLAUDE_CODE_FINAL.md](CLAUDE_CODE_FINAL.md) (done, see [FINAL_REPORT.md](FINAL_REPORT.md)),
> then [CLAUDE_CODE_PREFREEZE.md](CLAUDE_CODE_PREFREEZE.md) (done, see the addendum in the final report).

## Quickstart (offline, no network, no credentials)

```bash
python -m harness.run --platform files --fixtures fixtures --backend rule
python -m pytest -q
```

The run exercises the whole enumerate → plan → solve → ground → submit → log loop
with the `rule` model (a no-LLM heuristic that only runs tools; it never invents a
flag). Expect `warmup-01` and `multi-03` solved and `locked-02` dropped with
**zero** submissions (its flag isn't in any file — the grounding guard holds). A
JSONL log lands in `runs/logs/`.

## Entry points

```bash
# Production: solve the one challenge this container was given (what the image runs)
python -m harness.single --challenge <id>          # or CTF_CHALLENGE_ID; else the only one

# Local measurement: run a whole suite and print a score report
python -m harness.bench --fixtures <suite> --backend openai --concurrency 4

# Between-run learning: analyze a run log
python -m harness.judge runs/logs/run-<id>.jsonl
python -m harness.judge runs/logs/run-<id>.jsonl --transcript [challenge]   # what it actually did
```

`single` escalates effort up the ladder within one per-run budget, then keeps
restarting the top rung from a clean context (`CTF_TOP_RUNG_RESTARTS`, default 6)
so budget is not left unspent, and streams flags as they ground — the shipped path. `bench` drives a suite through the
`Scheduler` and reports solve rate, per-category breakdown, accuracy and timing.
`judge` turns a log into per-challenge progress scores and concrete suggestions.

## Architecture

**Two swappable interfaces.** `Platform` (`platforms/base.py`:
`list_challenges / get_challenge / download_files / start_instance /
get_conn_info / submit_flag`) — adapters: `FilesTargetPlatform`,
`BenchmarkPlatform` (launches local services), `CyberEduMcpPlatform` (wired, MCP
response fields marked `CONFIRM`). `Model` (`inference/base.py`:
`.complete(messages, tools) -> ModelResponse`) — solvers never import a vendor SDK;
adapters are offline `rule`/`scripted`, `anthropic`, `openai` (endpoint/key from env).

**Escalation ladder + scheduler.** Rungs are (model + effort + iteration budget +
temperature). Rung 0 is a cheap breadth-first sweep; a **stalled** challenge
escalates a rung, a **parked** one (attempt slice spent) resumes with state intact
so no slot idles; the per-challenge budget is a hard cutoff, the global budget
stops the run cleanly. With one model it degrades to an effort-only ladder.

**Flag grounding (the core correctness rule).** `EvidenceStore` holds only bytes a
tool actually produced; model prose is never evidence. `verify_candidate()`
accepts a model-claimed flag only if it is present verbatim in that evidence, and
`FlagSubmitter` is the only path to `Platform.submit_flag`. Knowledge-base and
summary output are marked non-evidence, so an example `CTF{...}` in a writeup can
never ground. A flag the model only claims in prose is refused when wrong flags
are penalised (`penalize_wrong=True`); while they are free (the confirmed rule)
it is submitted once as an ungrounded try, since the guard could then only lose
flags. The flag pattern is `CTF{...}` plus an optional glued prefix (`DCTF{...}`
submits both forms); set `CTF_FLAG_REGEX` once the format is confirmed.

**Multi-flag / staged submission.** The predecessor agent (CyberEDU's "Overmind",
which won the UNbreakable România 2026 human finals) *solved* two forensics
challenges it then couldn't submit, for lack of multi-flag plumbing. So a
`Challenge` carries `flags_required`, the store latches every distinct flag, and
the submitter keeps submitting until the challenge is complete; a grounded flag the
grader rejects is retried a bounded number of times for staged challenges.
Overmind also won at **64% accuracy** because wrong guesses weren't penalized —
hence submit-fast-and-often (`penalize_wrong=False`).

## The submission image & tools

The agent is routed to a **category specialist** — rev, pwn, crypto,
forensics(+stego), web, mobile, blockchain, pyjail, or a generalist fallback —
each with a concrete tool playbook in its prompt and a fitting profile. Beyond
`shell`/`write_file`/`knowledge` it gets structured wrappers for the fiddly tools:
`gdb` (batch; runs `CTF_GDB`, the portable pwndbg in the image, falling back to
plain gdb, with `--nx` so a planted `./.gdbinit` is ignored),
`gdb_session` (persistent interactive debugging), `ghidra_decompile` (Ghidra
headless → C), and `volatility`. Wrappers force **non-interactive** mode and
**degrade honestly** — a missing tool returns "not installed", never a fabrication.

The agent can only *run* a tool present at run time (no internet to install one),
so presence is guaranteed by the **Kali-based** `Dockerfile` (matching the Kali
workflow in `ctf-notes`), which bakes the full kit:

- **rev/pwn:** gdb+pwndbg, gdb-multiarch, qemu-user-static, Ghidra, radare2,
  ropper/ROPgadget, one_gadget, seccomp-tools, patchelf, pwninit, checksec, angr,
  z3, unicorn, capstone, upx, yara, floss, uncompyle6
- **crypto:** SageMath, pari/gp, yafu, sympy/numpy/gmpy2, fpylll+cysignals,
  RsaCtfTool, xortool, roca-detect, pycryptodome
- **forensics/stego:** volatility3, sleuthkit, bulk-extractor, testdisk, scalpel,
  binwalk, foremost, exiftool, tshark, qpdf, oletools, imagemagick, ffmpeg, sox,
  zsteg, stegseek, steghide, outguess, stegsnow, zbar, multimon-ng, **tesseract (OCR)**
- **cracking:** john, hashcat, hashid, hydra, fcrackzip/pdfcrack, hcxtools +
  rockyou/SecLists
- **web:** sqlmap, gobuster, ffuf, feroxbuster, nikto, whatweb, wfuzz, commix,
  wafw00f, nmap, flask-unsign, jwt_tool
- **mobile:** jadx, apktool, dex2jar, apksigner
- **blockchain:** Foundry (`cast`/`forge`/`anvil`), web3.py, slither, solc

At each run's start `probe_tools()` detects what's actually installed and tells the
specialist, so it only reaches for what's there. Two run-time caveats no install
fixes: **no GPU** (hashcat is CPU-only/slow — John is the workhorse) and **no
internet** (factordb / online lookups are dead — factor locally with sage/yafu).

```bash
docker build -t ctf-harness:latest .                              # full kit
docker build -f Dockerfile.slim --build-arg TIER=core \
  -t ctf-harness:base-core .                                      # smaller tier (medium | core)
docker run --rm ctf-harness:latest python -m pytest -q            # smoke test
docker run --rm ctf-harness:latest ctf-tools                      # list what the probe sees
```

Packages install in a resilient per-package loop, so a name this Kali snapshot
lacks only skips that package (logged `WARN`) instead of failing the build.
If the contest limits image size, use one of the smaller tiers built by
`Dockerfile.slim` (`HANDOFF.md`, "If the image is too big"). The `WITH_SAGE` /
`WITH_WORDLISTS` arguments of the main `Dockerfile` do not give a smaller image.

## Research-informed features

Drawn from the current CTF-agent literature (EnIGMA, CRAKEN/CTFusion, Plain
Agents, D-CIPHER, harness-engineering surveys):

- **Offline knowledge base + `knowledge` tool** — web access ~doubles solve rate
  and is forbidden here, so every specialist greps a baked-in base (your
  `ctf-notes` + cheatsheets) for the known technique. Output is non-evidence.
- **Output summarizer** — tool output over `CTF_TOOL_OUTPUT_BYTES` (default 8 KB)
  is shown as head + lines-of-interest + tail (heuristic, zero extra tokens); the
  full bytes still reach the evidence store and are saved under `.tool_output/`
  for the agent to grep.
- **History diet** — every message is re-sent each turn, so once the transcript
  passes `CTF_HISTORY_SOFT_CHARS` old tool results shrink to a stub, and past
  `CTF_HISTORY_HARD_CHARS` the middle is replaced by a digest of the actions taken
  (before the endpoint rejects the request). Knobs in `agents/limits.py`.
- **Transcript log** — each model turn, command and capped result excerpt is in the
  JSONL log (flags shown as previews only); `CTF_LOG_MIRROR=1` (image default)
  also streams it to stderr.
- **Stuck-loop detection** — repeated actions / no-new-evidence stalls get one
  nudge, then bail to STALLED so the ladder escalates instead of spinning.
- **Planning step** — one upfront no-tool plan per challenge (`plan_first`), the
  single biggest lever in ReAct&Plan; replan folds into the stuck nudge.
- **Per-rung sampling** — temperature rises 0.2 → 0.8 across the ladder; `top_p`
  plumbed through both adapters.
- **Fresh-context restart on escalation** (`fresh_context_on_escalate`, default
  off) — restart a stalled challenge's next rung with a clean context. Before any
  restart the model writes a handover note (facts, what failed, what to try next)
  that seeds the new context; a command list is the fallback.
- **Persistent interactive debugger** (`gdb_session`) — EnIGMA-style stateful gdb
  for pwn/rev, alongside the one-shot `gdb`.
- **Run-log judge** (`harness/judge.py`) — CTFJudge/CCI-style report: partial-credit
  progress scores, per-category solve rates, concrete suggestions.
- **Prompt-injection hardening** — specialists treat file/tool/service/knowledge
  text as untrusted data, never instructions, and stay in scope.
- **Benchmark converter** (`scripts/convert_benchmark.py`) — CTFTiny / NYU /
  InterCode / generic → the suite layout.

## Open knobs → organizer questions

Set them in **`contest.env`** (one file, baked into the image, overridden by the
real environment). Defaults in `config.py`:

- **Model** (Q1): `inference_backend`, `fast_model`, `strong_model`, ladder rungs.
- **Budgets** (Q2): `caps` (`total_*`, `per_challenge_*`, `per_attempt_*`,
  `count_cached_input`); also via `CTF_*` env vars. Set `CTF_TOTAL_SECONDS` a
  little under the organizers' limit: tool timeouts are clamped to the time left
  minus `CTF_RESERVE_SECONDS` (default 20). `CTF_MAX_OUTPUT_TOKENS` clamps the
  ladder's per-response `max_tokens`; `CTF_MODEL_TIMEOUT` (default 300 s) bounds
  one model request.
- **Concurrency** (Q3): `concurrency`; `slots_per_challenge` noted for parallel
  best-of-N if permitted.
- **Platform** (Q4): `platform=files|benchmark|mcp` or `module:Class`
  (skeleton: `harness/platforms/starter_kit.py`), `contest_id`.
- **Packaging/sandbox** (Q5): the Docker image; smaller tiers via `Dockerfile.slim`.
- **Wrong-submission penalty** (Q6): `penalize_wrong` (default False).
- **Flag format**: `CTF_FLAG_REGEX` (default: `CTF{...}` with optional prefix).

## What's left — mostly on your (build) side

1. **`docker build`** on a machine with Docker + internet, then
   `docker run --rm ctf-harness:latest ctf-tools` to confirm the toolchain landed
   (the per-package loop logs any `WARN` skips to fix).
2. **Populate `knowledge/`** with your `ctf-notes` before building
   (`python scripts/sync_knowledge.py ../ctf-notes`). Each specialist's task
   prompt then carries an index of its category's notes, and the `knowledge`
   tool can open a note or section by path.
3. **Benchmark** — convert a suite (`scripts/convert_benchmark.py`), run
   `harness.bench` with a real model endpoint, and `harness.judge` the log for a
   real capture-rate number and where to tune next.
4. **Wire the starter-kit `Platform` adapter** when the kit drops; set the model id
   and token/time caps.

## Credential hygiene (non-negotiable)

Everything submitted is logged and reviewed. **No secrets in the submission.**
- Credentials (e.g. a CyberEDU cookie via `CYBEREDU_SESSION`) are read from env at
  run time, never committed or baked into the image.
- `telemetry/run_log.py` redacts known-sensitive keys from every event.
- `.gitignore` blocks `.env`, `*.session.json`, `cyberedu_session*`, `runs/`.
