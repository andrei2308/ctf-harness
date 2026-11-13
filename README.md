# ctf-harness — DefCamp 2026 Agentic CTF

An autonomous harness that plays a sealed CTF on its own: no internet, no human
at the controls, no mid-run steering. Lean orchestrator + per-category specialist
agents + a hard flag-grounding guard + streaming submission + heavy logging,
behind two swappable interfaces so the organizer unknowns never block the build.

This is the **skeleton** from step 1 of the build handoff. It runs today, fully
offline, and you drop real values in as organizer answers land.

## Competition setup (confirmed by the AISafe organizers)

- **Submission = a Docker image we build** and upload to the platform; we put
  whatever tools we want in it. The organizers run it on their infra. → see
  `Dockerfile` (the image *is* the submission).
- **One container run per challenge**, challenge auto-started. So the production
  path is single-challenge: a run reads its one assigned challenge and solves it.
  The multi-challenge `Scheduler` here is therefore the **local benchmark/dev
  harness**; the shipped run loop is the single-challenge `Solver`
  (`agents/base.py`). *(Single-challenge entrypoint lands with the starter kit.)*
- **One shared model for everyone, via the organizers' endpoint**, announced with
  its limits at the event. → single-model, effort-based ladder; point the
  OpenAI-compatible adapter at their endpoint via env.
- **A wrong flag costs nothing.** → `penalize_wrong=False`; submit aggressively.
- **Starter kit + docs arrive on the platform at event start** — that defines the
  exact challenge-read / flag-submit interface, which slots behind `Platform`.

Still pending: the model id + exact token/time limits, and the starter-kit
platform interface. Everything else is wired and swappable.

## Why it's shaped this way (the rules drive the design)

| Rule | Design consequence |
|---|---|
| Fixed, equal concurrency | Edge is in *what each slot does* → the escalation-ladder scheduler (`scheduler/`) |
| Hard token+time limits, "no burning tokens" | Budget is a gate on every attempt, not end-of-run bookkeeping (`scheduler/budget.py`); prompts are terse |
| Retries + update-between-runs, no mid-run steering | The dev/observability loop *is* the competition → structured JSONL logging (`telemetry/`) |
| Dynamic scoring, rare flags worth most | Breadth-first first pass banks easy/rare flags; escalation targets high-value resisters |
| Tiebreak = earliest last-flag | Flags stream the instant they verify (`flags/submit.py`), never batched |
| No internet; stay in scope | Network tools are bound to the challenge target; a specialist literally cannot reach another host (`agents/tools.py`) |
| Confabulated flags burn submissions | A flag counts only if it traces to real tool output (`flags/grounding.py`) |
| Keep secrets out of the submission | Credentials read from env only; logs redact; `.gitignore` guards cookies |

## Layout

```
harness/
  platforms/     Platform interface + adapters (files-on-disk, CyberEDU MCP)
  inference/     Model interface + adapters (offline rule/scripted, Anthropic, OpenAI-compatible)
  scheduler/     Escalation ladder + fixed-concurrency pool + park/resume + budget
  flags/         Evidence-grounded flag extraction (confab guard) + streaming submit
  agents/        Tool profiles + solver loop + static/interactive(pwn)/web specialists
  telemetry/     Append-only JSONL run log with secret redaction
  config.py      Every organizer unknown as a knob with a sane default
  single.py      PRODUCTION path: solve one challenge (one container/challenge)
  bench.py       Local benchmark runner + score report (dev/measurement)
  run.py         Multi-challenge runner (dev convenience)
Dockerfile       Submission image: harness + full CTF toolset
BENCHMARKS.md    How to point the benchmark loop at Cybench/NYU/InterCode
fixtures/        Self-contained demo challenges (one solvable, one not) for the offline rig
tests/           pytest; grounding, budget, submit, solver, end-to-end
```

## Quickstart (offline, no network, no credentials)

```bash
python -m harness.run --platform files --fixtures fixtures --backend rule
```

This exercises the whole enumerate → solve → ground → submit → log loop using the
`rule` model (a no-LLM heuristic that only runs tools; it never invents a flag)
and the files adapter. Expect `warmup-01` solved and `locked-02` dropped with
**zero** submissions (its flag isn't in any provided file — the grounding guard
holds end to end). A JSONL log lands in `runs/logs/`.

```bash
python -m pytest -q        # 19 tests: grounding, budget, submit, solver, e2e
```

## Entry points

```bash
# Production: solve the one challenge this container was given (what the image runs)
python -m harness.single --challenge <id>        # or CTF_CHALLENGE_ID; else the only one

# Local measurement: run a whole suite and print a score report
python -m harness.bench --fixtures <suite> --backend openai --concurrency 4
```

`single` escalates effort up the ladder within one per-run budget and streams
flags as they ground — the shipped path. `bench` drives the whole suite through
the multi-challenge `Scheduler` and reports solve rate, per-category breakdown,
accuracy and solve timing (see BENCHMARKS.md).

## The two swappable interfaces

**`Platform`** (`platforms/base.py`) — `list_challenges / get_challenge /
download_files / start_instance / get_conn_info / submit_flag`. The scheduler and
solvers talk only to this.
- `FilesTargetPlatform` — challenges as directories on disk (+ optional target
  host/port/url, + local self-grading). The local test rig and the likely
  fallback runtime shape.
- `CyberEduMcpPlatform` — wired against `CyberEDU-Cyber-Range/cyberedu-mcp`
  (stdio). Tool-name mapping is in place; **load-bearing response field names are
  marked `CONFIRM`** — verify against the live server. Cookie is read from
  `CYBEREDU_SESSION` env only.

**`Model`** (`inference/base.py`) — `.complete(messages, tools) -> ModelResponse`
with normalized tool calls + token usage. Solvers never import a vendor SDK.
- `null`/`rule` — offline, deterministic, for the dev loop and tests.
- `anthropic`, `openai` — lazy-imported; endpoint/key from env.

## Escalation ladder + scheduler

`scheduler/ladder.py` defines rungs (model + effort + iteration budget). Default:
cheap/shallow rung 0 for a breadth-first sweep, escalating to stronger model /
higher effort / more iterations for resisters. If only one model is provided it
degrades to an effort-only ladder on that model.

`scheduler/scheduler.py` runs a fixed-concurrency pool:
1. every challenge gets one rung-0 attempt first (bank easy/rare flags early);
2. a **stalled** challenge escalates a rung; a **parked** challenge (ran out of
   its attempt slice) resumes at the same rung with state intact, so no slot idles;
3. resumable work is ordered by partial-signal → value → cheapness;
4. the per-challenge budget is a hard cutoff (write notes, drop, move on); the
   global budget stops the whole run cleanly.

## Open knobs → organizer questions

Defaults in `config.py`. These map 1:1 to the Tier-1 questions in the handoff:

- **Model** (Q1): `inference_backend`, `fast_model`, `strong_model`, ladder rungs.
- **Budgets** (Q2): `caps` — `total_*`, `per_challenge_*`, `per_attempt_*`,
  `count_cached_input`. Also settable via `CTF_*` env vars.
- **Concurrency** (Q3): `concurrency` (slots). `slots_per_challenge` is noted in
  the scheduler for if parallel best-of-N-within-a-run is permitted.
- **Wrong-submission penalty** (Q6): `penalize_wrong` (default False, per the
  predecessor event); flips the submit posture from aggressive-retry to one
  attempt per flag.
- **Platform** (Q4): `platform=files|mcp`, `contest_id`.
- **Packaging/sandbox** (Q5/Q6): `LocalExecutor` is dev-only; swap for a
  container executor (read-only rootfs, `/input` ro + `/work` + `/artifacts`,
  digest-pinned, no runtime installs) without touching tool code.

## Analysis tools & the submission image

The agent is routed to a **category specialist** — rev, pwn, crypto, forensics
(+stego), web, mobile, or a generalist fallback — each carrying a concrete tool
playbook in its system prompt (which tool for which job) and a fitting profile.
Beyond `shell`/`write_file` it gets structured wrappers for the fiddly ones:
`gdb` (batch, pwndbg-loaded via a trusted init while `--nx` ignores any planted
`./.gdbinit`), `ghidra_decompile` (Ghidra headless → C), and `volatility`. The
wrappers force **non-interactive** mode (an autonomous slot must never block on a
prompt) and **degrade honestly** — a tool the sandbox lacks returns "not
installed", never a fabricated result.

Because the agent can only *run* a tool that exists at run time (no internet to
install one), presence is guaranteed by baking tools into the `Dockerfile`
submission image. At each run's start, `probe_tools()` checks what's actually
installed and the specialist prompt is told, so the agent only reaches for what's
there.

The image is **Kali-based** (matches the Kali workflow in `ctf-notes`) and bakes
the full kit across categories: rev/pwn (gdb+pwndbg, Ghidra, radare2, ropper,
ROPgadget, one_gadget, seccomp-tools, patchelf, pwninit, checksec, angr, z3,
unicorn, capstone), crypto (**SageMath**, sympy/numpy/gmpy2, fpylll+cysignals,
RsaCtfTool, xortool, roca-detect, pycryptodome), forensics/stego (volatility3,
zsteg, stegseek, steghide, binwalk, foremost, exiftool, tshark, sox), cracking
(john, hashcat, hashid, hydra, fcrackzip/pdfcrack, hcxtools + rockyou/SecLists),
web (sqlmap, gobuster, ffuf, nmap, flask-unsign, jwt_tool), and mobile
(jadx, apktool, dex2jar). Two run-time caveats no install fixes: **no GPU**
(hashcat is CPU-only/slow — John is the CPU workhorse) and **no internet**
(factordb / online RSA lookups are dead — factor locally with sage/yafu).

Build + smoke-test the image (on a machine with Docker + internet):

```bash
docker build -t ctf-harness:latest .                              # full kit
docker build --build-arg WITH_SAGE=0 --build-arg WITH_WORDLISTS=0 \
  -t ctf-harness:slim .                                           # trim the heavy layers
docker run --rm ctf-harness:latest python -m pytest -q            # smoke test
docker run --rm ctf-harness:latest ctf-tools                      # list what the probe sees
```

Packages install in a resilient per-package loop, so a name this Kali snapshot
lacks only skips that one package (logged `WARN`) instead of failing the build.

SageMath and SecLists are most of the image size — toggle them off with the build
args if the submission size limit (OPEN) bites.

## Multi-flag / staged submission

Informed by the predecessor agent (CyberEDU's own "Overmind", which won the
UNbreakable România 2026 human finals): its *only* failure was two forensics
challenges it solved but could not submit, because they needed several flags in
sequence and it had no multi-flag path. So a `Challenge` carries `flags_required`,
the `EvidenceStore` latches every distinct flag, and `FlagSubmitter` keeps
submitting until the platform says the challenge is complete (or enough distinct
flags are accepted). A grounded flag the grader rejects is retried a bounded
number of times (`max_submits_per_flag`) to handle staged challenges — disabled
when `penalize_wrong=True`.

The same run also showed the winning posture was **submit fast and often** (it
won at 64% accuracy because wrong guesses weren't penalised). The harness streams
every grounded candidate immediately; set `penalize_wrong=True` if the contest
rules turn out to charge for wrong submissions (OPEN — confirm with organizers).

## Flag grounding guarantee

`flags/grounding.EvidenceStore` holds only bytes a tool actually produced; the
model's prose is never evidence. `verify_candidate()` accepts a model-claimed
flag only if it is present verbatim in that evidence. `FlagSubmitter` is the only
code path to `Platform.submit_flag`, so a confabulated flag cannot be submitted.
Covered by `tests/test_grounding.py`, `tests/test_solver.py`, and end to end in
`tests/test_scheduler_e2e.py`.

## Next steps (from the handoff)

1. **Local test loop** — point the harness at Cybench / NYU CTF Bench /
   InterCode-CTF via a thin `Platform` adapter (same benchmarks EnIGMA/CAI report
   on, so numbers are comparable), and rehearse against past CyberEDU/D-CTF-quals
   challenges through the MCP with your own cookie (**local env only**).
2. **Harden the specialists** — lean on EnIGMA's interactive ACI for pwn/rev and
   CAI's one-tool-per-specialist swarm shape; tune prompts and tool profiles from
   real runs.
3. **Container executor** — implement the sandboxed `Executor` for real runs.

## Credential hygiene (non-negotiable)

Everything submitted is logged and reviewed. **No secrets in the submission.**
- The CyberEDU cookie is read from `CYBEREDU_SESSION` at run time; never committed.
- `telemetry/run_log.py` redacts known-sensitive keys from every event.
- `.gitignore` blocks `.env`, `*.session.json`, `cyberedu_session*`, `runs/`.
