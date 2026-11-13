# Local benchmark loop

Measure the harness's capture rate before the event by running it over public CTF
benchmarks — the same ones EnIGMA/CAI report on, so numbers are comparable:

- **InterCode-CTF** — picoCTF-style tasks (easier; good smoke signal)
- **NYU CTF Bench** — 200 real CSAW challenges across categories
- **Cybench** — 40 hard challenges from recent competitions

```bash
python -m harness.bench --fixtures <suite-dir> --backend openai --concurrency 4
```

(`--backend rule` is the offline no-LLM model — it only validates plumbing, not
solving. For real numbers point `--backend openai`/`anthropic` at a model
endpoint via env, as in production.)

## The suite layout the runner expects

One directory per task under the suite root:

```
<suite>/
  <task-id>/
    challenge.json
    files/              # attachments, copied into the agent's work dir
```

`challenge.json`:

```json
{
  "id": "nyu-ret2win",
  "name": "ret2win",
  "kind": "interactive",          // static | interactive | web | unknown
  "category": "pwn",
  "points": 100,
  "description": "nc the service and read the flag",
  "flags": ["CTF{...}"],          // one or more expected flags (local grading)
  "service": {                     // optional: launch a local service for the task
    "cmd": "python3 server.py 1337",
    "port": 1337,
    "cwd": "files",
    "ready_wait": 15
  }
}
```

- `flags` (or a single `flag`) is the local answer key — used only to grade
  `submit_flag` offline. It never leaves your machine and is never part of the
  submission image. `flags_required` is inferred from the list length.
- `service` makes `BenchmarkPlatform` spawn the task's own server locally and hand
  the agent `127.0.0.1:<port>`. **It runs the benchmark's code**, so only run
  suites you trust, on your dev machine.
- For web tasks, use `"kind": "web"` and either a `service` (local app) or a
  `"target": {"url": "http://127.0.0.1:PORT"}` in `challenge.json`.

## Converting each dataset

Each benchmark ships its own metadata; write a small converter that emits the
layout above. The mapping (verify field names against the dataset you pull — these
move between releases):

| Target field | InterCode-CTF | NYU CTF Bench | Cybench |
|---|---|---|---|
| `id` / `name` | task id / name | `challenge` dir name | task dir name |
| `category` | `category`/`tags` | `category` | from the task's path/metadata |
| `description` | `description`/`prompt` | `description` | task `README`/prompt |
| `files/` | provided files | `files/` | the task's provided artifacts |
| `flags` | `flag` | `flag` | the task's known flag(s) |
| `service` | n/a (mostly static) | from the task's `docker-compose` (service + port) | from the task's compose/start script |

A converter is ~30 lines: iterate the dataset's tasks, copy files into
`<suite>/<id>/files/`, and write `challenge.json`. For tasks that ship a
`docker-compose.yml`, either translate the service into a `service.cmd` that
launches it, or run compose yourself and point `target.url`/`host:port` at it.

`scripts/convert_benchmark.py` does this for the common layouts:

```bash
python scripts/convert_benchmark.py --spec ctftiny --src /path/to/CTFTiny --out suites/ctftiny
python scripts/convert_benchmark.py --spec generic --src ./tasks     --out suites/mine
python -m harness.bench --fixtures suites/ctftiny --backend openai --concurrency 4
```

Presets (`ctftiny`/`nyu`/`intercode`/`generic`) hold best-effort field names —
verify against the dataset you pulled and override with `--metadata`/`--flag-key`
if a task fails to parse. Run it on your dev machine (datasets need internet to
fetch; keep them and the converted suites out of git).

Keep converters and pulled datasets out of this repo (they're large and some have
their own licenses) — `.gitignore` already excludes `runs/`; add your
`benchmarks/` data dir there too.

## Reading the report

`bench` prints a summary and writes `runs/logs/bench-<id>.json`:

- **solve_rate** — solved / total for this run = pass@1. Re-run across the window
  for pass@k; keep the per-run JSON to compare harness versions between attempts
  (the dev loop *is* the competition).
- **by_category** — where the harness is strong/weak; aim tuning at the weak
  categories.
- **accuracy** — fraction of submissions that were correct. Low accuracy is fine
  (no wrong-flag penalty) *if* solve rate is high — but watch it doesn't mean the
  grounding guard is letting junk through.
- **solves** — solve order + seconds-to-first-flag. First-blood and earliest-last-
  flag both reward speed, so this is the number to drive down.

## Analyse a run (judge)

After any run, `harness.judge` turns the JSONL log into a between-run improvement
report — per-challenge progress score (partial credit), per-category solve rates,
and concrete suggestions (e.g. "found a flag but did not submit it" → a plumbing
gap; "weakest category: crypto"). No re-run, zero token cost.

```bash
python -m harness.judge runs/logs/run-<id>.jsonl
python -m harness.judge runs/logs/run-<id>.jsonl --llm --backend openai   # + model diagnosis
```

This is the core of the dev loop: run → judge → change the harness/prompts/tools
→ re-run. The run log is the only way to learn between attempts, so keep them.
