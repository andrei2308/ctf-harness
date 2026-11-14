# Handoff

State of the harness after the review, and exactly what you have to supply for a
run to work. Written 2026-11-14.

## Where things are

Everything is merged to `main`. The work was done on three stacked branches,
kept for reference:

| Branch | What it holds |
|---|---|
| `fix/review-blockers` | The eight defects from the review (iteration loop, tool-call history, image, shell, resilience, flag format) |
| `enhance/logging-tokens-time` | Transcript logging, token diet, working time budget |
| `enhance/recaps-notes-handoff` | Restart handover notes, notes index in the prompt, `preflight`, `contest.env`, this file |

Verified here: 115 tests pass, and the production path solves a fixture through
the real `openai` SDK against a local fake endpoint that enforces tool-call
pairing.

**Not verified, and yours to do:** the Docker image has never been built, and
nothing has run against a real model.

## Changing settings on the day

**One file: `contest.env`** at the repo root. Every setting in this document
goes there as `NAME=value`. It is copied into the image and read at start-up, so
the loop is: edit `contest.env`, `docker build` (only the last layer reruns, a
few seconds), `python -m harness.preflight` inside the image. Anything set in
the real environment (`docker run -e`, `export`) overrides the file.

What is a setting and what is code:

| Change | Where | Effort |
|---|---|---|
| Endpoint, model id, key, limits, flag format, penalty | `contest.env` | Edit a line |
| Organizer passes a variable under another name | `contest.env`: `OPENAI_BASE_URL=${THEIR_NAME}/v1` | Edit a line |
| Model wants `max_completion_tokens` or refuses `temperature` | nothing | Handled automatically |
| How to read the challenge and submit a flag | `harness/platforms/starter_kit.py` | Fill in four methods |
| Ladder depth and temperatures | `default_ladder` in `harness/scheduler/ladder.py` | Edit one function |
| Specialist prompts | `harness/agents/specialists.py` | Edit strings |

## What the model needs: the three required inputs

A run talks to an OpenAI-compatible endpoint. It needs exactly these:

| Input | Env var | Example | If missing |
|---|---|---|---|
| Endpoint base URL | `OPENAI_BASE_URL` | `http://10.0.0.5:8000/v1` | SDK calls api.openai.com, which is unreachable in the sandbox |
| Model id | `CTF_FAST_MODEL` | `qwen2.5-coder-32b` | Sends the literal name `fast`; the endpoint rejects it |
| API key | `OPENAI_API_KEY` | whatever they issue | Sends `not-needed`; fine only if the endpoint has no auth |

`CTF_BACKEND=openai` is also required; `contest.env` already sets it.

If the organizers inject the endpoint under **different variable names**, map
them in `contest.env`, for example `OPENAI_BASE_URL=${THEIR_URL_VAR}/v1`. You
cannot change what they pass at run time, only how the image reads it.

If they hand out an Anthropic-shaped endpoint instead: `CTF_BACKEND=anthropic`,
`ANTHROPIC_BASE_URL`, `ANTHROPIC_API_KEY`. That adapter is less tested; see
Known gaps.

## What the endpoint must support

- **`POST /v1/chat/completions`, non-streaming.**
- **Tool (function) calling.** Without it the harness cannot act at all.
- **These request fields:** `model`, `messages`, `tools`, `max_tokens`,
  `temperature`. `reasoning_effort` is sent only with `CTF_OPENAI_SEND_EFFORT=1`.
- **A `usage` block in the response.** Without it token caps never trigger and
  only the time cap protects you.

OpenAI's own reasoning models reject `max_tokens` (they want
`max_completion_tokens`) and a non-default `temperature`. The adapter detects
those rejections, switches, and remembers per model, so no change is needed.

## Check it before you run anything

```bash
# after filling in contest.env (or exporting the same variables)
python -m harness.preflight
```

It prints the configuration a run would use (never the key), then sends a few
tiny requests through the same adapter and ladder: reachability, usage
reporting, a tool call, a tool result going back, and each rung's `max_tokens`
and `temperature`. Each failure names the setting that fixes it. Exit code 0
means a run can start. It costs a few hundred tokens.

Run it twice: on your machine when the endpoint is announced, and inside the
image (`docker run --rm -e ... ctf-harness:latest python -m harness.preflight`).

## Run it

Against a bundled fixture, with a real model:

```bash
python -m harness.single --platform files --fixtures fixtures --challenge warmup-01
python -m harness.judge runs/logs/run-<id>.jsonl --transcript
```

Any OpenAI-compatible server works for rehearsal (vLLM, Ollama at
`http://localhost:11434/v1`, LM Studio). Pick a model with tool calling.

In the image:

```bash
python scripts/sync_knowledge.py ../ctf-notes      # notes into the image; see below
docker build -t ctf-harness:latest .
docker run --rm ctf-harness:latest ctf-tools       # must list pwntools, z3, angr
docker run --rm ctf-harness:latest python -m pytest -q
docker run --rm -e OPENAI_BASE_URL=... -e OPENAI_API_KEY=... -e CTF_FAST_MODEL=... \
  -e CTF_PLATFORM=files -e CTF_FIXTURES=/opt/ctf-harness/fixtures \
  ctf-harness:latest --challenge warmup-01
```

If `ctf-tools` does not list `pwntools`, the agent's shell is not seeing the
venv. That was the suspected `PATH` problem; the fix is in, but only a build
confirms it.

## Set these once the limits are announced

| What they announce | Set | Why |
|---|---|---|
| Time limit per run | `CTF_TOTAL_SECONDS`, a little under it | Tool timeouts are clamped to the time left; without it nothing is |
| Token limit per run | `CTF_TOTAL_TOKENS` | Stops cleanly instead of being cut off |
| Model's max output tokens / context size | `CTF_MAX_OUTPUT_TOKENS` | Upper rungs ask for 16K and 32K; a smaller model rejects that outright |
| Small context window | `CTF_HISTORY_SOFT_CHARS`, `CTF_HISTORY_HARD_CHARS` | Defaults (40K / 160K chars) assume roughly 64K tokens or more |
| Flag format | `CTF_FLAG_REGEX` | Default handles `CTF{..}` and prefixed forms like `DCTF{..}` only |
| A wrong-flag penalty | `CTF_PENALIZE_WRONG=1` | Turns off ungrounded and repeat submissions |
| Cached input is free | raise `CTF_HISTORY_SOFT_CHARS` | Trimming old results breaks the cache prefix |

Put the final values in `contest.env`; commented examples for each are already
there. The remaining size knobs are in `harness/agents/limits.py`.

## Platform inputs (still open)

The harness also needs to be told the challenge and how to submit. That depends
on the starter kit, which is not out yet.

- `CTF_PLATFORM` selects the adapter: `files`, `benchmark`, `mcp`, or
  `module:Class` for your own.
- `CTF_CHALLENGE_ID` or `--challenge` picks the challenge; with neither, the
  first one the platform lists is used.
- When the kit lands, fill in the four `TODO` methods in
  `harness/platforms/starter_kit.py` (list the challenge, fetch its files, say
  where the service is, submit a flag) and uncomment its `CTF_PLATFORM` line in
  `contest.env`. No other file needs touching. Raise `PlatformError` on
  transport failures; `submit_flag` is then retried and queued for you.

## Your notes in the image

`python scripts/sync_knowledge.py ../ctf-notes` copies the text files into
`knowledge/ctf-notes/`, which is git-ignored but inside the Docker build
context. Each specialist's task prompt then gets a short index of its
category's notes (about 2.5 KB, `CTF_PRIMER_CHARS`), and the `knowledge` tool
can open a note or one section by path.

Two things to know:

- The image is the submission, so the organizers can read whatever is in it.
- The category match goes by path names (`pwn_notes/`, `crypto/`,
  `forensics_notes.md`, ...). A new top-level folder with a different naming
  scheme needs a line in `_CATEGORY_PATHS` in `harness/agents/knowledge.py`.

## Before the event

1. Build the image and run the three `docker run` checks above.
2. Convert one benchmark suite (`BENCHMARKS.md`) and run it against any real
   model. Read transcripts of the failures; that is where the next gains are.
3. Decide whether the image size is acceptable (`WITH_SAGE`, `WITH_WORDLISTS`).
4. On the day: fill in `contest.env` (three inputs, then limits), run preflight,
   fill in `starter_kit.py`, rebuild, run preflight inside the image.

## Known gaps

- **Anthropic adapter and thinking.** It does not pass thinking blocks back, so
  rungs with a thinking budget will likely be rejected on a real Anthropic API.
- **Single model.** With one model and `CTF_OPENAI_SEND_EFFORT` unset, the four
  rungs differ only in temperature, output cap and depth.
- **Stuck detection.** "No new evidence" counts bytes, so a repeated error
  message looks like progress. Repeated identical commands are caught.
- **`HttpTool` keeps no cookies** between calls. The agent can use `curl` with a
  cookie jar from `shell`.
- **`solc-select`** is installed under `/root`, but the agent's `HOME` is the
  work dir, so `solc` may not find its version. Affects blockchain only.
- **Prompts and ladder depths are untuned.** They have never met a real model.
