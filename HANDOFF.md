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

**Validated on 2026-11-15** (branch `local-validation`; full detail in
`VALIDATION_REPORT.md`): the image builds (14.3 GB, 5.1 GB gzipped);
`scripts/check_image.py` passes 57/57 through the agent's own shell; 126 tests
pass on the host and in the image; the offline end-to-end run solves the
fixtures with `--network none`; a `contest.env` rebuild takes about 4 s with
no network; and GLM 5.3 Flash solved the fixtures through the OpenAI adapter,
on the host and in the image. The image build, four tool wrappers and three
solver behaviours needed fixes along the way; the report lists each one.

**After the rehearsal (2026-11-17, branch `contest-readiness`, not yet built or
run on a real machine):** the scope guard no longer refuses ordinary commands
and has a setting; the model is told what happened to each flag it produced and
when time is short; the prompt asks for batched steps; the work and log
directories fall back to a temporary one if unwritable; a tools script adds the
clients the agent lacked; and the contest adapter has a kit and a check command.
`CLAUDE_CODE_FINAL.md` lists what must be verified before the freeze.

## Contest day, step by step

1. **Read the starter kit.** Find: how the challenge arrives, how a flag is
   submitted and what comes back, the endpoint and model id, the limits, the
   flag format, and whether a challenge is one service or a whole machine.
2. **Write the adapter** in `harness/platforms/starter_kit.py`. The file lists
   the ten lessons from the rehearsal and has a recipe per method;
   `harness/platforms/kit.py` has the tested pieces, and
   `harness/platforms/example_http.py` is a complete adapter written from the
   skeleton in the drill (an HTTP kit with a token, flags as questions, a
   rate-limited submit). If flags are questions with ids, send each value to
   the open questions in turn and space your own calls with `kit.Pacer`: one
   submit_flag hitting several questions got HTTP 429 in the drill. If the kit
   is CyberEDU's own MCP server, write nothing: set `CTF_PLATFORM=cyberedu`
   and `CTF_CONTEST_ID` (the server is already in the image).
3. **Fill in `contest.env`:** the three model inputs, the limits, the flag
   regex, `CTF_PLATFORM`, `CTF_TARGET_SCOPE`. The flag regex is not optional
   when the format is not `CTF{...}` (say `DCTF{...}` or `FLAG{...}`): the
   default pattern only matches `...CTF{...}`, and a flag it cannot match is
   never submitted automatically.
4. **Check on your laptop**, if their endpoints are reachable from it:
   ```bash
   python -m harness.preflight                              # the model
   python -m harness.adapter_check                          # the adapter, read-only
   python -m harness.adapter_check --submit 'CTF{wrong}'    # a rejection comes back as one
   ```
   Read the block `adapter_check` prints under "what the agent is told". If
   the flag format or the question is not in it, the agent does not know it.
   A `[WARN]` that the stated format does not match the flag pattern means
   step 3's regex is missing or wrong: fix it before uploading.
5. **Rebuild and check the image:**
   ```bash
   docker build -f Dockerfile.contest -t ctf-harness:latest .
   docker run --rm ctf-harness:latest python scripts/check_image.py
   ```
6. **Upload, and aim the first run at the easiest challenge.** Logs appear
   only after a solve, so one early solve is the only proof the pipeline works.
7. **Then tune from what the logs show.** After the freeze, only `contest.env`
   and `starter_kit.py` change.

## Changing settings on the day

**One file: `contest.env`** at the repo root. Every setting in this document
goes there as `NAME=value`. It is copied into the image and read at start-up, so
the loop is: edit `contest.env`, rebuild, `python -m harness.preflight` inside
the image. Anything set in the real environment (`docker run -e`, `export`)
overrides the file.

**Rebuild with `Dockerfile.contest`,** which starts from the finished image and
replaces only the harness, so it does not depend on Docker's build cache
surviving:

```bash
# once, after a good full build
docker tag ctf-harness:latest ctf-harness:base
docker save ctf-harness:base | pigz > ctf-harness-base.tar.gz   # backup; `docker load` restores it
# on the day
docker build -f Dockerfile.contest -t ctf-harness:latest .
```

A change to the tools themselves (a new package) still needs the full
`Dockerfile`, then re-tagging `:base`.

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
venv. The 2026-11-15 build confirmed it does (`python3 is the venv's` passes).

## Rehearsing against a real model on Andrei's machine

The endpoint used for the 2026-11-15 rehearsal was z.ai's OpenAI-compatible
API with the GLM key from `~/.claude/settings.json.glm`. Read the key from that
file at run time; never copy it into a file in this repo:

```bash
export OPENAI_API_KEY="$(python3 -c 'import json,pathlib;print(json.loads(pathlib.Path.home().joinpath(".claude/settings.json.glm").read_text())["env"]["ANTHROPIC_AUTH_TOKEN"])')"
export CTF_BACKEND=openai OPENAI_BASE_URL=https://api.z.ai/api/coding/paas/v4 CTF_FAST_MODEL=glm-5.3-flash
python -m harness.preflight
# in the image: pass the key by name only, so it never appears on a command line
docker run --rm -e OPENAI_API_KEY -e OPENAI_BASE_URL -e CTF_FAST_MODEL ctf-harness:latest python -m harness.preflight
```

`glm-5.3-flash` is a reasoning model: hidden reasoning counts against
`max_tokens`. Use `CTF_MIN_OUTPUT_TOKENS=8192` (see `REHEARSAL_REPORT.md`).

### Rehearsing on real CyberEDU challenges

The harness's CyberEDU adapter (`CTF_PLATFORM=cyberedu`) works against the
official MCP server; it was used for 23 rehearsal runs (`REHEARSAL_REPORT.md`).
The server lives only in the rehearsal image, which is **never uploaded**:

```bash
docker build -f Dockerfile.contest   -t ctf-harness:latest .
docker build -f Dockerfile.rehearsal -t ctf-harness:rehearsal .
# cookie and model key by NAME only; NET_ADMIN for the egress firewall
docker run --rm --cap-add NET_ADMIN \
  -e CYBEREDU_SESSION_COOKIE -e OPENAI_API_KEY -e OPENAI_BASE_URL -e CTF_FAST_MODEL \
  -e CTF_TOTAL_SECONDS=1200 -e CTF_PENALIZE_WRONG=1 -e CTF_MIN_OUTPUT_TOKENS=8192 \
  ctf-harness:rehearsal --challenge <challenge-id>
```

The run scripts used (one run per fresh, empty log directory; a token ledger)
are in `~/Desktop/ctf-rehearsal/`, outside the repo, because the challenges
are CyberEDU's. The cookie lives only in `~/.claude.json` (the `cyberedu` MCP
entry) and is read from there at run time.

## Set these once the limits are announced

| What they announce | Set | Why |
|---|---|---|
| Time limit per run | `CTF_TOTAL_SECONDS`, a little under it | Tool timeouts are clamped to the time left; without it nothing is |
| Token limit per run | `CTF_TOTAL_TOKENS` | Stops cleanly instead of being cut off |
| Model's max output tokens / context size | `CTF_MAX_OUTPUT_TOKENS` | Upper rungs ask for 16K and 32K; a smaller model rejects that outright |
| The model is a reasoning model (preflight check 6 says so) | `CTF_MIN_OUTPUT_TOKENS=8192` or more | Hidden reasoning counts against `max_tokens`; rung 0's 4096 can be spent before it acts |
| Small context window | `CTF_HISTORY_SOFT_CHARS`, `CTF_HISTORY_HARD_CHARS` | Defaults (40K / 160K chars) assume roughly 64K tokens or more |
| Flag format | `CTF_FLAG_REGEX` | Default handles `CTF{..}` and prefixed forms like `DCTF{..}` only |
| A wrong-flag penalty | `CTF_PENALIZE_WRONG=1` | Turns off ungrounded and repeat submissions |
| Free wrong flags (the expected case) | `CTF_MAX_GUESSES` (default 8) | Ungrounded guesses per challenge; one challenge sent 22 before the cap |
| A challenge is a whole machine, not one port | `CTF_TARGET_SCOPE=host` | The default refuses other ports on the target host, which is right only on shared infrastructure |
| The model cannot see images (preflight check 7) | `CTF_VISION=0` | Drops `view_image` from the tool list |
| A time limit well above or below 20 minutes | `CTF_LADDER_DEPTHS` | Turns per rung (default 12, 25, 40, 60); GLM's median turn was 9 s (p90 46 s), and 20 minutes was 40 to 70 turns. Depth never bound in testing; time did |
| A model much slower or faster than GLM 5.3 Flash | `CTF_MODEL_TIMEOUT` (shipped: 180) | Set from 1,556 GLM turns (p99 132 s); recheck with the contest model's preflight timings |
| A very short time limit | `CTF_OPENAI_SEND_EFFORT=1`, if the model honours it | Faster turns but erratic: 3 of 4 runs fast, 1 collapsed. Off by default |
| Cached input is free | raise `CTF_HISTORY_SOFT_CHARS` | Trimming old results breaks the cache prefix |

Put the final values in `contest.env`; commented examples for each are already
there. The remaining size knobs are in `harness/agents/limits.py`.

## Platform inputs (still open)

The harness also needs to be told the challenge and how to submit. That depends
on the starter kit, which is not out yet. Whether the contest uses CyberEDU's
MCP server is not known either, so both routes are prepared.

- `CTF_PLATFORM` selects the adapter: `files`, `benchmark`, `cyberedu`, or
  `module:Class` for your own.
- `CTF_CHALLENGE_ID` or `--challenge` picks the challenge; with neither, the
  first one the platform lists is used.
- **Route A, your own adapter:** fill in the four methods in
  `harness/platforms/starter_kit.py` and uncomment its `CTF_PLATFORM` line in
  `contest.env`. `harness/platforms/kit.py` gives you `http_json` (a 4xx is an
  answer, only a missing answer raises), `http_download` (real file names),
  `conn_from` (every address form, and an error when it cannot be read) and
  `describe` (per-flag questions into the description).
- **Route B, CyberEDU's MCP server:** it is in the image under
  `/opt/cyberedu-mcp`, off the agent's path and idle unless selected. Set
  `CTF_PLATFORM=cyberedu` and `CTF_CONTEST_ID=<slug>`; the cookie is read from
  `CYBEREDU_SESSION_COOKIE` at run time. Practice mode is proven by 23
  rehearsal runs; **contest mode has not met a live contest.**
- **Either way, run `python -m harness.adapter_check` before uploading.** It
  walks the adapter as a run does and prints what the agent would be told.

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

## Known gaps

- **Anthropic adapter and thinking.** It does not pass thinking blocks back, so
  rungs with a thinking budget will likely be rejected on a real Anthropic API.
- **Single model.** With one model and `CTF_OPENAI_SEND_EFFORT` unset, the four
  rungs differ only in temperature, output cap and depth.
- **Stuck detection.** "No new evidence" counts bytes, so a repeated error
  message looks like progress. Repeated identical commands are caught.
- **`HttpTool` keeps no cookies** between calls. The agent can use `curl` with a
  cookie jar from `shell`.
- **Prompts and ladder depths** have met one real model (GLM 5.3 Flash) on
  real CyberEDU challenges in two batches (`REHEARSAL_REPORT.md`,
  `FINAL_REPORT.md`). Ladder depth never bound; the time limit did. Restarts
  were forced on the offline suite: the handover notes carry the established
  facts with exact values and the next attempt builds on them; images do not
  survive a restart. A clean context at every rung change
  (`CTF_FRESH_CONTEXT=1`) nearly doubled wall time and stays off.
- **Rung 0's 4096 output tokens is small for a reasoning model.** Set
  `CTF_MIN_OUTPUT_TOKENS` to raise every rung's floor. Without it the solver
  still recovers: a turn cut off with nothing produced doubles the cap for the
  rest of the challenge, at the cost of that one wasted turn. Preflight check 6
  reports whether the model reasons and whether it gets cut off.
- **CyberEDU contest mode is checked read-only.** `adapter_check` on DefCamp
  CTF 2025 Quals listed 26 challenges, downloaded a file and showed the
  question; the slug is the last part of the contest's `url`
  (`/competition/dctf25-quals`). Starting a contest service and submitting
  were not exercised. The server cannot stop an instance; instances end after
  CyberEDU's 60 minutes.
- **Toy flags ship in the image** (`/opt/ctf-harness/tests`, `fixtures`). They
  are now collected at start-up and never submitted (`harness/flags/decoys.py`),
  except with the fixtures rig, where they are the answers. Flags in your notes
  are deliberately still submitted.
- **Fixture results need the answers hidden from the agent.** On the host the
  agent read `fixtures/locked-02/challenge.json` and "solved" an unsolvable
  challenge. For any rehearsal suite, run `python scripts/hash_flags.py <suite>`
  so it holds only SHA-256 hashes. The bundled `fixtures/` stay plaintext for
  the tests, so results on them prove plumbing only.
- **The agent runs as the same user as the harness.** Mitigated, not closed:
  known secret values are scrubbed from every tool result, and under the
  rehearsal lockdown the agent's commands lose NET_ADMIN/NET_RAW (which also
  makes `/proc/<harness>/environ` unreadable to them) and may reach only their
  target. A stuck agent did go looking for the cookie twice in rehearsal; the
  boundaries held. A separate user for the agent's shell would close it.
- **gdb cannot disable ASLR** under Docker's default seccomp profile
  (`personality` is blocked); addresses differ from run to run under gdb.
- **Tools the rehearsal wanted** (PHP, an ssh client with `sshpass`, telnet,
  ftp, smbclient, database clients, node, 32-bit libraries, ping/ip/ss,
  matplotlib/scipy, the `mcp` client and CyberEDU's server) are in the
  current `:base` (built 2026-11-17 from `Dockerfile.tools`; the previous base
  is kept as `ctf-harness:base-1115` and `~/ctf-harness-base-1115.tar.gz`).
  nmap's file capabilities are stripped so it runs when a sandbox drops
  NET_RAW. `check_image.py` passes 74/74 as root, read-only, as uid 1000 and
  with NET_RAW dropped. Wine is left out.
- **The scope guard is a guard, not a firewall.** With the default
  `CTF_TARGET_SCOPE=service` it refuses scanners and other ports on the target
  host, and a script that builds an address at run time gets past it. The
  contest sandbox's own isolation is the real boundary there.
- **The contest configuration (`CTF_PENALIZE_WRONG=0`) has run on the
  offline suite only** (5 of 6 solved), not on CyberEDU, to keep junk off the
  account. It led to two fixes: a lettered prefix is tried first, and
  ungrounded guesses are capped (`CTF_MAX_GUESSES`).
- **Unpinned downloads:** RsaCtfTool, jwt_tool and the Foundry installer
  follow upstream HEAD. The base image is pinned by digest; bump it
  deliberately, never on contest day (a new base invalidates every cached
  layer and turns a 4 s rebuild into a 30 min one that needs the network).
- **Kali rolling moves.** Python is 3.14 there now; packages built for older
  Pythons fail to install. Build failures after a base bump are most
  likely this.
