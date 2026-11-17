# Status report: ctf-harness, 2026-11-17

Where the harness stands after the local validation (`CLAUDE_CODE_TASKS.md`,
2026-11-15) and the real-challenge rehearsal (`CLAUDE_CODE_REHEARSAL.md`,
2026-11-16/17), with what changed, how to run it and what is still open.
Detail lives in `VALIDATION_REPORT.md` and `REHEARSAL_REPORT.md`. Settings
and day-of procedure are in `HANDOFF.md`.

## In short

- **The submission image works** as the agent sees it: 57/57 tool checks, the
  full test suite inside the image, offline end-to-end solves.
- **A rebuild survives a lost build cache.** `Dockerfile.contest` builds in
  under 4 s with `--no-cache`, needs no network, and starts from a backed-up
  base image.
- **The agent solves real challenges.** On 13 CyberEDU challenges with GLM 5.3
  Flash it solved 6 on the first attempt, and 9 after the fixes. The 4 still
  unsolved ran out of time while progressing.
- **27 harness defects were found and fixed**: 7 in validation and 20 in
  rehearsal. Each has a regression test; 204 tests pass.
- **The contest-day unknowns are unchanged:** the starter-kit adapter, the
  model, the limits and the flag format.

## What was done

### Phase 1: local validation (2026-11-15), branch `local-validation`, merged to `main`

- **The image built only after fixes for the current Kali**: JDK 17 removed,
  Python 3.14, pwndbg not on PyPI, `filebytes` broken on 3.14, volatility3
  dropped from Kali, `solc` tied to `$HOME`.
- **The base image is pinned by digest**, and rebuilds after a `contest.env`
  edit are enforced network-free (`RUN --network=none`).
- **Harness bugs fixed:**
  - `contest.env` was never committed;
  - `gdb_session` leaked the model key;
  - the Ghidra wrapper always failed (a dot-directory);
  - the Volatility wrapper always failed;
  - RsaCtfTool was a dead wrapper;
  - a relative work dir in the prompt made the agent `cd` in circles;
  - length-cut empty turns counted as stalls.
- First real-model run (GLM, toy fixtures): solved; the transcripts led to the
  last three fixes.

### Phase 2: rehearsal on CyberEDU (2026-11-16/17), branch `contest-readiness`

- **The CyberEDU adapter was rewritten** against the real server. It covers the
  practice catalogue and contests, shows each flag's question (allowlisted
  fields only), and never calls flag retrieval.
- **Rehearsal image** (`Dockerfile.rehearsal`, never uploaded), with an
  **egress firewall**: the agent's commands reach only their challenge.
- **New agent capabilities:**
  - `view_image` (vision);
  - `submit_flag` for answers that are not `CTF{...}`;
  - service tools for any specialist with a live target.
- **Flag handling hardened:**
  - polite submission (a 4xx is an answer; 429 and outages back off);
  - a stated hash format filters lookalikes;
  - flag bodies cannot span braces;
  - the harness's own source is a decoy source;
  - secrets are scrubbed from tool output.
- **Routing:**
  - the category comes from CyberEDU's category tags only;
  - keywords match at a word start;
  - network → forensics;
  - misc → generalist.
- **Robustness:**
  - dead sockets are never reused;
  - netcat-style addresses are understood;
  - model calls are capped by the time left.
- **Rehearsal results:** see the table in `REHEARSAL_REPORT.md`.
- **Base image backup:** `~/ctf-harness-base.tar.gz` (5.1 GB).

## Current state

| Item | State |
|---|---|
| Branch `contest-readiness` | Pushed; ahead of `main`; not merged |
| Tests | 204 pass on the host and in the image |
| `ctf-harness:latest` | Built from the current branch; 57/57 checks |
| `ctf-harness:base` | Validation-day image; backup at `~/ctf-harness-base.tar.gz` |
| `ctf-harness:rehearsal` | Current branch plus the CyberEDU server; never uploaded |
| Token spend | 10.6M of the 25M GLM ceiling agreed for the rehearsal |

## How to run it

| Task | Command |
|---|---|
| Contest-day rebuild | `docker build -f Dockerfile.contest -t ctf-harness:latest .` |
| Restore a lost base | `docker load < ~/ctf-harness-base.tar.gz` |
| Check the image | `docker run --rm ctf-harness:latest python scripts/check_image.py` |
| Check an endpoint | `python -m harness.preflight`, then the same inside the image (`HANDOFF.md`) |
| One CyberEDU rehearsal run | `~/Desktop/ctf-rehearsal/rehearse.sh <challenge-id>` |
| A rehearsal batch | `~/Desktop/ctf-rehearsal/batch.sh`, reading a set JSON |

## Recommended contest settings

- `CTF_PENALIZE_WRONG=0`: wrong flags are free at the contest.
- `CTF_MIN_OUTPUT_TOKENS=8192` if the model reasons; preflight check 6 says
  so.
- `CTF_TOTAL_SECONDS` a little under the announced limit.
- `CTF_FLAG_REGEX` once the flag format is confirmed. For `CTF{sha256}`:
  `(?i)(?<![a-z0-9])[a-z]{0,8}ctf\{[0-9a-f]{64}\}`.
- No ladder change: time bound in every unsolved run, depth never did.

## Open decisions (Andrei)

1. **Image tools:** add `php-cli`, `openssh-client` + `sshpass` (small) and
   possibly Wine (large). Each change is a tool-layer rebuild, a new `:base`
   and a new backup.
2. **Answers read from images under a wrong-flag penalty** cannot be grounded
   in tool output. Allow a capped `submit_flag` for them? This does not arise
   with the contest's free wrong flags.
3. **Merge `contest-readiness` into `main`.**
4. **An offline regression suite** from the solved static challenges (hashes
   only, outside the repo); not done.

## Known limits that remain

- **Time, not the harness, decided every remaining failure.** At GLM's 15–30 s
  per turn, 20 minutes is about 50 turns.
- **The agent's shell runs as the same user as the harness.** Secrets are
  scrubbed and the rehearsal lockdown holds, but only a separate user would
  fully isolate it.
- **gdb cannot disable ASLR** under Docker's default seccomp profile.
- **CyberEDU contest mode** is untested live, and the server cannot stop
  instances.
- **The starter-kit adapter** (`harness/platforms/starter_kit.py`) can only be
  written when the contest starts.
