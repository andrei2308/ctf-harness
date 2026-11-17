# Rehearsal report: real CyberEDU challenges

Rehearsal run per `CLAUDE_CODE_REHEARSAL.md`, 2026-11-16 and 2026-11-17,
on branch `contest-readiness`. The day-by-day interim notes are in
`REHEARSAL_PROGRESS.md`.

**Verdict: 6 of 13 eligible challenges were solved on the first attempt; 9 of
13 after the fixes.** All the re-run gains came from harness fixes, not
prompt tuning. 20 harness defects were found on real challenges and fixed,
each with a test (204 pass).

## Setup

| | |
|---|---|
| Model | GLM 5.3 Flash (z.ai, OpenAI-compatible); `CTF_MIN_OUTPUT_TOKENS=8192` |
| Platform | CyberEDU practice catalogue through the official MCP server, run in `Dockerfile.rehearsal` (never uploaded) |
| Per run | 1200 s, 1.5M tokens, `CTF_PENALIZE_WRONG=1`, fresh container, firewall on |
| Set | 16 Entry Level and Easy challenges Andrei approved (9 subscribed for this); none written up in `ctf-notes`. 3 dropped (see table) |
| Spend | 23 runs, **10.6M tokens of the agreed 25M** |

## Results

One row per challenge; re-runs follow the run that motivated them. "Class" is
the failure class from the brief.

| Challenge | Category | Diff. | Result | Time | Tokens | Turns | Rung | Wrong subs | Class / what decided it |
|---|---|---|---|---|---|---|---|---|---|
| wifi-get-me | network | Easy | **solved** | 42 s | 17K | 4 | 0 | 0 | Earlier runs: harness defects (no way to submit a non-flag answer; flag format hidden in the question) |
| bdlp | crypto | Entry | **solved** | 42 s | 11K | 4 | 0 | 0 | — |
| encryptor | rev | Easy | **solved** | 99 s | 94K | 11 | 0 | 0 | — |
| ret2win | pwn | Easy | unsolved | 1246 s | 918K | 61 | 2 | 4 | **Harness defect:** the netcat service address was not understood, so the agent was told there was no target |
| ↳ re-run | | | **solved** | 107 s | 40K | 7 | 0 | 0 | Fix confirmed |
| zodiac | forensics | Easy | unsolved | 1205 s | 612K | 50 | 2 | 0 | **Tool gap:** no vision; read handwriting by OCR for 19 min |
| ↳ re-run | | | **solved** | 264 s | 198K | 22 | 1 | 0 | `view_image` read it at 73 s |
| adding-in-parts | forensics | Easy | **solved** | 716 s | 191K | 18 | 1 | 1 | The wrong submission was the original event's (TFC) flag; CyberEDU re-hosts with its own |
| puzzled | web | Easy | **solved** | 669 s | 231K | 22 | 1 | 0 | Wanted to run the leaked PHP; no interpreter in the image |
| investigator | forensics | Easy | **solved** | 433 s | 403K | 27 | 1 | 1 | **Harness defect:** a planted `DCTF{Try Hard...}` was auto-submitted (fixed: format check) |
| hidden-cipher | network | Easy | **solved** | 1155 s | 1.39M | 72 | 2 | 0 | 45 s to spare. **Wrong routing** (pwn); no ssh client in the image |
| fair-dice | misc / service | Easy | unsolved | 1221 s | 453K | 44 | 2 | 0 | **Harness defects:** routing (a CWE tag contains "rev"); a dead socket reused for 4 min |
| ↳ re-run | | | unsolved | 1202 s | 137K | 19 | 1 | 0 | **Model limit / budget:** slow bot scripts over the network. Also routed to pwn by its port (fixed after) |
| badimg | web | Easy | unsolved | 1205 s | 938K | 52 | 2 | 0 | **Wrong routing** (pwn, via a MITRE "Exploit" tag); steady progress |
| ↳ re-run | | | unsolved | 1200 s | 674K | 47 | 2 | 0 | **Budget shape:** routed right, got deep (LFI, credentials, filters), out of time |
| Poarta | rev | Entry | unsolved | 1266 s | 734K | 39 | 2 | 0 | **Model limit:** Heaven's Gate obfuscation (2 solvers ever). Wanted Wine |
| universe | stego | Easy | unsolved | 1231 s | 769K | 42 | 2 | 0 | **Model limit:** half the hidden data found |
| ↳ re-run | | | unsolved | 1353 s | 145K | 14 | 1 | 0 | **Harness defect:** model calls not capped by the time left (one GLM call ran 526 s, overran by 153 s) |
| biscuiti | network | Easy | dropped | — | 848K | — | — | — | Both flags already solved on the account (flag 2 is a site question) |
| Linux Memory Forensics | forensics | Entry | unsolvable here | 1230 s | 1.16M | 71 | 2 | 2 | **Environment:** file on Google Drive, no internet. The agent then probed the harness for 18 min |
| Digital Dust | stego | Easy | dropped | — | — | — | — | — | Five site questions, not flags |

Eligible: 13 (16 approved, less biscuiti and Digital Dust, which are site
questions, and Linux Memory Forensics, whose file needs the internet).

- **Solved on the first attempt (6):** bdlp, encryptor, adding-in-parts,
  puzzled, investigator, hidden-cipher.
- **Solved after fixes (3 more):** wifi-get-me, zodiac, ret2win.
- **Unsolved (4):** fair-dice, badimg, Poarta, universe.

## Fixes, each with the failure behind it

All on `contest-readiness`, each with a regression test.

| # | Commit | Failure seen | Fix |
|---|---|---|---|
| 1 | `e854a2b` | Host `.venv` (40 MB) and `build.log` inside the submission image | `.dockerignore` mirrors `.gitignore`, incl. credential-shaped files |
| 2 | `a374b17` | Adapter used guessed tool names; could not work | Rewritten from the server source, checked live; practice catalogue + contests |
| 3 | `a374b17` | Agent can read `/proc/1/environ` in one container | Known secret values scrubbed from every tool result |
| 4 | `4c7c3a2` | pingster: the stuck agent port-scanned the CyberEDU node and opened other users' instances | Scope line in prompt; shell guard; **egress firewall** (rehearsal image) |
| 5 | `9fc8453` | zodiac: no vision | `view_image` (falls back to text for blind models) |
| 6 | `46aa70b` | biscuiti: one flag re-sent 323 times in 21 min on a 403 | A 4xx is an answer; transport retries back off and give up |
| 7 | `c0f5cc1` | Files arrived as `downloaded_file` | Real file names; grader message logged |
| 8 | `0056093` | wifi-get-me: a cracked password could not be submitted | `submit_flag` tool, grounded on independent output |
| 9 | `e8e532b` | wifi-get-me: flag format only in the per-flag question | Questions shown (allowlisted fields only), approved by Andrei |
| 10 | `53f1b24` | Linux Memory Forensics: agent used the platform API while hunting the cookie | Agent commands in their own group; the firewall lets that group reach only the target |
| 11 | `53f1b24` | Junk `CTF{, flag{, ...}` submitted from the harness's own log | Flag bodies exclude `{`; the harness source is a decoy source |
| 12 | `5da1189` | hidden-cipher routed to pwn by its port | Network → forensics; any specialist gets the tools for a live target |
| 13 | `8f95cb3` | fair-dice routed to rev ("Previous" ⊃ "rev") | Category = CyberEDU `default` tags only; word-start matching; skill tags become hints |
| 14 | `8f95cb3` | fair-dice: dead socket "reused" for 4 min | Errors close the session; `connect` is always fresh; closure reported |
| 15 | `788dd4c` | investigator: planted lookalike flag submitted | A stated hash format (`{sha256}`) rules out non-matching candidates |
| 16 | `b4d4057` | ret2win: `nc HOST PORT` address read as "no target" | All address forms parsed; an unreadable one fails loudly |
| 17 | `b4d4057` | HTTP 429 on a burst of submissions treated as final | 429 is retryable |
| 18 | `40f0771` | universe: a model call ran past the budget (+153 s) | Every model call is capped by the time left, like tool calls |
| 19 | `d250ba9` | fair-dice re-run: "Misc" with a port went to pwn | Explicit misc goes to the generalist |
| 20 | `a4d81bb` | (verification) | Submission response shapes checked live |

## Answers to the brief's questions

**`CTF_MIN_OUTPUT_TOKENS` for GLM:** use **8192**. Only 4 of about 600
turns were cut at the limit, all during multi-minute "thinking" turns. At
rung 0's default of 4096, the earlier fixture runs lost turns this way.

**Turns per solve, by category:** network 4 and 72, crypto 4, pwn 7, rev 11,
forensics 18–27, web 22. The median solve took 18 turns. With GLM at
**15–30 s per turn**, a 20-minute run is about **50 turns**. The ladder
depths (12, 25, 40, 60) were never the binding constraint: time ran out
first. 4 of 9 solves finished within rung 0's 12 turns.

**Do clean-context restarts help? Do handover notes carry the right facts?**
They were **never triggered**: no run got past rung 2 within 1200 s. This
can't be answered from this rehearsal, and it would need longer budgets.

**Is 8 KB per tool result too tight?** Not a blocker. There were 0–4
truncations per run, mostly disassembly and pcap dumps. The full output is
saved to a file the agent can grep, and the agent used that. One run said
"maybe I missed parts (awk truncated output)". **Keep 8 KB.**

**Notes usage:** a note was opened in 9 of 21 runs, usually once or twice.
It clearly helped in wifi-get-me (opened at turn 1, then a direct solve).
The index sometimes lists irrelevant notes for broad categories (misc,
stego).

**`gdb` / `strace` / `ltrace` under Docker's default profile:** all **work**,
with and without the rehearsal lockdown. Caveat: **gdb cannot disable
ASLR** (`personality` is blocked by the default seccomp profile), so
addresses change from run to run under gdb.

## Recommended contest settings

`contest.env`, once the model and limits are announced:

- `CTF_PENALIZE_WRONG=0` (wrong flags are free at the contest; this
  rehearsal used 1).
- `CTF_MIN_OUTPUT_TOKENS=8192` if the contest model is a reasoning model;
  preflight check 6 says so.
- `CTF_TOTAL_SECONDS` a little under the announced limit. Every run that ran
  out here was still making progress or slowly closing in.
- `CTF_FLAG_REGEX`: if DefCamp confirms `CTF{sha256}`-style flags, set it to
  match that exactly, e.g. `(?i)(?<![a-z0-9])[a-z]{0,8}ctf\{[0-9a-f]{64}\}`.
  This removes lookalike and junk candidates at the source.

No ladder change is recommended: depth never bound, time did.

## Failures not fixed, and what would fix them

| Failure | What would fix it |
|---|---|
| Poarta, universe, fair-dice, badimg: out of time while progressing | A longer per-run budget (organizers' choice) or a faster model. Nothing in the harness |
| No PHP interpreter (puzzled), no ssh client (hidden-cipher), no Wine (Poarta) | Add `php-cli`, `openssh-client`, `sshpass` (small) and possibly `wine` (large) in a tool layer, then re-tag `:base` and redo the backup. **Andrei to decide** |
| gdb cannot disable ASLR | Only `--security-opt seccomp=unconfined` on the organizers' side. Mention it in the pwn prompt if they don't allow it |
| A stuck agent turns on its own environment (fixtures, logs, cookie hunt) | The boundaries held (firewall, capability drop, scrubbing). Full isolation needs the agent's shell to run as a **separate user** (out of scope) |
| With a penalty, a value read from an image can never be grounded; zodiac spent about 3 of its 4½ minutes laundering one into tool output | A decision: allow a capped `submit_flag` for values read with `view_image`. Not an issue with the contest's free wrong flags |
| The server cannot stop instances | They end after 60 min. Nothing to do without a server change |

## Where things are

- **Base image backup:** `~/ctf-harness-base.tar.gz` (5.1 GB, `pigz`,
  integrity checked). Restore with `docker load < ~/ctf-harness-base.tar.gz`,
  then `docker build -f Dockerfile.contest -t ctf-harness:latest .`, which
  takes under 4 s and needs no cache.
- **Rehearsal kit and logs:** `~/Desktop/ctf-rehearsal/`, outside the repo
  because the challenges are CyberEDU's. It holds every run log, the token
  ledger, per-run statistics and the transcript review notes.
- **Offline regression suite (step 7): not done.** The solved static
  challenges (encryptor, bdlp, investigator, adding-in-parts, zodiac,
  wifi-get-me) are the candidates, with `flag_sha256` only, kept outside the
  repo.
