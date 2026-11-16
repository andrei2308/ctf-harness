# Rehearsal progress (interim)

Status of the `CLAUDE_CODE_REHEARSAL.md` work as of 2026-11-16, mid-run. The
final write-up will be `REHEARSAL_REPORT.md`. This file records what was done
so far, every change and the failure behind it, and what is still running.

**In one line:** the agent now solves real CyberEDU challenges end to end
inside the contest toolchain. 2 of the first 4 attempted challenges are solved,
and 10 harness defects have been found on real challenges and fixed, each with
a test. The rehearsal batch is still running.

## Setup

- Model: GLM 5.3 Flash (z.ai, OpenAI-compatible API).
- Platform: CyberEDU practice catalogue through the official MCP server, which
  runs in a separate image (`Dockerfile.rehearsal`) that is never uploaded.
- Budget per run: 1200 s and 1.5M tokens. `CTF_PENALIZE_WRONG=1`.
  `CTF_MIN_OUTPUT_TOKENS=8192`. One run at a time, each in a fresh container.
- Tokens used so far: about 3.1M of the agreed 25M ceiling.
- Challenges: 16 Entry Level and Easy ones Andrei approved. 9 of them were
  subscribed for the rehearsal; none were solved on the account before; none
  are written up in `ctf-notes`. Logs and per-run data are kept outside this
  repo (`~/Desktop/ctf-rehearsal/`), since the challenges are CyberEDU's.

## Step 1: verifying what was added since validation

| Check | Result |
|---|---|
| Host tests | 136 passed (now 187 after this work) |
| `Dockerfile.contest` rebuild | 10 s; **3.8 s with `--no-cache`**, so it survives a lost build cache |
| Image check / in-image tests | 57/57, 136/136 |
| Base image backup | `~/ctf-harness-base.tar.gz`, 5.1 GB, `pigz` in 591 s, integrity checked |
| Preflight in the image | exit 0. Check 6 identifies GLM as a reasoning model; with `CTF_MIN_OUTPUT_TOKENS=8192`, rung 0 is 8192 |

Found and fixed in step 1: **the host's `.venv` (40 MB) and `build.log` were
inside the submission image.** `.dockerignore` lacked what `.gitignore` has;
credential-shaped files would have gone in too.

## Results so far

| Challenge | Category | Result | Time | Tokens | What decided it |
|---|---|---|---|---|---|
| wifi-get-me | network / cracking | **solved** | 43 s | 19K | Solved after three fixes (submit_flag, flag questions, submit flood). Earlier runs: answer not flag-shaped; flag format hidden |
| puzzled | web | **solved** | 671 s | 233K | Clean solve on rung 1. Wanted a local PHP interpreter, which the image lacks |
| zodiac | forensics | unsolved | 1205 s | 612K | No vision: read handwriting through OCR and ASCII art; three glyphs short. Re-run with `view_image` is queued |
| universe | misc / stego | unsolved | 1232 s | 771K | Found half of the hidden data; did not decode the stereogram half. Ran before flag questions were shown; to re-run |
| biscuiti | network | dropped | — | 848K | Both flags already solved on the account (flag 2 is a site question); excluded |

Still running, one at a time: Linux Memory Forensics, adding-in-parts,
hidden-cipher, fair-dice, badimg, investigator, bdlp, ret2win, encryptor,
Poarta, then zodiac again.

## Changes, each with the failure that motivated it

All are on `contest-readiness`, each with a regression test (187 tests pass).

1. **CyberEDU adapter rewritten** (`a374b17`). The old one used guessed tool
   names and could not work. It is now written from the server source and
   checked live:
   - covers the practice catalogue (and contests by slug);
   - the cookie comes from `CYBEREDU_SESSION_COOKIE`, is removed from the
     process environment and goes only to the server, which gets a private,
     temporary `HOME`;
   - files are saved inside the work dir;
   - instances are started and awaited (a 400 from the status call means
     files-only);
   - offline tests use a fake transport replaying live response shapes.
   - **The server cannot stop an instance.** It has start, extend and restart,
     but no stop, so an instance ends at CyberEDU's 60-minute lifetime.
2. **Secrets scrubbed from tool output** (`a374b17`). In one container the
   agent can `cat /proc/1/environ`. Every tool result now has known key and
   cookie values replaced before it reaches the model, the log or the evidence
   store. This stops accidental exposure, not a model that sets out to encode
   the value; only a separate user for the agent's shell would.
3. **The agent attacked other people's instances** (`4c7c3a2`). On pingster,
   stuck after 11 minutes, it port-scanned the CyberEDU node hosting its
   instance and opened other ports there, mostly with Python socket loops. The
   run was stopped by hand. Fixes:
   - an explicit scope line in the prompt;
   - a shell guard against scanners and other ports on the target host;
   - **the real boundary, an egress firewall** (rehearsal image, `--cap-add
     NET_ADMIN`). Before the agent starts, iptables allows only the instance,
     the model endpoint, the platform API and DNS. The agent's processes lose
     `NET_ADMIN`/`NET_RAW`, so they cannot undo it even as root. It fails
     closed. Verified live: other ports and hosts are blocked, and
     `iptables -F` is refused.
4. **`view_image`** (`9fc8453`). zodiac: the agent rebuilt handwriting from a
   mouse-movement capture in a minute, then spent 19 minutes reading it
   through OCR. GLM 5.3 Flash accepts images (tested); full `glm-5.3` rejects
   them. The tool shows an image in the next message. A model that rejects
   images is remembered and told in text instead, so the run goes on.
   `CTF_VISION=0` removes the tool.
5. **Submission flood** (`46aa70b`). biscuiti: CyberEDU answered 403 "already
   solved" (an earlier solve on the account). The adapter treated every HTTP
   error as an outage, so one flag was re-sent **323 times in 21 minutes**.
   - A 4xx is now the grader's answer and is never retried.
   - "Already solved" closes that flag and the next one is tried.
   - A flag that does not reach the grader is retried once straight away,
     then backs off (30 s, 60 s, …) and is dropped after 8 rounds.
6. **Real file names** (`c0f5cc1`). Files arrived as `downloaded_file`; the
   challenge lists the real name, and its extension is a clue. The submit log
   now records the grader's message.
7. **`submit_flag` tool** (`9f2ee31`). wifi-get-me asks for a WPA2 password.
   The agent cracked it in 49 s, then repeated it about 40 times: only
   `CTF{...}`-shaped strings could ever be submitted. The new tool takes the
   exact answer. With a penalty it must appear in the output of a command that
   did not itself contain it (`echo` proves nothing), at most 3 per challenge.
8. **Flag questions shown to the agent** (`57010b0`, approved by Andrei). The
   answer format (`ctf{sha256(flag)}`) lives in each flag's question, which
   only the server's `get_flag` returns, and that call was blocked. It is now
   called only to read questions, and only these fields are kept: question,
   description, type, options, multiple, limit, found. Never forwarded:
   `value` (the account's last submission), `rejection_reason` and `hints`
   (unlocking one costs points). Flags already found are skipped before any
   submission; an attempt limit is respected.
9. **`.dockerignore`** (`e854a2b`). See step 1.
10. **Live check of the submission response** (`563223e`). A correct flag
    comes back accepted, a wrong one not, and an already-solved one as 403.

## Rehearsal-side settings (not in the repo)

- Flags are matched as whole tokens:
  `CTF_FLAG_REGEX=(?i)(?<![a-z0-9])[a-z]{0,8}ctf\{...\}`. The default
  submits both the bare and the prefixed form of `DCTF{...}`, and a broader
  prefix picked up hex digits glued to a flag.
- Each run gets an empty logs directory. The agent read the mounted logs of
  earlier runs once, before this change.
- **Contest note:** wrong flags cost nothing there, so the contest setting is
  `CTF_PENALIZE_WRONG=0`, the opposite of this rehearsal.

## Lessons so far that matter for the contest

- **Question text matters.** If the contest platform puts the answer format
  in a per-flag question, as CyberEDU does, the starter-kit adapter must pass
  it to the agent. Without it the agent can solve a challenge and still fail.
- **The flag count in the prompt is believed.** On biscuiti the agent kept
  hunting the capture for a second "flag" that is really a site question.
- **Shared infrastructure needs a network boundary.** A stuck agent widens its
  search; only a firewall reliably stops it at its own instance.
- **No PHP interpreter in the image** (puzzled). It would help PHP-quirk web
  challenges, but needs a full image rebuild. This is a recommendation, not
  done.

## Still to do

- Finish the batch and re-run zodiac and universe with the latest fixes.
- Read every transcript and classify each failure (step 5).
- Answer the brief's step 6 questions with evidence: `CTF_MIN_OUTPUT_TOKENS`,
  turns per solve, restarts, handover notes, the 8 KB result limit, notes
  usage, and gdb/strace under Docker's default profile.
- An offline regression suite of solved static challenges, kept outside the
  repo (step 7).
- The final `REHEARSAL_REPORT.md`.
