# Validation report: `local-validation`

Run on Andrei's Kali machine, 2026-11-15, following `CLAUDE_CODE_TASKS.md`.

**Verdict: ready to merge.** Every "Done means" condition is met:
- `check_image.py` exits 0 (57/57).
- The offline run solves `warmup-01` with `--network none`.
- A `contest.env` rebuild needs no network, and the build now enforces that.
- GLM 5.3 Flash solved both required fixtures on the host and in the image.

Getting there took 6 build breakages, 1 settings file missing from the repo, and 8 harness or check defects. All are fixed, each harness fix with a regression test. One task step was redefined (step 7, below). The largest remaining risk: the real-model rehearsal has only covered toy fixtures (see Open items).

## Results

| # | Task | Result | Key numbers |
|---|---|---|---|
| 1 | Prepare | PASS | x86_64; Docker 27.5.1, overlay2; 169 GB free under `/var/lib/docker` |
| 2 | Host tests | PASS after fix | Started at 114/115: `contest.env` was missing from the repo. Now **126 passed** (115 + 11 new regression tests) |
| 3 | Sync notes | PASS | 66 files, 468 KB; `knowledge/ctf-notes/` stays out of `git status` |
| 4 | Full build | PASS after 6 fixes | Image **14.3 GB** (14,258,504,467 B). Cold build ≈ **28–30 min**, estimated from two partial runs: apt layers ≈ 13.5 min, everything after them 880 s. No single clean cold run was timed |
| 5 | Image as the agent sees it | PASS | **57/57**, 0 critical, 0 optional missing. In-image pytest **126 passed** |
| 6 | Offline end-to-end, `--network none` | PASS | `warmup-01` solved; `multi-03` solved, `flags_accepted: 2`; `locked-02` unsolved as expected. stdout is JSON; stderr has only JSON event lines |
| 7 | Rebuild loop | PASS, redefined | Rebuild after a `contest.env` edit: **3.3–3.9 s**. `docker build --network none` cannot pass on BuildKit (see below), so the network-free guarantee is now enforced inside the Dockerfile |
| 8 | Export | PASS | `docker save \| gzip`: **5.1 GB** (5,464,802,206 B) in **1215 s**. Uncompressed image 14.3 GB. Tarball deleted afterwards |
| 9 | Real-model rehearsal | PASS | GLM 5.3 Flash (z.ai, OpenAI-compatible). Preflight exit 0. `warmup-01` and `multi-03` solved on the host and in the image. 3 harness defects found and fixed |

### Step 7: why `docker build --network none` is the wrong test

BuildKit includes the network mode in every `RUN` step's cache key. A `--network none` build therefore reuses **no** layer: it restarts at the first `apt-get` and fails there. That would happen with any layer order. The real requirement is that a contest-day rebuild needs no network. A normal rebuild re-executes only `COPY`, `pip install --no-index -e .` and the `ctf-tools` `printf`; all 15 steps before them come from cache. Those two `RUN` steps are now `RUN --network=none`, so the build fails if they ever need the network. I checked that the flag really blocks network access: the same `curl` fails under `--network=none` and succeeds without it.

## Build `WARN` lines

| `WARN` | Cause | Action |
|---|---|---|
| `apt skip yafu` | Not packaged in Kali | Accepted. Sage, pari-gp, RsaCtfTool and gmpy2 cover factoring |
| `apt skip volatility3` | Removed from Kali | **Fixed**: installed from PyPI (2.28.2); `vol` CLI and module both work |
| `apt skip outguess` | Not in the current Kali snapshot | Accepted. steghide, stegseek, zsteg and binwalk are present |
| `apt skip solidity` | Not packaged in Kali | Expected: `solc` comes from `solc-select`. **Fixed** so the agent can run it (see changes) |
| `pip skip wfuzz` | Its `pycurl` 7.43 does not compile on Python 3.14 | Accepted: the apt `wfuzz` is installed and on PATH |

Not a `WARN`, but in the log: `update-alternatives: error: no alternatives for upx`. Harmless; `upx 4.2.4` runs.

I also checked for failures that `|| true` swallows without a `WARN`. That found RsaCtfTool (fixed, below); nothing else.

## Final `check_image.py` output

```
[PASS] python3 is the venv's
[PASS] pwntools works
[PASS] z3 solves
[PASS] pycryptodome
[PASS] gmpy2 / sympy
[PASS] requests
[PASS] angr imports
[PASS] capstone / unicorn
[PASS] scapy
[PASS] fpylll (lattices)
[PASS] web3
[PASS] volatility3 module
[PASS] gdb runs
[PASS] pwndbg loads (as the gdb tools run it)
[PASS] binutils (objdump/readelf/strings)
[PASS] ROPgadget
[PASS] ropper
[PASS] checksec
[PASS] one_gadget
[PASS] seccomp-tools
[PASS] pwninit
[PASS] patchelf
[PASS] radare2
[PASS] ghidra headless
[PASS] qemu-user
[PASS] ltrace / strace
[PASS] sage factors
[PASS] RsaCtfTool runs
[PASS] pari-gp
[PASS] binwalk
[PASS] exiftool
[PASS] tshark
[PASS] volatility3 CLI
[PASS] foremost / scalpel
[PASS] 7z / unrar
[PASS] steghide / stegseek
[PASS] zsteg
[PASS] tesseract
[PASS] ffmpeg / sox
[PASS] john
[PASS] hashcat
[PASS] rockyou.txt
[PASS] seclists
[PASS] curl
[PASS] sqlmap
[PASS] ffuf / gobuster
[PASS] jwt_tool
[PASS] nmap / nc / socat
[PASS] apktool / jadx
[PASS] forge / cast (foundry)
[PASS] solc runs with the agent's HOME
[PASS] ghidra_decompile tool decompiles
[PASS] volatility tool reaches Volatility
[PASS] openai SDK importable by the harness
[PASS] contest.env is in the image
[PASS] ctf-notes are in the image
[PASS] a planted ~/.profile is not sourced

57/57 passed; 0 critical failure(s), 0 optional tool(s) missing
```

The known suspects from the task list:
- **PATH:** the agent gets `/opt/venv/bin/python3`.
- **pwndbg:** works; see changes.
- **solc:** runs with the agent's `HOME`.
- **Large installs:** Sage 10.10, Ghidra 12.2 headless and Foundry (`forge` 1.9.0) are all present; volatility3 2.28.2 is installed from PyPI.
- **rockyou.txt:** unpacked, 140 MB.

## Changes and reasons

Commits on `local-validation`, oldest first.

**`8b2cb14` `contest.env` was never in the repo.** `.gitignore`'s `*.env` rule also matched it, so every clone and image lacked the settings file. That failed `test_shipped_settings_file…` and `check_image`'s critical `contest.env` check, and the image never had `CTF_BACKEND=openai`. Added `!contest.env` and recreated the file from `HANDOFF.md`. Active lines are only `CTF_BACKEND=openai` and `CTF_LOG_MIRROR=1`; everything else is a commented example, and it holds no key. **Andrei: if your original local copy had more lines, re-add them.**

**`a900bd9` Image build and tools.** Current Kali rolling moved to Python 3.14 and dropped packages.
- `openjdk-17-jre-headless` no longer exists, which failed the core layer. Now `default-jdk-headless`, currently JDK 25, which Ghidra 12.2 requires (`application.java.min=25`).
- `pwndbg` is not on PyPI (only an old Python 2 upload) and not in Kali, which failed the critical pip line. Now the official portable release 2026.10.28, pinned by sha256, which bundles its own gdb and Python. Andrei chose this.
- `ropper`'s dependency `filebytes` 0.10.2 uses `ast.Str`, removed in Python 3.14, which also failed the critical pip line. Moved to a best-effort layer; `filebytes` comes from upstream's unreleased fix commit (pinned).
- `volatility3` comes from PyPI (no Kali package).
- `solc-select`'s shim looks for compilers under `$HOME`, but the agent's `HOME` is the work dir. The real `solc` 0.8.26 is now installed at a fixed path and linked from the venv.
- `FROM` is pinned by digest. With a bare tag, any `docker pull` of `kali-rolling` threw away every cached layer. I triggered exactly that once: the next rebuild took 15 minutes and needed the network.
- Harness fixes, each with a test:
  - **`gdb_session` leaked the model API key.** It started gdb with the harness's full environment, so `shell env` in gdb printed `OPENAI_API_KEY`. It now gets the same stripped environment as the agent's shell (`agent_env()`, shared with `LocalExecutor`).
  - **Both gdb tools now launch `CTF_GDB`** (`pwndbg` in the image) and fall back to plain `gdb` when it isn't on PATH. Under pwndbg they turn its ANSI colours off, which cost the model tokens.
  - **`ghidra_decompile` always failed.** Ghidra rejects any path element starting with `.` (the tool used `.ghidra_proj`). The post-script also moved from Jython to Java, which every Ghidra version compiles itself, and only the decompiled C is returned (≈600 B instead of ≈8 KB of INFO log).
  - **The `volatility` tool always failed when the module was installed.** It tried `python3 -m volatility3` first, and the package has no `__main__`. It now prefers the `vol` CLI.
- `check_image.py` now drives the ghidra and volatility wrappers end to end; "binary is on PATH" missed both bugs. The pwndbg check runs pwndbg exactly as the gdb tools do.

**`6242449` Network-free rebuilds enforced.** See step 7.

**`24c50a6` Defects from the GLM rehearsal** (details in the next section).

**`78eeeb4` RsaCtfTool.** Upstream moved `RsaCtfTool.py` into `src/RsaCtfTool/`, so the wrapper pointed at a missing file, yet `check_image` passed it because it only tested that the name was on PATH. The clone is now `pip install`ed, and the check runs the tool.

Also: `build.log` is git-ignored.

## Real-model rehearsal (step 9)

Endpoint: z.ai's OpenAI-compatible API, `https://api.z.ai/api/coding/paas/v4`, model `glm-5.3-flash`. The key was taken from Andrei's local Claude settings at run time and passed only as an environment variable; in Docker it went as `-e OPENAI_API_KEY` with no value, so it never appeared on a command line.

**Preflight:** exit 0 in 23 s. Endpoint reached, usage reported, tool call made, tool result accepted, all four rungs accepted (`max_tokens` 4096, 8192, 16384, 32768).

| Run | Where | Result | Time | Tokens |
|---|---|---|---|---|
| warmup-01 | host, before fixes | solved, 1 attempt | 50 s | 8,904 |
| multi-03 | host, before fixes | solved, 2/2 flags | 11 s | 3,573 |
| locked-02 | host, before fixes | "solved" — **not genuine**, see below | 512 s | 137,765 |
| warmup-01 | image, after fixes | solved, 1 turn | 15 s | 4,301 |
| multi-03 | image, after fixes | solved, 2/2 flags | 14 s | 3,994 |

What the transcripts showed. Defects 1–3 are fixed, each with a test that fails on the old code. Defects 4–5 are reported only.

1. **Relative work dir in the prompt.** The prompt said `Files in your working directory (runs/work/<id>)`. In 2 of 3 runs the model's first command was `cd runs/work/<id>` from inside that dir; it failed, and a 15–30 s `find /` followed. The prompt now gives the absolute path and says the shell already starts there. In the image, `warmup-01` went from 3 turns to 1.
2. **Length-cut empty turns.** GLM 5.3 Flash is a reasoning model. At rung 0 (`max_tokens=4096`) two turns spent the whole budget on hidden reasoning and returned no text and no tool call (`finish_reason=length`). The loop stored an empty assistant message and counted it toward a stall. Now such a turn gets a specific note ("hit the output limit… call a tool now") and does not count toward a stall. `model.turn` also logs `stop`, which was previously invisible.
3. **The task prompt was not logged,** so a transcript could not show what the model was told. Now logged once as `task.prompt`. Confirmed in the image: the 3.7 KB prompt carries the notes index, and in `locked-02` the model's first action was opening `crypto/PLAYBOOK.md § LFSR`, which was relevant.
4. **The `locked-02` "solve" was the agent gaming the environment.** That fixture is unsolvable by design. After stalling, the model read `tests/test_scheduler_e2e.py` and `cat`-ed every `fixtures/*/files`. The harness auto-submitted each `CTF{…}` it saw, three wrong ones before the right one. Fixture results only mean something when the agent cannot read the fixtures. In the contest image the same applies: `/opt/ctf-harness/{tests,fixtures}` hold toy flags an agent could stumble onto and submit. Wrong flags are free, but it is noise.
5. **Minor:** for a vague "misc" challenge the notes index's "likely relevant" picks were pwn ORW notes. Relevance ranking is weak when the category says little.

No malformed or ignored tool calls, no stuck repetition, no flag left unsubmitted, no flag submitted in the wrong form. Token growth was bounded: input rose from 1.7K to 11.6K tokens over 17 turns as `_diet` kicked in.

## Open items for Andrei

1. **Rehearse on real, harder challenges.** This is the largest remaining risk: fixtures are toys. Your CyberEDU account is now reachable. The official `cyberedu-mcp` server is set up for Claude Code at `~/Desktop/cyberedu-mcp`, outside this repo; it needed `mcp<2` pinned locally. It sees about 800 challenges across the CyberEDU, UNbreakable, ROCSC and DefCamp tenants. But **`harness/platforms/cyberedu_mcp.py` cannot work against that server**:
   - every tool name is missing the `cyberedu_` prefix;
   - it sends `contest_id` where the server wants `contest_slug`;
   - `get_contest_challenges` does not exist, and submit needs a `flag_id`;
   - the cookie goes in `CYBEREDU_SESSION`, but the server reads `CYBEREDU_SESSION_COOKIE`;
   - it only handles contests, not the practice catalogue.

   Decide: rewrite the adapter (submissions would record on your account), or convert a set of challenges into offline fixtures.
2. **Rung 0's 4096 output tokens is too small for a reasoning model.** Defect 2 is now handled gracefully, but each cut turn still burns 4K tokens. `CTF_MAX_OUTPUT_TOKENS` can only lower the caps, not raise them. If the contest model reasons, raise rung 0 in `default_ladder`, preferably after seeing the announced model.
3. **Image size.** 14.3 GB raw, 5.1 GB gzipped, 20 min to export single-threaded (`pigz` is not installed here). Acceptable or not depends on the upload limits announced at the contest.
4. **Toy flags inside the image** (`tests/`, `fixtures/`). Excluding them would break the in-image pytest and the step 6 check, so I left them. Decide whether the contest image should ship them.
5. **Unpinned downloads.** `RsaCtfTool`, `jwt_tool` and the Foundry installer follow upstream HEAD, so a rebuild without cache can change them. Pin before the contest if reproducibility matters.
6. **Rotate the CyberEDU session cookie** after rehearsing: it was pasted into a chat and is stored in plain text in `~/.claude.json`.
