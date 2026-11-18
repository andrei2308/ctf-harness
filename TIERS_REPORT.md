# Smaller image tiers: report

Claude Code, 18 November 2026, on Andrei's Kali machine, following
`CLAUDE_CODE_TIERS.md`. Branch `image-tiers`. `main` is untouched (`b4c4f12`).
Build logs, check outputs and usage tables: `~/Desktop/ctf-rehearsal/tiers/`.

## The answer

| Base tag | Raw | Compressed (`docker save \| pigz`) | What it lacks against the full image |
|---|---|---|---|
| `ctf-harness:base` | 15.09 GB | 5.75 GB (`~/ctf-harness-base.tar.gz`) | nothing; the image every rehearsal ran on |
| `ctf-harness:base-medium` (`fd52b05a0af4`) | 6.62 GB | 2.65 GB (`~/ctf-harness-base-medium.tar.gz`) | SageMath, hashcat, qemu-user, commix (and the metasploit it drags in), 99% of SecLists, docs |
| `ctf-harness:base-core` (`14834adbc17b`) | 2.91 GB | 0.93 GB (`~/ctf-harness-base-core.tar.gz`) | also Ghidra, all Java tools (jadx, apktool, dex2jar, smali), pwndbg, Foundry, ffmpeg, tesseract, ImageMagick, node, database clients, smbclient, hydra, second-line web scanners, matplotlib/scipy |

SHA-256 of the backups:

```
5e528a7e7dfdd911d42aa4205cfaead540cadced02974650d2eabe914af7d01d  ctf-harness-base-core.tar.gz
bff7a88e60ad8d326075d701c2583e6a04dbd8e44b44e6256fb9ab4c9f54fa30  ctf-harness-base-medium.tar.gz
```

On the day: `docker build -f Dockerfile.contest --build-arg BASE=<tag> -t ctf-harness:latest .`
Takes 3-6 s with no network for either tier (measured).

**The price of core, measured:** on the offline suite with GLM 5.3 Flash, core
solved the same five challenges as the full image (3 at the first pass,
investigator and adding-in-parts on the one re-run each; zodiac is unsolved on
both images). The cost shows on the APK challenge: without jadx it took 971 s
and 1.2M tokens against 322 s and 0.47M on the full image, and failed once at
the token cap. See section 4.

## 1. Where the 15 GB is

From `docker history`, `dpkg-query Installed-Size` and `du` on `ctf-harness:base`.
The apt layer alone is 8.19 GB; the Python venv 0.85 GB + 0.63 GB; pwndbg 0.69 GB;
the CyberEDU server and image extras 0.82 GB; the Kali base 0.12 GB.

| # | Item | Installed MB | Brought in by | core | medium |
|---|---|---|---|---|---|
| 1 | SecLists | 1,846 | `seclists` | 11 MB subset | 11 MB subset |
| 2 | Python venv `/opt/venv` | 1,749 | pip | 1,260 | 1,584 |
| 3 | mingw-w64 cross-compilers (gcc x86-64 + i686, dev, runtimes, common) | ~790 | metasploit-framework | no | no |
| 4 | Ghidra | 828 | `ghidra` | no | yes |
| 5 | pwndbg `/opt/pwndbg` | 752 | release tarball | no | yes |
| 6 | metasploit-framework | 602 | **`commix` depends on it** | no | no |
| 7 | OpenJDK 25 (JDK 349 + JRE 235) | 585 | `default-jdk-headless`; Ghidra, jadx | no | yes (Ghidra's dependency) |
| 8 | qemu-user | 461 | `qemu-user` | no | no |
| 9 | `/usr/share/doc` | 394 | every package | no (dpkg excludes) | no |
| 10 | `/usr/lib/gcc` | 373 | build-essential | yes | yes |
| 11 | Foundry, second copy in `/root/.foundry` | 294 | foundryup | no | no (one copy in `/usr/local/bin`) |
| 12 | libpocl2t64 (OpenCL on CPU) | 282 | hashcat | no | no |
| 13 | python3-sage | 231 | sagemath | no | no |
| 14 | oracle-instantclient-basic | 205 | metasploit-framework | no | no |
| 15 | GAP (libs, transgrp, table-of-marks) | ~163 | sagemath | no | no |
| 16 | libboost1.92-dev | 159 | sagemath | no | no |
| 17 | `/usr/share/locale` | 160 | every package | no | no |
| 18 | libllvm21 | 133 | pocl, clang | no | yes |
| 19 | libwireshark19 | 132 | tshark | yes | yes |
| 20 | hashcat + hashcat-data | 151 | `hashcat` | no | no |
| 21 | Maxima (sage + share) | 77 | sagemath | no | no |
| 22 | john + john-data | 164 | `john` | yes | yes |
| 23 | python3-scipy + python3-networkx (apt) | 211 | sagemath | no | no |
| 24 | jadx | 74 | `jadx` | no | yes |
| 25 | libnode137 | 70 | nodejs | no | yes |

Three findings from this table that the first cut did not know:

- **`commix` costs 1.8 GB.** In Kali it depends on `metasploit-framework`, which
  pulls Oracle Instant Client and both mingw toolchains (items 3, 6, 14). No run
  ever called commix. Dropped from medium.
- **The full image has `qemu-user`, not `qemu-user-static`** (the main
  `Dockerfile` lists both; `-static` does not install there). Medium listed
  `-static` as "kept"; it costs 484 MB and qemu was never run. Dropped.
- **Sage's real size is its stack**: python3-sage itself is 231 MB, but GAP,
  boost, Maxima, giac, R and the apt scipy/networkx come with it.

## 2. What the agent used

`scripts/tool_usage.py` over every log in `~/Desktop/ctf-rehearsal`: 100 logs,
95 challenge runs with tool calls, 56 solved. The name list includes heredoc
noise (`EOF`, `flag`, `break` ...), so every name the script marked `-` was
checked against the full image (`command -v` + `dpkg -S`); only real programs
are listed. "In the flag command" means the program appears in the command
that grounded the accepted flag (`flag.candidate` source).

Top of the table (runs / solved): python3 82/45, file 72/42, strings 54/26,
xxd 43/29, tshark 33/17, unzip 27/21, objdump 17/8, checksec 16/7, 7z 13/10,
aircrack-ng 13/11, sha256sum 12/11, nm 11/5, tcpflow 9/6, jadx 10/7.
Wrappers: `ghidra_decompile` in 12 runs, 10 solved (encryptor 9, friendly-admin 1).

Programs a tier lacks, used in solved runs:

| Program | Solved runs | Challenges | Cost over core | core | medium |
|---|---|---|---|---|---|
| tcpflow | 6 | investigator 5, wifi-get-me, hidden-cipher | 1 MB | **added** (rule 1) | yes |
| ghidra / `ghidra_decompile` | 10 | encryptor 9, friendly-admin 1 | 1,846 MB (with Java) | no (rule 2) | yes |
| jadx | 7 | investigator | 686 MB (with Java) | no (rule 2) | yes |
| apktool | 4 | investigator | 335 MB | no (rule 2) | yes |
| d2j-dex2jar | 4 | investigator | 614 MB (with Java) | no (rule 2) | yes |
| smali | 2 | investigator (**in the flag command once**) | Java | no (rule 2) | yes |
| java / javac / javap | 3 / 1 / 1 | investigator | 613 MB | no (rule 2) | yes |
| sage | 2 | bdlp | Sage stack | no (rule 4) | no (rule 4) |
| tesseract, convert, fc-list, pytesseract | 1 | zodiac (not in the flag command) | 68 MB / 2 MB | no (1 run, not the flag) | yes |
| ngrep | 1 | investigator (not in the flag command) | 0.2 MB | no (1 run, not the flag) | yes |

Not real gaps: `capinfos`, `editcap` (wireshark-common, comes with tshark);
`airdecap-ng` (aircrack-ng); `zipinfo` (unzip); `sha256sum`, `md5sum`, `stat`,
`du` (coreutils); `top`, `pgrep` (procps). All present in core.

**SageMath:** 2 solved runs called `sage`, both bdlp. Core solved bdlp without
it (43 s, 0 wrong).

Rule 3 (medium items over 300 MB never called), dropped from medium:

| Item | Cost over core | Calls in any run |
|---|---|---|
| commix (+ metasploit, mingw, Oracle client) | 1,842 MB | 0 |
| qemu-user-static | 484 MB | 0 (one `which qemu-i386` in Poarta, unsolved) |

## 3. Per tier

| | core | medium |
|---|---|---|
| Raw / compressed | 2.91 GB / 0.93 GB | 6.62 GB / 2.65 GB |
| Build time (full, network) | 18 min 31 s | 20 min 02 s |
| Skipped packages | 0 | 1: pip `wfuzz` (pycurl will not build; wfuzz from apt is installed, as in the full image). Removed from the list after the build. |
| `check_image --strict`, plain | 59/74, 15 `[ -- ]`, 0 FAIL, 0 miss, exit 0 | 71/74, 3 `[ -- ]`, 0 FAIL, 0 miss, exit 0 |
| `--read-only --tmpfs /tmp --tmpfs /var/tmp` | same, exit 0 | same, exit 0 |
| `--user 1000:1000` | same, exit 0 | same, exit 0 |
| `--cap-drop NET_RAW` | same, exit 0 | same, exit 0 |
| Tests in the image | 304 passed | 304 passed |
| `ctf-tools` (probe; the full image finds 102) | 73 | 99 |
| Contest-day rebuild (`Dockerfile.contest --build-arg BASE=`) | 6 s, check exit 0, `harness.single --help` starts, `CTF_IMAGE_TIER=core` | 3 s, check exit 0, starts |
| SecLists kept | 575 files, 11 MB | 575 files, 11 MB |

Core's 15 by-design gaps: pwndbg, ghidra headless, ghidra_decompile, qemu-user,
sage, tesseract, ffmpeg/sox, hashcat, apktool/jadx, forge/cast, forge as
non-root, smbclient, mysql/psql/redis-cli, matplotlib/scipy, node. Medium's 3:
sage, hashcat, qemu-user.

Java in medium: Ghidra and jadx bring OpenJDK 25 (JDK and JRE) as
dependencies; `ghidra headless`, `ghidra_decompile tool decompiles` and
`apktool / jadx` pass, so `default-jdk-headless` was not added.

Wordlists: `/usr/share/wordlists/rockyou.txt` exists in both tiers. The two
other paths the brief names, `/usr/share/wordlists/dirb/common.txt` and
`/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`, **do not exist
in the full image either** (checked); the SecLists subset holds
`Discovery/Web-Content/common.txt` and `DirBuster-2007_directory-list-2.3-medium.txt`.

No tool needed a `path-include` for docs: every check passes with
`/usr/share/doc`, man pages and locales excluded.

## 4. The pass on core

Offline suite, GLM 5.3 Flash, `suite_run.sh` exactly as the pre-freeze check
(1200 s, 1.5M tokens, penalize on, egress lockdown), image
`ctf-harness:rehearsal-core` = `Dockerfile.contest` + `Dockerfile.rehearsal`
on `base-core`.

| Challenge | Full image, pre-freeze (prefreeze2) | Core | Core re-run |
|---|---|---|---|
| encryptor (rev) | solved 75 s | **solved 86 s**, 0 wrong, no Ghidra | - |
| bdlp (crypto) | solved 58 s | **solved 43 s**, 0 wrong, no Sage | - |
| investigator (forensics, APK in a pcap) | unsolved (variance), re-run solved 322 s | unsolved: token cap, 1 wrong | **solved 971 s**, 1.22M tokens, 0 wrong |
| adding-in-parts (forensics) | solved 785 s, 4 wrong | unsolved: time, 3 wrong | **solved 428 s**, 0 wrong |
| zodiac (forensics, image) | unsolved (never solved) | unsolved, 3 wrong | - |
| wifi-get-me (forensics) | solved 55 s | **solved 40 s**, 0 wrong | - |

The prompt line, from encryptor (rev):

> Not installed in this image, do not call them: floss; gdb-multiarch; ghidra (no `ghidra_decompile`: read code with `r2 -q -A -c 'pdf @ main' FILE`, `objdump -d -M intel`, `gdb`); qemu (a foreign-architecture binary cannot be run here: analyse it statically).

and bdlp (crypto):

> Not installed in this image, do not call them: hashcat (use `john`); sage (use `gp` (PARI/GP), `sympy`, `gmpy2`, `fpylll`); yafu (factor with `gp -q` or `sympy.factorint`).

`ghidra_decompile` calls: 0 in every core run (the tool is not offered).

`command not found` / `No module named` across all core runs: **one**,
`No module named 'matplotlib'` in zodiac. matplotlib costs 75 MB in core
(measured: pip install in the image), over the 50 MB line, and no playbook
names it, so no stand-in either. zodiac was not solvable on the full image.

**investigator** shows the missing tool, and the re-run shows the way around
it. First pass: `which jadx apktool baksmali d2j-dex2jar` find nothing, then
~25 turns of a hand-written DEX parser in Python until the token cap, and one
computed guess (`DCTF{sha256 of the APK}`) rejected. Re-run: the model
disassembled `classes.dex` with radare2 (r2 reads Dalvik), emulated the method's
bytecode in Python and grounded the flag, 0 wrong, but at 3x the time and 2.6x
the tokens of the full image's solve. The forensics playbook does not name jadx,
so the prompt line did not mention it; the model found out with `which`. The
Java tools that make it cheap cost 600+ MB: rule 2, left out. Verdict: a cost
(time, tokens, reliability on APKs), not an impossibility.

**adding-in-parts** had no missing tool: every program it used is in core. The
first pass had the right string by turn 10 and spent its time on long turns
(82-154 s each) and format variants; the full image's runs show the same
pattern (2 and 4 wrong). The re-run solved it in 428 s, 10 turns, 0 wrong:
run-to-run variance.

## 5. Changes made

To the lists (`scripts/tiers/*.conf`, `*.missing`):

| Change | Tier | Reason |
|---|---|---|
| + tcpflow | core | 6 solved runs, 1 MB (rule 1) |
| − outguess | both | not in this Kali; the full image does not have it either (apt skip) |
| − yafu, solidity | medium | not in this Kali, not in the full image (`solc` comes from solc-select) |
| − commix | medium | 1,842 MB with metasploit; never called (rule 3) |
| − qemu-user-static | medium | 484 MB; never run (rule 3); `qemu-user` added to `medium.missing` |
| − wfuzz (pip) | medium | pycurl does not build; apt wfuzz present, as in the full image |
| `RSACTFTOOL_REF=4ffadb01…`, `JWT_TOOL_REF=3bc7407c…` | both | the commits in `ctf-harness:base` (task 4) |
| headers rewritten | both | what each tier really holds, and its measured price |

To the script and the checks:

| File | Change | Reason |
|---|---|---|
| `scripts/tiers/constraints.txt` | 233 pins from `ctf-harness:base`'s `pip freeze` | task 4. None had to be removed. |
| `scripts/image_tier.sh` | `cmake pkg-config` in the base stage | the first core build stopped: the pinned `unicorn==2.1.2` has no wheel for Python 3.14 and builds from source with cmake. The full image has cmake as a dependency of its other packages. Of the 233 pins, 15 have no wheel; the others are pure Python or compile with build-essential. |
| `scripts/check_image.py` | `command -v X >/dev/null &&` before 5 checks: gdb runs, radare2, tshark, tesseract, curl | each was `X --version \| head -1`: a pipeline's status is head's, so **the check passed with the program absent**. Found because core's `tesseract` printed `[PASS]`. gdb, tshark and curl are critical. Same results in the full image (all present). |
| `tests/test_image_tiers.py` | `test_an_image_check_fails_when_its_program_is_absent` | regression test for the above: with only shell plumbing on PATH no check that runs a program may pass. Fails on the old file (5 checks), passes now. 304 tests. |

## 6. Still unverified

- **The apt packages are today's Kali, not the rehearsed image's.** The base
  image digest is pinned and the Python packages are pinned to the full image,
  but `apt-get update` takes the rolling archive of today (Python 3.14.10 in the
  tiers vs 3.14.8 in the full image). A Kali snapshot mirror would pin this; not
  done.
- **Medium has not run the suite.** It has every tool the rehearsals used except
  Sage; its checks and tests pass.
- **The tier bases contain the repo as of the build** (with the pins, before the
  header and test edits). `Dockerfile.contest` replaces `/opt/ctf-harness`
  entirely, so this does not reach a contest image; the backups were not rebuilt
  for it.
- `photorec` is a separate package in this Kali and is in none of the three
  images; the prompt line names it in the tiers.
- `CTF_IMAGE_TIER` unset in the full image is checked by the tests; the full
  image was not rebuilt for this branch (it is not merged).

## Follow-up (`CLAUDE_CODE_TIERS_FOLLOWUP.md`, 18 November afternoon)

305 tests pass on the host (`24d0e78`). Rehearsal images rebuilt on both tier
bases at that commit; same runner and settings as section 4.

### 1. The jadx line, on core

The forensics prompt of investigator now carries it:

> Not installed in this image, do not call them: jadx (for an APK: unzip it and disassemble classes.dex with `r2 -q -A`, which reads Dalvik: `afl`, then `pdf @ <method>`); outguess; photorec; pytesseract; tesseract (look at pictures with `view_image`).

The commands work as written on the suite's app (`com.example.secretcode1`,
1.9 MB classes.dex) in `base-core`: `r2 -q -A -c afl` lists 10,275 functions
in 7 s, `pdf @ <method>` prints Dalvik. In the agent's shell r2 prints no
colour codes (checked in the logs). `_STAND_INS` left unchanged.

| Core run | Result | Time | Tokens | Wrong | Route |
|---|---|---|---|---|---|
| first pass (no jadx line) | unsolved, token cap | 1,048 s | 1.52M | 1 | `which jadx ...`, then a hand-written DEX parser |
| re-run (no jadx line) | solved | 971 s | 1.22M | 0 | found r2 by itself |
| with the jadx line | unsolved, time | 1,177 s | 1.09M | 0 | **r2 at once**, no `which`, no parser |

With the line the model went to `r2 -q -A -c "afl~MainActivity"` 7 s after
unzipping the APK. The run was lost elsewhere: carving the APK out of the ADB
stream took until 615 s (the same on any image), and the remaining 540 s went
into emulating `MainActivity$1.toString()` (1,868 bytes of Dalvik) by hand from
the disassembly, which a decompiler gives in one step. A failure for time, not
for a missing hint: the line does its job, and what it cannot replace is jadx.
Task closed as the brief says; no further tuning.

### 2. The suite on medium

| Challenge | Full (prefreeze2) | Core | **Medium** |
|---|---|---|---|
| encryptor | solved 75 s | solved 86 s | **solved 132 s**, 0 wrong (1 Ghidra call) |
| bdlp | solved 58 s | solved 43 s | **solved 34 s**, 0 wrong, no Sage |
| investigator | unsolved; re-run solved 322 s | 1 of 3 solved | **solved 956 s**, 0.92M tokens, 0 wrong (jadx used, 5 calls) |
| adding-in-parts | solved 785 s, 4 wrong | unsolved; re-run solved 428 s | **solved 942 s**, 2 wrong (format guesses, as on full) |
| zodiac | unsolved | unsolved | unsolved, 3 wrong (never solved on any image) |
| wifi-get-me | solved 55 s | solved 40 s | **solved 131 s**, 0 wrong |

Medium solved 5 of 6 in one pass, the full image's best. `command not found` /
`No module named`: one, `knowledge: command not found` in adding-in-parts (the
model typed the harness's `knowledge` tool into the shell; not a package).
Medium's rev prompt line names only qemu. No re-runs (no failure showed a
missing tool).

### 3. Merge (Andrei's go-ahead, 18 November)

`main` fast-forwarded `b4c4f12 → 24d0e78` and pushed. `ctf-harness:latest`
rebuilt with `Dockerfile.contest` on `ctf-harness:base` (default; its layers
are a prefix of `latest`'s):

| Check | Result |
|---|---|
| `check_image.py` | 74/74 passed, 0 critical, 0 optional missing |
| `pytest` in the image | 305 passed |
| `CTF_IMAGE_TIER` | `tier=[]` |
| `docker image ls` | `latest` 39205c41232b 15.1 GB; `base` 03a62b938197; `base-core` 14834adbc17b 2.91 GB; `base-medium` fd52b05a0af4 6.62 GB; `base-1115` kept |

The `tier-test-*` tags were removed; `rehearsal-core` and `rehearsal-medium`
remain (rehearsal only, never uploaded). This section is committed on top and
fast-forwarded to `main` too (documentation only; the image above is built on
the same code).
