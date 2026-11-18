# Smaller image tiers: instructions for Claude Code

> **Completed 2026-11-18.** Results are in `TIERS_REPORT.md`. Both tiers are
> built, checked in the four sandbox shapes and backed up: core 2.91 GB
> (0.93 GB compressed), medium 6.62 GB (2.65 GB compressed). Core solved the
> same 5 of 6 suite challenges as the full image over a pass and a re-run.
> Not merged. Kept for reference.

You are on Andrei's Kali machine, in the `ctf-harness` repo. `main` (`b4c4f12`)
is the frozen-ready state and stays the plan. Branch `image-tiers` is one commit
ahead of it. That commit was written without Docker and without access to the
Kali package mirror, so the image builds in it have never run. Build them,
measure them, fix what does not install, and report.

**Why.** The organizers have not said whether the image upload has a size limit.
The full image is 15.09 GB (5.75 GB compressed). If a limit appears in the
starter kit on 19 November, there will be no time and no network to make a
smaller image at the venue. So two smaller bases are built now and kept beside
the full one. Without a limit they are never used.

**Time box.** Half a day. The freeze is 18 November, 20:00. If the tiers are not
verified by 18:00, stop, write up what exists, and leave `main` as it is. A core
tier that is built and checked is worth more than two tiers half done: do core
first.

## What the commit contains

| File | What it is |
|---|---|
| `Dockerfile.slim` | Builds a tier from the same pinned Kali base. `--build-arg TIER=medium\|core`. Ends as a complete image, usable as `BASE` for `Dockerfile.contest`. |
| `scripts/image_tier.sh` | The install steps, one stage per layer. Same for every tier. Stops the build when a critical tool is missing; writes every skipped package to `/var/log/ctf-image-skips.log` in the image. |
| `scripts/tiers/core.conf`, `medium.conf` | What each tier holds: package lists and `WITH_*` switches. Plain bash. **This is the file you edit.** |
| `scripts/tiers/core.missing`, `medium.missing` | Labels of `check_image.py` checks the tier does not pass by design. |
| `scripts/tiers/constraints.txt` | Python version pins for the tier builds. Empty; task 4 fills it. |
| `scripts/check_image.py` | Reads the tier from `/etc/ctf-image-tier`. By-design gaps print `[ -- ]`; `--strict` makes an unexpected `[miss]` count in the exit code. |
| `scripts/tool_usage.py` | Counts which programs the agent ran, from run logs. |
| `harness/agents/exttools.py`, `specialists.py`, `single.py`, `scheduler.py` | In a tier image only (`CTF_IMAGE_TIER` set by `Dockerfile.slim`): the task prompt gets one line naming the tools the playbook mentions that are not installed, with a stand-in, and `ghidra_decompile` / `volatility` are not offered when their program is absent. With the variable unset, prompts and tools are the rehearsed ones; two tests assert it. |
| `Dockerfile`, `README.md` | Comments only. The old advice (`WITH_SAGE=0 WITH_WORDLISTS=0` for a "slim" image) was wrong: `WITH_SAGE=0` removes nothing, because `sagemath` is also in the main package list. No instruction in `Dockerfile` changed. |
| `HANDOFF.md` | New section "If the image is too big". Its size table says "not built yet": you fill it in. |

First-cut contents (yours to correct from the evidence in tasks 2 and 3):

- **medium** = full minus SageMath, all but a few MB of SecLists, hashcat,
  `qemu-user` (the `-static` build stays), frida/objection, Foundry's second
  copy, docs and man pages. Ghidra stays.
- **core** = also without Ghidra and Java tools, pwndbg, Foundry, qemu, ffmpeg,
  tesseract, imagemagick, node, database clients, smbclient, hydra, the
  second-line web scanners, matplotlib/scipy. It keeps angr, radare2, fpylll,
  PARI/GP, volatility3, web3 with solc, RsaCtfTool, john, sqlmap, ffuf, the
  stego set, `rockyou.txt`, and the CyberEDU MCP server.

What I measured here (Python 3.13, not Kali's): the whole Python toolkit of the
full image is about 1.4 GB, core's is about 1.0 GB, and angr adds only 290 MB on
top of pwntools. So the 15 GB is mostly apt packages, and I do not know which.
Task 2 finds out.

What ran here and what did not:

| Part | Status |
|---|---|
| `python` and `extras` stages of `image_tier.sh` (core lists) | Ran, in an isolated root on Ubuntu. All packages installed; RsaCtfTool, jwt_tool, pwninit, ropper and the CyberEDU server passed their `check_image` lines. |
| `solc-select` download | Not reachable from here. Untested: look at `solc runs with the agent's HOME`. |
| `wordlists` stage | Ran against a fake SecLists tree with a stub `apt-get`. The real file names may differ. |
| `base`, `apt`, `gems`, `heavy` stages | Never ran. Package names come from the main `Dockerfile` and `image_extras.sh`, except `openssl`, `libcap2-bin` and `dirb`. |
| Tests | 303 pass on the host, also with `CTF_IMAGE_TIER=core` set. |

## Ground rules

The rules of the earlier briefs apply. In particular:

- **The frozen image is not touched.** Never tag a tier as `ctf-harness:base` or
  `ctf-harness:latest`. Tier tags are `ctf-harness:base-medium` and
  `ctf-harness:base-core`; test rebuilds are `ctf-harness:tier-test`.
- **You may edit:** `scripts/tiers/*`, `scripts/image_tier.sh`,
  `Dockerfile.slim`, the tier parts of `scripts/check_image.py`, the stand-in
  map in `harness/agents/exttools.py`, tests, docs.
- **You may not edit:** any instruction in `Dockerfile`, `Dockerfile.contest`,
  `scripts/image_extras.sh`, the values in `contest.env`, or harness behaviour
  when `CTF_IMAGE_TIER` is unset.
- No `docker system prune`, no `docker builder prune`, no Kali upgrade. If disk
  space is short, stop and tell Andrei; do not delete an image to make room.
- No secret in a file, a command line or a report. The model key goes in by
  variable name only, as before.
- Build logs go to `~/Desktop/ctf-rehearsal/tiers/`, not into the repo.

## Tasks

### 1. Verify the branch

```bash
git fetch origin && git checkout image-tiers && git pull
python -m pytest -q                    # expect 303 passed
bash -n scripts/image_tier.sh
df -h /var/lib/docker ~ ; docker system df
```

Both tiers and their backups need roughly 20 GB free. With less, build core
only and say so.

### 2. Find where the 15 GB is

Nothing is built in this task. Record the three outputs in the report.

```bash
docker history --format '{{.Size}}\t{{.CreatedBy}}' ctf-harness:base | cut -c1-150
docker run --rm ctf-harness:base bash -c \
  "dpkg-query -Wf '\${Installed-Size}\t\${Package}\n' | sort -rn | head -50"
docker run --rm ctf-harness:base bash -c \
  'du -xsm /opt/* /usr/share/* /usr/lib/* /root/.[a-z]* 2>/dev/null | sort -rn | head -40'
```

`Installed-Size` is in KB. From these, write one table: the 25 largest items
(package or directory), their size, and whether core and medium keep them.

### 3. Find what the agent actually used

```bash
python scripts/tool_usage.py ~/Desktop/ctf-rehearsal --tier core   | tee ~/Desktop/ctf-rehearsal/tiers/usage-core.txt
python scripts/tool_usage.py ~/Desktop/ctf-rehearsal --tier medium | tee ~/Desktop/ctf-rehearsal/tiers/usage-medium.txt
```

A `-` in the last column means the program's name is not in the tier's package
list. It is a comparison of names: confirm before acting on it.

Then adjust the `.conf` files, by these rules and no others:

1. A program called in **two or more solved runs**, or that produced the flag
   in any one solve, which a tier lacks and which costs **under 50 MB**
   installed (task 2's table): add it to that tier. If a `check_image` label
   covers it, remove the label from the tier's `.missing`.
2. The same, but it costs **more than 50 MB**: leave it out and list it in the
   report with its size and the challenges that used it. That list is the
   price of the tier, and Andrei needs to see it.
3. Something medium keeps that is **over 300 MB and was never called in any
   run**: you may drop it from medium. List each one in the report.
4. SageMath stays out of both tiers whatever the count says (with it, the tier
   is the full image). Do report how many solved runs called `sage`.
5. Everything `check_image.py` marks critical stays in both tiers. A test
   enforces it.

`core.conf` must stay a subset of `medium.conf` (a test enforces it): add to
both.

### 4. Pin the versions to the rehearsed image

So that a tier differs from the full image in what is installed and not in
which release of it:

```bash
docker run --rm ctf-harness:base pip freeze \
  | grep -E '^[A-Za-z0-9_.-]+==[^ ]+$' >> scripts/tiers/constraints.txt
docker run --rm ctf-harness:base git -C /opt/RsaCtfTool rev-parse HEAD
docker run --rm ctf-harness:base git -C /opt/jwt_tool rev-parse HEAD
```

Put the two commits into `RSACTFTOOL_REF` and `JWT_TOOL_REF` in both `.conf`
files. If a pin makes the build fail (a version no longer downloadable), remove
that one line from `constraints.txt` and note it.

### 5. Build core, then medium

```bash
mkdir -p ~/Desktop/ctf-rehearsal/tiers && set -o pipefail
time docker build -f Dockerfile.slim --build-arg TIER=core -t ctf-harness:base-core . \
  2>&1 | tee ~/Desktop/ctf-rehearsal/tiers/build-core.log
docker run --rm ctf-harness:base-core cat /etc/ctf-image-tier /var/log/ctf-image-skips.log
docker image ls ctf-harness:base-core
docker history --format '{{.Size}}\t{{.CreatedBy}}' ctf-harness:base-core | cut -c1-120
```

The last stage prints "where the space is" and a total into the build log.

Things I expect might go wrong, and what to do:

- **`FATAL: critical tool missing after install: X`** in the `apt` stage: the
  package name is wrong for this Kali snapshot, or `apt-get update` failed. Fix
  the name in the `.conf`.
- **A skipped package** (`WARN:` lines, and the skips file): fix its name, or if
  this Kali has no such package and the full image does not have it either,
  remove it from the list.
- **`SecLists kept: N files`**: expect dozens of files and tens of MB. With 0
  files or more than 200 MB, the patterns in `SECLISTS_KEEP`
  (`scripts/image_tier.sh`) do not fit this SecLists release: fix them. The
  lists the notes name must exist afterwards:
  `/usr/share/wordlists/rockyou.txt`, `/usr/share/wordlists/dirb/common.txt`,
  `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`. Check whether
  the last two exist in the full image at all, and say so.
- **Java in medium.** The main `Dockerfile` installs `default-jdk-headless`
  itself; the tiers leave it to the dependencies of `ghidra`, `jadx` and
  `apktool`. If `ghidra headless`, `ghidra_decompile tool decompiles` or
  `apktool / jadx` miss in medium, add `default-jdk-headless` to `medium.conf`.
- **Docs excluded.** The `base` stage tells dpkg not to install
  `/usr/share/doc`, man pages and locales. If a tool turns out to keep data
  there, add a `path-include` line for it in `stage_base` and name the tool in
  the report.

Then the same for medium (`TIER=medium`, tag `ctf-harness:base-medium`, log
`build-medium.log`).

### 6. Check each tier

For each of the two tags:

```bash
T=ctf-harness:base-core        # then ctf-harness:base-medium
docker run --rm $T python scripts/check_image.py --strict ; echo "exit $?"
docker run --rm --read-only --tmpfs /tmp --tmpfs /var/tmp $T python scripts/check_image.py --strict
docker run --rm --user 1000:1000 $T python scripts/check_image.py --strict
docker run --rm --cap-drop NET_RAW $T python scripts/check_image.py --strict
docker run --rm $T python -m pytest -q
docker run --rm $T ctf-tools
```

Expected: no `[FAIL]`, no `[miss]`, exit 0. Core shows 15 `[ -- ]` lines, medium
2 (fewer or more if you changed the lists in task 3; the `.missing` file must
then match). For every `[miss]`: find the cause in the skips file and the build
log and fix the install. Only when the tool cannot be installed in that tier,
add its label to the tier's `.missing` with a comment saying why. Never add a
critical check there.

If a test in the image fails because the tier lacks a tool the test assumes,
report the test; do not delete it.

Then the contest-day path, which is what Andrei would run at the venue:

```bash
docker build -f Dockerfile.contest --build-arg BASE=$T -t ctf-harness:tier-test .
docker run --rm ctf-harness:tier-test python scripts/check_image.py --strict
docker run --rm ctf-harness:tier-test python -m harness.single --help >/dev/null && echo starts
docker rmi ctf-harness:tier-test
```

It must build with no network (its `RUN` steps already forbid it) and in
seconds.

### 7. One real pass on core

Run the offline suite once on `ctf-harness:base-core`, the same way and with
the same model as the pre-freeze check, and compare the solved set with the
full image's last result on that suite.

In the logs, look for three things:

1. `task.prompt` of a crypto and of a rev challenge contains the line
   `Not installed in this image, do not call them: ...`. Quote one in the
   report.
2. No `tool.call` with `ghidra_decompile`.
3. Every tool result that says `command not found` or `No module named`:
   ```bash
   grep -ho '[A-Za-z0-9_.+-]*: command not found\|No module named [A-Za-z0-9_.'"'"']*' \
     <the run's logs> | sort | uniq -c | sort -rn
   ```
   Each one is a tool the model reached for and the tier lacks. Under 50 MB:
   add it to the tier and rebuild. Otherwise, if a playbook names it, give it a
   stand-in in `_STAND_INS` (`harness/agents/exttools.py`); the note only lists
   tools the playbook names.

A challenge the full image solved and core did not: say which, and whether the
log shows a missing tool or the usual run-to-run variance (re-run it once
before deciding).

If the model endpoint is unavailable or time is short, skip this task and say
so in the report. Do not skip tasks 5 and 6 for it.

### 8. Back up and measure the upload size

```bash
docker save ctf-harness:base-core   | pigz > ~/ctf-harness-base-core.tar.gz
docker save ctf-harness:base-medium | pigz > ~/ctf-harness-base-medium.tar.gz
ls -l ~/ctf-harness-base-*.tar.gz && sha256sum ~/ctf-harness-base-{core,medium}.tar.gz
```

The compressed size is the number that matters if the limit is on the upload.

### 9. Report, document, push

- Fill the size table in `HANDOFF.md` ("If the image is too big") with the
  measured numbers, raw and compressed, and correct the one-line descriptions
  if the contents changed.
- Update the header comments of `core.conf` and `medium.conf` so they describe
  what the tier really holds.
- Write `TIERS_REPORT.md`:
  1. Where the 15 GB is (task 2's table).
  2. What the agent used (the top of task 3's output, and every used program a
     tier lacks, with its size).
  3. Per tier: size raw and compressed, build time, `check_image` result in the
     four sandbox shapes, in-image tests, skipped packages, the contest-day
     rebuild.
  4. The pass on core: solved set against the full image, the quoted prompt
     line, the `command not found` list.
  5. Every change you made to the lists and to the script, with the reason.
  6. What is still unverified.
- Mark this file completed with a banner at the top, like the earlier briefs.
- Commit on `image-tiers` and push. Do not merge.

**Merging to `main`** is Andrei's call, before the freeze. It is safe to offer
when tasks 5 and 6 passed for core. If he says yes: fast-forward `main`, rebuild
the real image on the full base and confirm it is unchanged for the agent:

```bash
docker build -f Dockerfile.contest -t ctf-harness:latest .
docker run --rm ctf-harness:latest python scripts/check_image.py     # 74/74 as before
docker run --rm ctf-harness:latest python -m pytest -q
docker run --rm ctf-harness:latest bash -c 'echo "tier=[${CTF_IMAGE_TIER:-}]"'   # must print tier=[]
```

If he says no or is not reachable, `main` stays at `b4c4f12` and the tier bases
remain usable with it: `Dockerfile.contest --build-arg BASE=...` works with
either branch. The only loss is the "not installed" line in the prompt.

## What Andrei needs from this, in the end

Three bases on disk with their backups, and one table: tag, raw size,
compressed size, what it lacks. On the day he picks the largest that fits the
limit and changes one argument.
