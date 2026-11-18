# Image tiers, follow-up: instructions for Claude Code

> **Completed 2026-11-18.** Results in the Follow-up section of
> `TIERS_REPORT.md`: the jadx line works (core went to r2 at once but lost on
> time), medium solved 5 of 6 in one pass, and `main` was merged with Andrei's
> go-ahead (`24d0e78`; `latest` 74/74, 305 tests, tier empty). Kept for reference.

You are on Andrei's Kali machine, in the `ctf-harness` repo, branch
`image-tiers`. `TIERS_REPORT.md` is accepted as it stands. This is the last
round before the freeze (18 November, 20:00): three short tasks. If it is past
18:30 when you read this, do task 3 only.

The ground rules of `CLAUDE_CODE_TIERS.md` apply.

## Review of the tiers round

Both tiers are what was asked for, and the report answers the question it had
to: what each tier costs. Three things in it were better than the brief:

- **The `check_image.py` fix.** `X --version | head -1` passes when `X` is
  absent, and three of the five checks written that way were critical (gdb,
  tshark, curl). That predates the tiers and applies to the full image too. The
  regression test is the right one.
- **commix.** 1.8 GB for a tool no run called, because of what it depends on.
  The first cut had kept it in medium.
- **The investigator runs.** One failure and one solve, with the turn-by-turn
  reason for each, is exactly the evidence needed for the change below.

Nothing to correct.

## What the new commit changes

One thing, in tier images only (`CTF_IMAGE_TIER` set):

- **A tier without jadx now says so to every specialist**, with the way around
  it that your re-run found: `jadx (for an APK: unzip it and disassemble
  classes.dex with `r2 -q -A`, which reads Dalvik: `afl`, then `pdf @
  <method>`)`. Until now the line listed only tools the specialist's own
  playbook names; the forensics playbook does not name jadx, so on investigator
  the model learned it from `which` and then spent 25 turns on a DEX parser.
  (`harness/agents/exttools.py`: `_ANY_CATEGORY`, and the `jadx` entry of
  `_STAND_INS`.)
- `HANDOFF.md`: a slow upload is treated as a size limit.

305 tests pass on the host. The full image is not affected; a test asserts it.

## Tasks

### 1. Check the jadx line on core (30 minutes at most)

```bash
git pull && python -m pytest -q            # expect 305 passed
```

Rebuild the rehearsal image on `ctf-harness:base-core` as before (seconds) and
run **investigator** once, with the same settings as the tiers pass.

- The `task.prompt` must contain the jadx line. Quote it.
- Does the model go to `r2` without first writing its own parser? Report the
  time, tokens and wrong guesses beside the two earlier core runs (token cap;
  971 s and 1.22M tokens).
- If the r2 commands in the line do not work as written on a DEX file in this
  image (try them by hand on the suite's APK), correct the wording in
  `_STAND_INS` to what does work, and say what you changed.

One run. A solve, or a failure for a reason other than a missing tool, both
close the task. Do not tune further.

### 2. One suite pass on medium (if the time allows)

Medium is the likely fallback (it lacks only Sage of everything the rehearsals
used) and has never run a challenge. Run the offline suite once on
`ctf-harness:base-medium`, same settings, and add its column to the table in
section 4 of `TIERS_REPORT.md`. Look for `command not found` and
`No module named` as before. No re-runs unless a failure shows a missing tool.

Skip this if task 3 would otherwise start after 19:00.

### 3. Merge and freeze (needs Andrei's go-ahead)

Andrei decides. If he has told you to merge:

```bash
git checkout main && git merge --ff-only image-tiers && git -c push.negotiate=true push
docker build -f Dockerfile.contest -t ctf-harness:latest .
docker run --rm ctf-harness:latest python scripts/check_image.py      # 74/74, as before
docker run --rm ctf-harness:latest python -m pytest -q                # 305 passed
docker run --rm ctf-harness:latest bash -c 'echo "tier=[${CTF_IMAGE_TIER:-}]"'   # tier=[]
docker image ls | grep ctf-harness
```

`ctf-harness:latest` must be built on `ctf-harness:base` (the default), never on
a tier. If any of the four results differs, reset `main` to `b4c4f12`, push
that, and report.

If he has not said so, leave `main` at `b4c4f12` and say in the report that the
merge is open.

### 4. Report

Append a short "Follow-up" section to `TIERS_REPORT.md` (the investigator run,
the medium column, the merge and its four results), mark this file completed
with a banner, commit, push.

After that the freeze holds: only `contest.env` and
`harness/platforms/starter_kit.py` change, on the day.
