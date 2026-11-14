#!/usr/bin/env bash
set -euo pipefail
# Production path: one container per challenge (organizers auto-start the
# challenge and inject their model endpoint). Config is read from the
# environment — CTF_* knobs (see harness/config.py) plus the model endpoint
# vars — so nothing secret is baked into the image. The challenge is taken from
# CTF_CHALLENGE_ID or --challenge, else the single challenge the platform
# presents. Swap the Platform adapter for the starter kit's interface once it
# lands (CTF_PLATFORM / harness/config.py).
#
# If the first argument is a command on PATH (python, ctf-tools, bash), run that
# instead, so `docker run IMAGE python -m pytest -q` and `docker run IMAGE
# ctf-tools` work. Anything else is passed to the solver as its arguments.
if [ "$#" -gt 0 ] && [ "${1#-}" = "$1" ] && command -v "$1" >/dev/null 2>&1; then
  exec "$@"
fi
exec python -m harness.single "$@"
