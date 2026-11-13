#!/usr/bin/env bash
set -euo pipefail
# Production path: one container per challenge (organizers auto-start the
# challenge and inject their model endpoint). Config is read from the
# environment — CTF_* knobs (see harness/config.py) plus the model endpoint
# vars — so nothing secret is baked into the image. The challenge is taken from
# CTF_CHALLENGE_ID or --challenge, else the single challenge the platform
# presents. Pass args to override. Swap the Platform adapter for the starter
# kit's interface once it lands (CTF_PLATFORM / harness/config.py).
exec python -m harness.single "$@"
