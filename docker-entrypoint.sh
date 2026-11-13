#!/usr/bin/env bash
set -euo pipefail
# One container per challenge (organizers auto-start the challenge and inject
# their model endpoint). All configuration is read from the environment — CTF_*
# knobs (see harness/config.py) plus the model endpoint vars — so nothing secret
# is baked into the image. With no args this runs the harness; pass args to
# override. The single-challenge "solve-one" entrypoint replaces this line once
# the starter kit defines the challenge-read / flag-submit interface.
exec python -m harness.run "$@"
