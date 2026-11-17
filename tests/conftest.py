"""Tests must not depend on whatever is in contest.env."""

import os

os.environ["CTF_ENV_FILE"] = ""
# No pause between flag submissions in tests (the default is one second).
os.environ["CTF_SUBMIT_MIN_INTERVAL"] = "0"
