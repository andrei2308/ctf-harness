"""Tests must not depend on whatever is in contest.env."""

import os

os.environ["CTF_ENV_FILE"] = ""
