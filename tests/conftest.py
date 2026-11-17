"""Tests must not depend on whatever is in contest.env."""

import os

os.environ["CTF_ENV_FILE"] = ""
# No pause between flag submissions in tests (the default is one second).
os.environ["CTF_SUBMIT_MIN_INTERVAL"] = "0"
# ...nor on which image tier they run in: a tier image sets CTF_IMAGE_TIER, and
# the suite must behave there as it does everywhere else. Tests of the tier
# behaviour set it themselves.
os.environ.pop("CTF_IMAGE_TIER", None)
