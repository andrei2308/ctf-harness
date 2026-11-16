"""The build context is copied into the submission image, so it must exclude
local environments, logs and credential-shaped files. A host .venv and a
build.log were found inside the image before this test existed."""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _patterns(name: str) -> set[str]:
    lines = (ROOT / name).read_text().splitlines()
    return {ln.strip() for ln in lines if ln.strip() and not ln.startswith("#")}


def test_dockerignore_keeps_local_and_secret_files_out_of_the_image():
    ignored = _patterns(".dockerignore")
    for must in (".venv", "*.log", ".env", "*.session.json", "cyberedu_session*",
                 ".cyberedu-mcp/", "runs/", ".git"):
        assert must in ignored, f"{must} would be copied into the submission image"


def test_contest_env_is_not_excluded_from_the_image():
    assert not any(p in ("*.env", "contest.env") for p in _patterns(".dockerignore"))
