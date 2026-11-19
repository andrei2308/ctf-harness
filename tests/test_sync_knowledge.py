"""scripts/sync_knowledge.py --ref: the image takes its notes from a branch of
the notes repository without touching the owner's working copy."""

import importlib.util
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _mod():
    spec = importlib.util.spec_from_file_location("sync_knowledge", ROOT / "scripts/sync_knowledge.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t",
                    "-c", "commit.gpgsign=false", *args], check=True, capture_output=True)


@pytest.fixture
def notes(tmp_path):
    repo = tmp_path / "notes"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "crypto").mkdir()
    (repo / "crypto" / "notes.md").write_text("mine\n")
    (repo / "pic.png").write_bytes(b"\x89PNG")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "my notes")
    _git(repo, "checkout", "-q", "-b", "harness")
    (repo / "crypto" / "PLAYBOOK_no_sage.md").write_text("for the agent\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "agent playbooks")
    _git(repo, "checkout", "-q", "main")
    return repo


def test_a_branch_is_synced_without_checking_it_out(notes, tmp_path, capsys):
    dest = tmp_path / "dest"
    assert _mod().main([str(notes), "--ref", "harness"], dest=dest) == 0
    assert (dest / "crypto" / "PLAYBOOK_no_sage.md").read_text() == "for the agent\n"
    assert (dest / "crypto" / "notes.md").exists() and not (dest / "pic.png").exists()
    # The working copy is still on main, and still without the branch's file.
    head = subprocess.run(["git", "-C", str(notes), "rev-parse", "--abbrev-ref", "HEAD"],
                          capture_output=True, text=True).stdout.strip()
    assert head == "main" and not (notes / "crypto" / "PLAYBOOK_no_sage.md").exists()
    assert "from: harness (" in capsys.readouterr().out


def test_without_a_ref_the_files_on_disk_are_synced(notes, tmp_path, capsys):
    dest = tmp_path / "dest"
    (notes / "crypto" / "draft.md").write_text("not committed\n")
    assert _mod().main([str(notes)], dest=dest) == 0
    assert (dest / "crypto" / "draft.md").exists()
    assert not (dest / "crypto" / "PLAYBOOK_no_sage.md").exists()
    assert "branch main" in capsys.readouterr().out


def test_an_unknown_ref_changes_nothing(notes, tmp_path, capsys):
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "keep.md").write_text("previous sync\n")
    assert _mod().main([str(notes), "--ref", "nope"], dest=dest) == 1
    assert (dest / "keep.md").exists()
    assert "no branch, tag or commit named 'nope'" in capsys.readouterr().out
