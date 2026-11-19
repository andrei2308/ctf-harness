"""Smaller image tiers (Dockerfile.slim): the tier definitions hold together,
and the harness tells the model what a tier lacks, without changing anything in
the full image that was rehearsed."""

import importlib.util
import re
import subprocess
from pathlib import Path

import pytest

from harness.agents import exttools
from harness.agents.exttools import (GhidraDecompileTool, VolatilityTool,
                                     image_tier, missing_note)
from harness.agents.specialists import (CryptoSpecialist, ForensicsSpecialist,
                                        RevSpecialist)
from harness.platforms.base import Challenge, ChallengeKind

ROOT = Path(__file__).resolve().parent.parent
TIERS = ("core", "medium")
# What the capability probe reports in the full image, and in a core build.
FULL = set(exttools._PROBE_BINARIES) | set(exttools._PROBE_PYMODULES) | {"ghidra", "radare2"}
CORE = FULL - {"ghidra", "analyzeHeadless", "sage", "yafu", "hashcat",
               "qemu-aarch64-static", "floss"}


def _conf(tier: str, *names: str) -> dict[str, list[str]]:
    """Source a tier's settings the way scripts/image_tier.sh does."""
    script = f'. "{ROOT}/scripts/tiers/{tier}.conf"\n' + "\n".join(
        f'printf "%s\\n" "{n}=${{{n}[*]}}"' for n in names)
    out = subprocess.run(["bash", "-euc", script], capture_output=True, text=True, check=True)
    return {k: v.split() for k, v in (ln.split("=", 1) for ln in out.stdout.splitlines())}


def _check_image():
    spec = importlib.util.spec_from_file_location("check_image", ROOT / "scripts/check_image.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _chal() -> Challenge:
    return Challenge(id="c", name="c", category="rev", description="d",
                     kind=ChallengeKind.STATIC)


# --- the tier definitions -----------------------------------------------------

@pytest.mark.parametrize("tier", TIERS)
def test_a_tier_keeps_everything_the_image_check_calls_critical(tier):
    conf = _conf(tier, "APT", "PIP_PKGS", "GEMS", "WITH_ANGR", "WITH_CYBEREDU_MCP", "SECLISTS")
    for pkg in ("gdb", "binutils", "file", "xxd", "binwalk", "exiftool", "tshark",
                "john", "nmap", "socat", "netcat-traditional"):
        assert pkg in conf["APT"], f"{tier} tier lost {pkg}"
    assert conf["WITH_ANGR"] == ["1"]
    # The contest runs on CyberEDU: its MCP server and the client library stay.
    assert conf["WITH_CYBEREDU_MCP"] == ["1"] and "mcp<2" in conf["PIP_PKGS"]
    assert conf["SECLISTS"] == ["subset"]


@pytest.mark.parametrize("tier", TIERS)
def test_a_build_argument_overrides_the_tier_default(tier):
    script = f'WITH_ANGR=0 SECLISTS=none; . "{ROOT}/scripts/tiers/{tier}.conf"; echo "$WITH_ANGR $SECLISTS"'
    out = subprocess.run(["bash", "-euc", script], capture_output=True, text=True, check=True)
    assert out.stdout.split() == ["0", "none"]
    # An argument declared in the Dockerfile but not passed arrives empty.
    script = f'WITH_ANGR=""; . "{ROOT}/scripts/tiers/{tier}.conf"; echo "$WITH_ANGR"'
    out = subprocess.run(["bash", "-euc", script], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "1"


def test_core_is_a_subset_of_medium_apart_from_what_it_names():
    core, medium = _conf("core", "APT", "PIP_PKGS"), _conf("medium", "APT", "PIP_PKGS")
    assert set(core["APT"]) <= set(medium["APT"])
    assert set(core["PIP_PKGS"]) <= set(medium["PIP_PKGS"])


@pytest.mark.parametrize("tier", TIERS)
def test_expected_misses_name_real_optional_checks(tier):
    mod = _check_image()
    labels = {label: critical for label, _cmd, critical in mod.CHECKS}
    listed = [ln.strip() for ln in (ROOT / f"scripts/tiers/{tier}.missing").read_text().splitlines()
              if ln.strip() and not ln.startswith("#")]
    assert listed
    for label in listed:
        assert label in labels, f"{tier}.missing names no check: {label!r}"
        assert labels[label] is False, f"{tier} tier would leave out a critical check: {label}"


def test_the_tiers_build_on_the_same_kali_snapshot_as_the_full_image():
    def base(name):
        return re.search(r"^FROM (\S+)", (ROOT / name).read_text(), re.M).group(1)
    assert "@sha256:" in base("Dockerfile")
    assert base("Dockerfile.slim") == base("Dockerfile")


def test_the_build_script_is_valid_bash():
    subprocess.run(["bash", "-n", str(ROOT / "scripts/image_tier.sh")], check=True)


def test_constraints_file_holds_only_plain_pins():
    for ln in (ROOT / "scripts/tiers/constraints.txt").read_text().splitlines():
        if ln.strip() and not ln.startswith("#"):
            assert re.fullmatch(r"[A-Za-z0-9_.-]+==\S+", ln), ln


# --- what the model is told ---------------------------------------------------

def test_full_image_prompts_and_tools_are_unchanged(monkeypatch, tmp_path):
    monkeypatch.delenv("CTF_IMAGE_TIER", raising=False)
    assert image_tier() == "full"
    # Even with tools missing: the full image never gets the line.
    assert missing_note(CORE, RevSpecialist().system_prompt()) == ""
    prompt = RevSpecialist().task_prompt(_chal(), tmp_path, None, [], available=CORE)
    assert "Not installed" not in prompt
    names = [t.name for t in RevSpecialist().profile_for(None, CORE).tools]
    assert GhidraDecompileTool.name in names
    assert RevSpecialist().profile_for(None, CORE) is not None


def test_a_tier_names_the_missing_tools_of_this_playbook_only(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_IMAGE_TIER", "core")
    note = missing_note(CORE, CryptoSpecialist().system_prompt())
    assert note.startswith("Not installed in this image")
    assert "sage (use `gp`" in note and "hashcat (use `john`)" in note and "yafu" in note
    assert "ghidra" not in note            # the crypto playbook does not name it
    rev = missing_note(CORE, RevSpecialist().system_prompt())
    assert "ghidra (no `ghidra_decompile`" in rev and "qemu" in rev and "floss" in rev
    assert "sage" not in rev
    # ...and it reaches the task prompt, right after the list of what IS there.
    prompt = RevSpecialist().task_prompt(_chal(), tmp_path, None, [], available=CORE)
    assert prompt.index("Installed tools detected here") < prompt.index("Not installed in this image")


def test_a_tier_without_jadx_says_so_to_every_specialist(monkeypatch):
    # An APK can come out of a pcap or a disk image, in any category.
    monkeypatch.setenv("CTF_IMAGE_TIER", "core")
    no_java = CORE - {"jadx", "apktool", "d2j-dex2jar", "apksigner"}
    assert "jadx" not in ForensicsSpecialist().system_prompt().lower()
    for spec in (ForensicsSpecialist(), RevSpecialist(), CryptoSpecialist()):
        note = missing_note(no_java, spec.system_prompt())
        assert "jadx (for an APK: unzip it and disassemble classes.dex with `r2" in note
    # With jadx installed (medium) nothing is said about it.
    assert "jadx" not in missing_note(CORE, ForensicsSpecialist().system_prompt())
    # And never in the full image.
    monkeypatch.delenv("CTF_IMAGE_TIER")
    assert missing_note(no_java, ForensicsSpecialist().system_prompt()) == ""


def test_a_tier_with_everything_installed_says_nothing(monkeypatch):
    monkeypatch.setenv("CTF_IMAGE_TIER", "medium")
    for spec in (RevSpecialist(), CryptoSpecialist(), ForensicsSpecialist()):
        assert missing_note(FULL, spec.system_prompt()) == ""


def test_a_failed_probe_does_not_declare_every_tool_missing(monkeypatch):
    monkeypatch.setenv("CTF_IMAGE_TIER", "core")
    assert missing_note(set(), CryptoSpecialist().system_prompt()) == ""
    names = [t.name for t in RevSpecialist().profile_for(None, set()).tools]
    assert GhidraDecompileTool.name in names
    names = [t.name for t in RevSpecialist().profile_for(None, None).tools]
    assert GhidraDecompileTool.name in names


def test_a_tier_does_not_offer_a_wrapper_for_a_missing_program(monkeypatch):
    monkeypatch.setenv("CTF_IMAGE_TIER", "core")
    names = [t.name for t in RevSpecialist().profile_for(None, CORE).tools]
    assert GhidraDecompileTool.name not in names
    assert {"shell", "gdb", "submit_flag"} <= set(names)
    # Present program: the wrapper stays.
    names = [t.name for t in RevSpecialist().profile_for(None, FULL).tools]
    assert GhidraDecompileTool.name in names
    names = [t.name for t in ForensicsSpecialist().profile_for(None, CORE).tools]
    assert VolatilityTool.name in names
    names = [t.name for t in ForensicsSpecialist().profile_for(None, CORE - {"volatility3"}).tools]
    assert VolatilityTool.name not in names


def test_check_image_reads_the_tier_and_its_expected_misses(monkeypatch):
    mod = _check_image()
    monkeypatch.setenv("CTF_IMAGE_TIER", "core")
    if not Path("/etc/ctf-image-tier").exists():
        assert mod.image_tier() == "core"
    assert "sage factors" in mod.left_out("core")
    assert mod.left_out("full") == set()


# --- a whole run in a tier image ----------------------------------------------

def _run_rev_challenge(tmp_path, monkeypatch, tools):
    import json

    from harness.agents.specialists import Specialist
    from harness.config import Config
    from harness.single import solve_one

    flag = "CTF{" + "t" * 16 + "}"
    c = tmp_path / "fix" / "only"
    (c / "files").mkdir(parents=True)
    (c / "files" / "f.txt").write_text(f"here: {flag}\n")
    (c / "challenge.json").write_text(json.dumps(
        {"id": "only", "name": "only", "kind": "static", "category": "rev",
         "points": 100, "flag": flag}))
    monkeypatch.setattr("harness.single.probe_tools", lambda ex, wd: set(tools))
    offered = []
    real = Specialist.profile_for

    def spy(self, conn, available=None):
        prof = real(self, conn, available)
        offered.append({t.name for t in prof.tools})
        return prof

    monkeypatch.setattr(Specialist, "profile_for", spy)
    summary = solve_one(Config(inference_backend="rule", platform="files",
                               fixtures_root=str(tmp_path / "fix"),
                               work_root=str(tmp_path / "work"),
                               run_dir=str(tmp_path / "logs")))
    events = [json.loads(ln) for ln in open(summary["log"])]
    prompt = next(e["text"] for e in events if e["kind"] == "task.prompt")
    return summary, prompt, offered


def test_a_run_in_a_tier_image_tells_the_model_and_trims_the_tools(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_IMAGE_TIER", "core")
    summary, prompt, offered = _run_rev_challenge(tmp_path, monkeypatch, CORE)
    assert summary["solved"] is True
    assert "Not installed in this image" in prompt and "ghidra" in prompt
    assert offered and all(GhidraDecompileTool.name not in names for names in offered)


def test_the_same_run_in_the_full_image_is_as_rehearsed(tmp_path, monkeypatch):
    monkeypatch.delenv("CTF_IMAGE_TIER", raising=False)
    summary, prompt, offered = _run_rev_challenge(tmp_path, monkeypatch, CORE)
    assert summary["solved"] is True
    assert "Not installed" not in prompt
    assert offered and all(GhidraDecompileTool.name in names for names in offered)


# --- scripts/tool_usage.py: the evidence for what a tier may leave out --------

def _tool_usage():
    spec = importlib.util.spec_from_file_location("tool_usage", ROOT / "scripts/tool_usage.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_tool_usage_finds_the_programs_in_a_shell_line():
    mod = _tool_usage()
    cmd = ("cd /tmp && FOO=1 timeout 60 sage -c 'print(1)' 2>/dev/null; "
           "/usr/bin/7z x a.zip | head; python3 -c \"from pwn import *; import z3\"")
    assert mod.programs(cmd) == {"sage", "7z", "python3", "py:pwn", "py:z3"}


def test_tool_usage_knows_what_a_tier_lists():
    mod = _tool_usage()
    core, medium = mod.tier_packages("core"), mod.tier_packages("medium")
    assert mod.in_tier("7z", core) and mod.in_tier("strings", core) and mod.in_tier("python3", core)
    assert not mod.in_tier("sage", core) and not mod.in_tier("sage", medium)
    assert not mod.in_tier("ghidra", core) and mod.in_tier("ghidra", medium)
    assert not mod.in_tier("forge", core) and mod.in_tier("forge", medium)
    assert not mod.in_tier("hashcat", medium)


def test_an_image_check_fails_when_its_program_is_absent(tmp_path):
    """A pipeline's status is its LAST command's: `tesseract --version | head -1`
    passed in the core tier, which has no tesseract. With only the shell's
    plumbing on PATH (no tool at all), no check that runs a program may pass."""
    import shutil
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    for prog in ("head", "grep", "cat", "sh", "bash", "printf", "echo", "test"):
        real = shutil.which(prog)
        if real:
            (bin_ / prog).symlink_to(real)
    passed = []
    for label, cmd, _ in _check_image().CHECKS:
        if cmd.startswith(("/", "test ")):
            continue                    # names its program or file by path, not via PATH
        r = subprocess.run(["/bin/bash", "-c", cmd], cwd=tmp_path, env={"PATH": str(bin_)},
                           capture_output=True, timeout=60)
        if r.returncode == 0:
            passed.append(label)
    assert passed == []


# --- under a 1 GB limit: angr as the decompiler, and specialist tiers ----------

def test_without_ghidra_the_model_is_pointed_at_angrs_decompiler(monkeypatch):
    monkeypatch.setenv("CTF_IMAGE_TIER", "core")
    note = missing_note(CORE, RevSpecialist().system_prompt())
    assert "python3 -m angr -n decompile FILE --functions main" in note
    # A tier without angr gets the disassembly route instead.
    note = missing_note(CORE - {"angr"}, RevSpecialist().system_prompt())
    assert "angr -n decompile" not in note and "r2 -q -A -c 'pdf @ main' FILE" in note


def test_the_decompile_command_in_the_prompt_exists_in_this_angr():
    """Runs wherever angr is installed (the images): the command the prompt
    names must be one this angr has."""
    pytest.importorskip("angr")
    import sys
    out = subprocess.run([sys.executable, "-m", "angr", "decompile", "--help"],
                         capture_output=True, text=True, timeout=300)
    assert out.returncode == 0 and "--functions" in out.stdout
    out = subprocess.run([sys.executable, "-m", "angr", "--help"],
                         capture_output=True, text=True, timeout=300)
    assert "-n, --nopbar" in out.stdout


def test_the_apk_tier_is_a_specialist_with_its_own_critical_set():
    conf = _conf("apk", "APT", "NEED", "GEMS", "PIP_PKGS", "WITH_ANGR", "WITH_CYBEREDU_MCP",
                 "SECLISTS", "ROCKYOU")
    assert {"jadx", "apktool", "dex2jar"} <= set(conf["APT"])
    assert {"jadx", "apktool"} <= set(conf["NEED"])
    assert "john" not in conf["APT"] and "john" not in conf["NEED"]
    assert conf["SECLISTS"] == ["none"] and conf["ROCKYOU"] == ["0"]
    assert conf["WITH_CYBEREDU_MCP"] == ["1"] and "mcp<2" in conf["PIP_PKGS"]
    # Every program the build insists on comes from a package it installs
    # (or from the base stage).
    provides = {"objdump": "binutils", "readelf": "binutils", "strings": "binutils",
                "curl": None}
    for tool in conf["NEED"]:
        pkg = provides.get(tool, tool)
        assert pkg is None or pkg in conf["APT"], f"apk tier insists on {tool} but does not install it"
    # Its expected misses are real checks; critical ones are allowed here.
    mod = _check_image()
    labels = {label for label, _cmd, _crit in mod.CHECKS}
    listed = mod.left_out("apk")
    assert listed and listed <= labels
    assert "apktool / jadx" not in listed


def test_in_the_apk_tier_the_model_is_not_told_jadx_is_missing(monkeypatch):
    monkeypatch.setenv("CTF_IMAGE_TIER", "apk")
    have = CORE - {"angr", "john", "sage"}        # jadx is in CORE's probe set
    note = missing_note(have, ForensicsSpecialist().system_prompt())
    assert "jadx" not in note
