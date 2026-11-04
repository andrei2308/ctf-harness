"""Run configuration + wiring factories.

Every organizer unknown is a knob here with a sensible default, so the skeleton
runs today and real values drop in as answers land (see the OPEN questions in the
handoff). Nothing here reads a secret from disk; credentials come from env.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from .agents.tools import Executor, LocalExecutor
from .inference.base import Model, ModelSpec
from .scheduler.budget import Caps
from .scheduler.ladder import Ladder, default_ladder


@dataclass
class Config:
    # --- inference (OPEN #1: endpoint/model/shape) -------------------------
    # backend: "rule" (offline heuristic, no network), "null" (alias of rule),
    #          "anthropic", "openai" (OpenAI-compatible, incl. local endpoints).
    inference_backend: str = "rule"
    fast_model: str = "fast"          # name passed to the backend for rung 0-1
    strong_model: str | None = None   # None => single-model ladder (effort only)
    openai_send_effort: bool = False  # set True if the endpoint honours reasoning_effort

    # --- budgets (OPEN #2: exact numbers + scope) --------------------------
    caps: Caps = field(default_factory=Caps)

    # --- concurrency (OPEN #3: the fixed slot count) ----------------------
    concurrency: int = 4
    max_error_retries: int = 1

    # --- platform (OPEN #4: runtime interface) -----------------------------
    platform: str = "files"           # "files" | "mcp"
    fixtures_root: str = "fixtures"    # for the files adapter
    contest_id: str = ""              # for the mcp adapter

    # --- paths -------------------------------------------------------------
    work_root: str = "runs/work"
    run_dir: str = "runs/logs"

    # --- behaviour ---------------------------------------------------------
    dry_run: bool = False             # True => never actually submit (log only)
    # Does the contest penalise wrong submissions? (OPEN Q6.) The predecessor
    # event did NOT, and the winner ran at 64% accuracy — so the default is an
    # aggressive posture: retry not-yet-accepted grounded flags (helps staged
    # challenges). Flip to True and resubmits are disabled (one attempt/flag).
    penalize_wrong: bool = False
    max_submits_per_flag: int = 3

    def ladder(self) -> Ladder:
        return default_ladder(self.fast_model, self.strong_model)

    def executor(self) -> Executor:
        return LocalExecutor()


def make_model_factory(config: Config):
    """Return a ModelFactory: spec -> Model, per the configured backend."""
    backend = config.inference_backend.lower()

    if backend in ("rule", "null"):
        from .inference.null import RuleModel

        def factory(spec: ModelSpec) -> Model:
            return RuleModel(spec=spec)
        return factory

    if backend == "anthropic":
        from .inference.anthropic_client import AnthropicModel

        def factory(spec: ModelSpec) -> Model:
            return AnthropicModel(spec)
        return factory

    if backend == "openai":
        from .inference.openai_client import OpenAIModel

        def factory(spec: ModelSpec) -> Model:
            return OpenAIModel(spec, send_effort=config.openai_send_effort)
        return factory

    raise ValueError(f"unknown inference backend: {config.inference_backend}")


def make_platform(config: Config):
    """Build the Platform adapter per config. Credentials come from env only."""
    if config.platform == "files":
        from .platforms.files_target import FilesTargetPlatform
        return FilesTargetPlatform(config.fixtures_root)
    if config.platform == "mcp":
        from .platforms.cyberedu_mcp import CyberEduMcpPlatform
        if not config.contest_id:
            raise ValueError("contest_id required for the mcp platform")
        # Cookie read from CYBEREDU_SESSION inside the adapter; never from config.
        return CyberEduMcpPlatform(contest_id=config.contest_id)
    raise ValueError(f"unknown platform: {config.platform}")


def config_from_env() -> Config:
    """Build a Config from env vars (handy in a sandbox). Only non-secret knobs;
    model/platform credentials are read by the adapters themselves."""
    def _int(name, default):
        v = os.environ.get(name)
        return int(v) if v else default

    def _opt_int(name):
        v = os.environ.get(name)
        return int(v) if v else None

    caps = Caps(
        total_tokens=_opt_int("CTF_TOTAL_TOKENS"),
        total_seconds=(float(os.environ["CTF_TOTAL_SECONDS"])
                       if os.environ.get("CTF_TOTAL_SECONDS") else None),
        per_challenge_tokens=_opt_int("CTF_PER_CHALLENGE_TOKENS"),
        per_challenge_seconds=(float(os.environ["CTF_PER_CHALLENGE_SECONDS"])
                               if os.environ.get("CTF_PER_CHALLENGE_SECONDS") else None),
        per_attempt_tokens=_opt_int("CTF_PER_ATTEMPT_TOKENS"),
        per_attempt_seconds=(float(os.environ["CTF_PER_ATTEMPT_SECONDS"])
                             if os.environ.get("CTF_PER_ATTEMPT_SECONDS") else None),
    )
    return Config(
        inference_backend=os.environ.get("CTF_BACKEND", "rule"),
        fast_model=os.environ.get("CTF_FAST_MODEL", "fast"),
        strong_model=os.environ.get("CTF_STRONG_MODEL") or None,
        caps=caps,
        concurrency=_int("CTF_CONCURRENCY", 4),
        platform=os.environ.get("CTF_PLATFORM", "files"),
        fixtures_root=os.environ.get("CTF_FIXTURES", "fixtures"),
        contest_id=os.environ.get("CTF_CONTEST_ID", ""),
        work_root=os.environ.get("CTF_WORK_ROOT", "runs/work"),
        run_dir=os.environ.get("CTF_RUN_DIR", "runs/logs"),
        dry_run=os.environ.get("CTF_DRY_RUN", "").lower() in ("1", "true", "yes"),
        penalize_wrong=os.environ.get("CTF_PENALIZE_WRONG", "").lower() in ("1", "true", "yes"),
    )
