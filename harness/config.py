"""Run configuration + wiring factories.

Every organizer unknown is a knob here with a sensible default, so the skeleton
runs today and real values drop in as answers land (see the OPEN questions in the
handoff). Nothing here reads a secret from disk; credentials come from env.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from pathlib import Path

from .agents.tools import Executor, LocalExecutor
from .envfile import load_env_file
from .inference.base import Model, ModelSpec
from .scheduler.budget import Caps
from .scheduler.ladder import Ladder, Rung, default_ladder


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
    # One upfront planning turn per challenge (ReAct&Plan — arXiv:2412.02776).
    plan_first: bool = True
    # On escalation after a stall, restart with a clean context seeded by a recap
    # instead of resuming the full transcript. Research-mixed / model-dependent,
    # so default off; revalidate once the organizers' model is known.
    fresh_context_on_escalate: bool = False
    # Production (one challenge per container): after the ladder is climbed,
    # how many clean-context restarts of the top rung to spend remaining budget on.
    top_rung_restarts: int = 6
    # Also write every log event to stderr (the container's output stream is what
    # comes back from a contest run; the log file may not).
    log_mirror: bool = False
    # Clamp every rung's per-response max_tokens. The upper rungs ask for 16k/32k;
    # an endpoint whose context or output limit is smaller rejects that request
    # outright. Set once the organizers' model limits are known.
    max_output_tokens: int | None = None
    # Floor for every rung's max_tokens. A reasoning model spends output tokens
    # on hidden thinking, and the low rungs' 4096 can be gone before it acts.
    min_output_tokens: int | None = None

    # Turns per rung, overriding the default 12, 25, 40, 60 (CTF_LADDER_DEPTHS,
    # comma-separated, first rung first; fewer values leave the rest alone).
    # Rehearsal never got past rung 2 in 20 minutes, so the restart path was
    # never exercised: small depths reach it in a few minutes. On the day, size
    # the depths to the announced time limit.
    ladder_depths: tuple[int, ...] = ()

    def ladder(self) -> Ladder:
        ladder = default_ladder(self.fast_model, self.strong_model)
        if self.ladder_depths:
            ladder = Ladder([Rung(r.spec, max(1, self.ladder_depths[i]))
                             if i < len(self.ladder_depths) else r
                             for i, r in enumerate(ladder.rungs)])
        floor, cap = self.min_output_tokens, self.max_output_tokens
        if floor or cap:
            def fit(n: int) -> int:
                n = max(n, floor) if floor else n
                return min(n, cap) if cap else n       # the cap wins over the floor
            ladder = Ladder([Rung(replace(r.spec, max_tokens=fit(r.spec.max_tokens)),
                                  r.max_iterations) for r in ladder.rungs])
        return ladder

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
    if config.platform == "benchmark":
        from .platforms.benchmark import BenchmarkPlatform
        return BenchmarkPlatform(config.fixtures_root)
    if config.platform in ("cyberedu", "mcp"):
        from .platforms.cyberedu_mcp import CyberEduMcpPlatform
        # The practice catalogue unless a contest slug is given. The cookie is
        # read from CYBEREDU_SESSION_COOKIE inside the adapter, never from config.
        return CyberEduMcpPlatform(
            tenant=os.environ.get("CTF_CYBEREDU_TENANT", "cyberedu"),
            contest_slug=config.contest_id or None)
    if ":" in config.platform:
        # module:Class — an adapter written for the organizers' starter kit, so
        # adding one needs no edit here.
        import importlib
        module, _, cls = config.platform.partition(":")
        try:
            return getattr(importlib.import_module(module), cls)()
        except (ImportError, AttributeError) as e:
            raise ValueError(f"cannot load platform {config.platform!r}: {e}") from e
    raise ValueError(f"unknown platform: {config.platform}")


def _depths(raw: str) -> tuple[int, ...]:
    out = []
    for part in raw.replace(";", ",").split(","):
        part = part.strip()
        if not part:
            continue
        if not part.isdigit():
            return ()            # a typo must not silently reshape half the ladder
        out.append(int(part))
    return tuple(out)


def config_from_env() -> Config:
    """Build a Config from env vars (handy in a sandbox). Only non-secret knobs;
    model/platform credentials are read by the adapters themselves. Settings in
    contest.env are applied first, as defaults under the real environment."""
    load_env_file()
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
        openai_send_effort=os.environ.get("CTF_OPENAI_SEND_EFFORT", "").lower()
        in ("1", "true", "yes"),
        caps=caps,
        concurrency=_int("CTF_CONCURRENCY", 4),
        platform=os.environ.get("CTF_PLATFORM", "files"),
        fixtures_root=os.environ.get("CTF_FIXTURES", "fixtures"),
        contest_id=os.environ.get("CTF_CONTEST_ID", ""),
        work_root=os.environ.get("CTF_WORK_ROOT", "runs/work"),
        run_dir=os.environ.get("CTF_RUN_DIR", "runs/logs"),
        dry_run=os.environ.get("CTF_DRY_RUN", "").lower() in ("1", "true", "yes"),
        penalize_wrong=os.environ.get("CTF_PENALIZE_WRONG", "").lower() in ("1", "true", "yes"),
        top_rung_restarts=_int("CTF_TOP_RUNG_RESTARTS", 6),
        log_mirror=os.environ.get("CTF_LOG_MIRROR", "").lower() in ("1", "true", "yes"),
        max_output_tokens=_opt_int("CTF_MAX_OUTPUT_TOKENS"),
        min_output_tokens=_opt_int("CTF_MIN_OUTPUT_TOKENS"),
        ladder_depths=_depths(os.environ.get("CTF_LADDER_DEPTHS", "")),
        fresh_context_on_escalate=os.environ.get("CTF_FRESH_CONTEXT", "").lower()
        in ("1", "true", "yes"),
    )
