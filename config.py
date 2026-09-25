"""Loads settings from .env. Every module reads config through here, never os.environ directly."""

import os
from dataclasses import dataclass

from dotenv import load_dotenv


# Settings the target agent needs. frozen=True makes the object read-only,
# so no code can accidentally change the model or turn cap mid-run.
@dataclass(frozen=True)
class TargetConfig:
    api_key: str
    model: str
    max_turns: int


# Settings for the LLM judge. Separate from the target so the judge can run on a
# stronger (or cheaper) model than the agent being tested.
@dataclass(frozen=True)
class JudgeConfig:
    api_key: str
    model: str


# Settings for the attacker LLM (Phase 07). Separate model so a creative attacker
# is never coupled to the deliberately-weak target. Both caps are mandatory:
# a run must not start without an iteration cap and a cost cap (see CLAUDE.md).
@dataclass(frozen=True)
class AttackerConfig:
    api_key: str
    model: str
    max_iterations: int
    max_cost_usd: float


# Read one setting from the environment and fail loudly if it's missing or empty,
# instead of silently running with a None value.
def _require(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Missing required setting {name} — add it to .env (see .env.example)")
    return value


# Load .env into the environment, then collect the target's settings into one
# TargetConfig. max_turns arrives as text from .env, so it's converted to int.
def load_target_config() -> TargetConfig:
    load_dotenv()
    return TargetConfig(
        api_key=_require("OPENAI_API_KEY"),
        model=_require("TARGET_MODEL"),
        max_turns=int(_require("TARGET_MAX_TURNS")),
    )


def load_judge_config() -> JudgeConfig:
    load_dotenv()
    return JudgeConfig(
        api_key=_require("OPENAI_API_KEY"),
        model=_require("JUDGE_MODEL"),
    )


def load_attacker_config() -> AttackerConfig:
    load_dotenv()
    return AttackerConfig(
        api_key=_require("OPENAI_API_KEY"),
        model=_require("ATTACKER_MODEL"),
        max_iterations=int(_require("ATTACK_MAX_ITERATIONS")),
        max_cost_usd=float(_require("ATTACK_MAX_COST_USD")),
    )
