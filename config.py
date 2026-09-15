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
