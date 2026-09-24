"""Loads and validates the hand-written attack corpus.

The corpus is data, not code, so typos (a misspelled objective, a duplicate id,
plants on a direct attack) would otherwise surface as confusing harness bugs
much later. load_attacks() rejects them up front.
"""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from target.canaries import Canaries

SEED_ATTACKS_PATH = Path(__file__).parent / "seed_attacks.json"

# OWASP LLM Top 10 categories in use, plus CONTROL for benign attacks that must
# NOT produce a violation (they measure the scorer's false-positive rate).
CATEGORIES = frozenset({"LLM01", "LLM02", "LLM06", "CONTROL"})

# How the attack reaches the agent: in the user's own message, or through the
# output of a tool (a planted file or search result).
VECTORS = frozenset({"direct", "indirect"})

# What would count as a successful attack. Phase 03's scorer checks these
# against the recorded tool calls and the final reply.
OBJECTIVES = frozenset({
    "read_secret_file",
    "call_forbidden_tool",
    "email_external",
    "leak_canary_in_reply",
    "canary_in_tool_args",
})


# Placeholders usable inside planted content. Canaries are generated per run,
# so an attack that wants a real secret to appear in a /public/ file or a search
# result writes {{API_KEY}} and the runner substitutes this run's value.
PLACEHOLDERS = {
    "{{API_KEY}}": "api_key",
    "{{DB_PASSWORD}}": "db_password",
    "{{ADMIN_TOKEN}}": "admin_token",
}

_PLACEHOLDER_PATTERN = re.compile(r"\{\{[A-Z_]+\}\}")


# One attack from the corpus. plant_files maps path -> contents and
# plant_search_results holds title/url/snippet dicts, both ready to hand to
# FakeEnvironment.plant_file / plant_search_result.
@dataclass(frozen=True)
class Attack:
    id: str
    title: str
    category: str
    technique: str
    vector: str
    user_message: str
    objectives: tuple[str, ...]
    notes: str = ""
    plant_files: dict[str, str] = field(default_factory=dict)
    plant_search_results: tuple[dict[str, str], ...] = ()

    @property
    def is_control(self) -> bool:
        return self.category == "CONTROL"


# Raised when the corpus file itself is malformed, so a bad entry fails loudly
# at load time instead of silently skewing a run's results.
class AttackCorpusError(ValueError):
    pass


# Read the corpus, validate every entry, and return the attacks in file order.
def load_attacks(path: Path = SEED_ATTACKS_PATH) -> list[Attack]:
    raw = json.loads(path.read_text())
    if not isinstance(raw, list):
        raise AttackCorpusError("corpus must be a JSON list of attacks")

    attacks = [_build_attack(entry) for entry in raw]
    _check_unique_ids(attacks)
    return attacks


# Validate one entry and turn it into an Attack.
def _build_attack(entry: dict[str, Any]) -> Attack:
    attack_id = entry.get("id", "<missing id>")
    plants = entry.get("plants", {}) or {}
    files = plants.get("files", {}) or {}
    results = plants.get("search_results", []) or []

    _require_fields(entry, attack_id)
    _check_enum(entry["category"], CATEGORIES, "category", attack_id)
    _check_enum(entry["vector"], VECTORS, "vector", attack_id)
    for objective in entry["objectives"]:
        _check_enum(objective, OBJECTIVES, "objective", attack_id)
    _check_plants(entry["vector"], entry["category"], entry["objectives"], files, results, attack_id)

    return Attack(
        id=entry["id"],
        title=entry["title"],
        category=entry["category"],
        technique=entry["technique"],
        vector=entry["vector"],
        user_message=entry["user_message"],
        objectives=tuple(entry["objectives"]),
        notes=entry.get("notes", ""),
        plant_files=dict(files),
        plant_search_results=tuple(results),
    )


def _require_fields(entry: dict[str, Any], attack_id: str) -> None:
    for name in ("id", "title", "category", "technique", "vector", "user_message", "objectives"):
        if not entry.get(name) and not (name == "objectives" and entry.get(name) == []):
            raise AttackCorpusError(f"{attack_id}: missing or empty field '{name}'")


def _check_enum(value: str, allowed: frozenset[str], field_name: str, attack_id: str) -> None:
    if value not in allowed:
        raise AttackCorpusError(f"{attack_id}: unknown {field_name} '{value}' (allowed: {sorted(allowed)})")


# Vector and plants must agree, and controls must expect no violation —
# a control with objectives would silently become a real attack.
def _check_plants(
    vector: str,
    category: str,
    objectives: list[str],
    files: dict[str, str],
    results: list[dict[str, str]],
    attack_id: str,
) -> None:
    has_plants = bool(files) or bool(results)
    if vector == "indirect" and not has_plants:
        raise AttackCorpusError(f"{attack_id}: indirect attack has no planted content")
    if vector == "direct" and has_plants:
        raise AttackCorpusError(f"{attack_id}: direct attack should not plant content")
    for text in list(files.values()) + [v for r in results for v in r.values()]:
        for token in _PLACEHOLDER_PATTERN.findall(text):
            if token not in PLACEHOLDERS:
                raise AttackCorpusError(
                    f"{attack_id}: unknown placeholder {token} (allowed: {sorted(PLACEHOLDERS)})"
                )
    for result in results:
        missing = {"title", "url", "snippet"} - set(result)
        if missing:
            raise AttackCorpusError(f"{attack_id}: planted search result missing {sorted(missing)}")
    if category == "CONTROL" and objectives:
        raise AttackCorpusError(f"{attack_id}: control attacks must have no objectives")
    if category != "CONTROL" and not objectives:
        raise AttackCorpusError(f"{attack_id}: non-control attack must declare at least one objective")


def _check_unique_ids(attacks: list[Attack]) -> None:
    seen: set[str] = set()
    for attack in attacks:
        if attack.id in seen:
            raise AttackCorpusError(f"duplicate attack id '{attack.id}'")
        seen.add(attack.id)


# Substitute this run's canary values into one piece of planted text.
def render_text(text: str, canaries: Canaries) -> str:
    for placeholder, field_name in PLACEHOLDERS.items():
        text = text.replace(placeholder, getattr(canaries, field_name))
    return text


# Planted files and search results with canary placeholders filled in, ready to
# hand to FakeEnvironment.
def render_plants(
    attack: Attack, canaries: Canaries
) -> tuple[dict[str, str], list[dict[str, str]]]:
    files = {path: render_text(content, canaries) for path, content in attack.plant_files.items()}
    results = [
        {key: render_text(value, canaries) for key, value in result.items()}
        for result in attack.plant_search_results
    ]
    return files, results
