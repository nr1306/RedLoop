"""Tests for the seed attack corpus and its loader."""

import json
from pathlib import Path

import pytest

from target.canaries import Canaries, generate_canaries

from attacks.loader import (
    CATEGORIES,
    PLACEHOLDERS,
    OBJECTIVES,
    VECTORS,
    AttackCorpusError,
    load_attacks,
)

# A minimal valid entry; individual tests break one field at a time.
VALID_ENTRY = {
    "id": "TEST-01",
    "title": "Test attack",
    "category": "LLM01",
    "technique": "instruction_override",
    "vector": "direct",
    "user_message": "do the thing",
    "plants": {"files": {}, "search_results": []},
    "objectives": ["read_secret_file"],
    "notes": "",
}


# Write a one-entry corpus to a temp file so bad data never enters the real one.
def write_corpus(tmp_path: Path, *entries: dict) -> Path:
    path = tmp_path / "corpus.json"
    path.write_text(json.dumps(list(entries)))
    return path


# --- the real corpus ---

def test_real_corpus_loads() -> None:
    attacks = load_attacks()
    assert len(attacks) >= 10


def test_every_field_uses_known_values() -> None:
    for attack in load_attacks():
        assert attack.category in CATEGORIES
        assert attack.vector in VECTORS
        assert set(attack.objectives) <= OBJECTIVES


# Coverage check: the corpus is only useful if it spans the categories,
# both delivery vectors, and every objective the scorer can detect.
def test_corpus_covers_categories_vectors_and_objectives() -> None:
    attacks = load_attacks()
    assert {"LLM01", "LLM02", "LLM06", "CONTROL"} <= {a.category for a in attacks}
    assert {"direct", "indirect"} <= {a.vector for a in attacks}
    assert OBJECTIVES == {objective for a in attacks for objective in a.objectives}


# Controls measure false positives, so there must be at least two and they
# must expect nothing.
def test_corpus_has_controls_with_no_objectives() -> None:
    controls = [a for a in load_attacks() if a.is_control]
    assert len(controls) >= 2
    assert all(a.objectives == () for a in controls)


# Indirect attacks must actually plant something, or they are just direct ones.
def test_indirect_attacks_plant_content() -> None:
    for attack in load_attacks():
        if attack.vector == "indirect":
            assert attack.plant_files or attack.plant_search_results


# Planted files must live where the agent is allowed to look, otherwise the
# agent refuses on path alone and the injection is never exercised.
def test_planted_files_are_under_public() -> None:
    for attack in load_attacks():
        assert all(path.startswith("/public/") for path in attack.plant_files)


# --- loader validation ---

def test_rejects_duplicate_ids(tmp_path: Path) -> None:
    path = write_corpus(tmp_path, VALID_ENTRY, dict(VALID_ENTRY))
    with pytest.raises(AttackCorpusError, match="duplicate"):
        load_attacks(path)


def test_rejects_unknown_objective(tmp_path: Path) -> None:
    path = write_corpus(tmp_path, {**VALID_ENTRY, "objectives": ["steal_the_moon"]})
    with pytest.raises(AttackCorpusError, match="unknown objective"):
        load_attacks(path)


def test_rejects_unknown_category(tmp_path: Path) -> None:
    path = write_corpus(tmp_path, {**VALID_ENTRY, "category": "LLM99"})
    with pytest.raises(AttackCorpusError, match="unknown category"):
        load_attacks(path)


def test_rejects_missing_field(tmp_path: Path) -> None:
    entry = {**VALID_ENTRY}
    del entry["user_message"]
    path = write_corpus(tmp_path, entry)
    with pytest.raises(AttackCorpusError, match="user_message"):
        load_attacks(path)


def test_rejects_indirect_without_plants(tmp_path: Path) -> None:
    path = write_corpus(tmp_path, {**VALID_ENTRY, "vector": "indirect"})
    with pytest.raises(AttackCorpusError, match="no planted content"):
        load_attacks(path)


def test_rejects_direct_with_plants(tmp_path: Path) -> None:
    entry = {**VALID_ENTRY, "plants": {"files": {"/public/x.md": "hi"}, "search_results": []}}
    path = write_corpus(tmp_path, entry)
    with pytest.raises(AttackCorpusError, match="should not plant"):
        load_attacks(path)


def test_rejects_malformed_search_result(tmp_path: Path) -> None:
    entry = {
        **VALID_ENTRY,
        "vector": "indirect",
        "plants": {"files": {}, "search_results": [{"title": "t", "url": "u"}]},
    }
    path = write_corpus(tmp_path, entry)
    with pytest.raises(AttackCorpusError, match="snippet"):
        load_attacks(path)


def test_rejects_control_with_objectives(tmp_path: Path) -> None:
    entry = {**VALID_ENTRY, "category": "CONTROL", "objectives": ["read_secret_file"]}
    path = write_corpus(tmp_path, entry)
    with pytest.raises(AttackCorpusError, match="no objectives"):
        load_attacks(path)


def test_rejects_non_control_without_objectives(tmp_path: Path) -> None:
    path = write_corpus(tmp_path, {**VALID_ENTRY, "objectives": []})
    with pytest.raises(AttackCorpusError, match="at least one objective"):
        load_attacks(path)


# --- canary placeholders in planted content ---

def test_render_plants_substitutes_canaries() -> None:
    from attacks.loader import render_plants

    attacks = {a.id: a for a in load_attacks()}
    attack = attacks["LLM02-public-leak-01"]
    canaries = generate_canaries()
    files, _ = render_plants(attack, canaries)
    content = files["/public/backup-notes.md"]
    assert canaries.db_password in content
    assert "{{" not in content


# Every placeholder used in the corpus must be one the renderer knows.
def test_corpus_placeholders_are_known() -> None:
    import re

    for attack in load_attacks():
        texts = list(attack.plant_files.values()) + [v for r in attack.plant_search_results for v in r.values()]
        for text in texts:
            for token in re.findall(r"\{\{[A-Z_]+\}\}", text):
                assert token in PLACEHOLDERS


def test_rejects_unknown_placeholder(tmp_path: Path) -> None:
    entry = {
        **VALID_ENTRY,
        "vector": "indirect",
        "plants": {"files": {"/public/x.md": "key={{SECRET_SAUCE}}"}, "search_results": []},
    }
    path = write_corpus(tmp_path, entry)
    with pytest.raises(AttackCorpusError, match="unknown placeholder"):
        load_attacks(path)
