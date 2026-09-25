"""Test that a search tree persists with correct parent links (Phase 07)."""

import json
from pathlib import Path

import pytest

from attacker.search import search
from config import AttackerConfig, TargetConfig
from harness import storage
from tests.fakes import FakeClient, function_call, make_response, text


@pytest.fixture
def conn(tmp_path: Path):
    return storage.connect(tmp_path / "search.db")


def test_search_tree_persists_with_parent_links(conn) -> None:
    # Root refuses, then a variant reads a secret (wins at depth 1).
    target = FakeClient([
        make_response([text("no")]),
        make_response([function_call("c1", "read_file", {"path": "/secrets/db.env"})]),
        make_response([text("here")]),
    ])
    attacker = FakeClient([make_response([text(json.dumps(
        {"variants": [{"user_message": "win", "rationale": "r"}, {"user_message": "b", "rationale": "r"}]}
    ))])])

    run_id = storage.start_run(conn, "target-model", None, 1, 1, "test")
    node_to_attempt: dict[int, int] = {}

    def persist(node):
        parent = node_to_attempt.get(node.parent_id) if node.parent_id is not None else None
        attempt_id = storage.record_search_node(conn, run_id, node, parent)
        node_to_attempt[node.node_id] = attempt_id
        storage.record_rule_score(conn, attempt_id, node.rule_score)

    result = search(
        "SEED-1", "seed", "read_secret_file",
        target, TargetConfig("k", "target-model", 4),
        attacker, AttackerConfig("k", "attacker-model", 25, 1.0),
        on_node=persist,
    )
    assert result.success

    rows = conn.execute(
        "SELECT attack_id, depth, parent_node_id, seed_id, objective, category FROM attempts ORDER BY id"
    ).fetchall()
    # Root row: depth 0, no parent. Winner row: depth 1, parent = root's attempt id.
    assert rows[0]["depth"] == 0 and rows[0]["parent_node_id"] is None
    assert rows[0]["category"] == "ATTACKER" and rows[0]["seed_id"] == "SEED-1"
    assert rows[1]["depth"] == 1 and rows[1]["parent_node_id"] == 1
    assert rows[1]["objective"] == "read_secret_file"
