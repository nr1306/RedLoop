"""SQLite storage for runs, attempts and scores.

Three tables, one purpose each:
  runs     — one row per invocation of the harness (what was tested, with what)
  attempts — one row per attack execution (the transcript and what it cost)
  scores   — one row per scorer per attempt, so "where do the two scorers
             disagree?" is a single query rather than a re-run

The database holds full transcripts and canary values, so data/ is gitignored.
Plain stdlib sqlite3: no ORM at this scale.
"""

import json
import sqlite3
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from attacks.loader import Attack
from scoring.scorer_judge import JudgeScore
from scoring.scorer_rules import RuleScore
from target.canaries import Canaries
from target.transcript import Transcript

DEFAULT_DB_PATH = Path("data/redloop.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at    TEXT NOT NULL,
    finished_at   TEXT,
    target_model  TEXT NOT NULL,
    judge_model   TEXT,
    corpus_size   INTEGER NOT NULL,
    repeats       INTEGER NOT NULL,
    notes         TEXT
);

CREATE TABLE IF NOT EXISTS attempts (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id         INTEGER NOT NULL REFERENCES runs(id),
    attack_id      TEXT NOT NULL,
    category       TEXT NOT NULL,
    vector         TEXT NOT NULL,
    repeat_index   INTEGER NOT NULL,
    user_message   TEXT NOT NULL,
    objectives     TEXT NOT NULL,
    transcript     TEXT NOT NULL,
    canaries       TEXT NOT NULL,
    turns          INTEGER NOT NULL,
    input_tokens   INTEGER NOT NULL,
    output_tokens  INTEGER NOT NULL,
    stop_reason    TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    -- Lineage (Phase 07/08): NULL/seed defaults for static-harness attempts.
    parent_node_id     INTEGER,
    seed_id            TEXT,
    objective          TEXT,
    depth              INTEGER NOT NULL DEFAULT 0,
    attacker_message   TEXT,
    attacker_rationale TEXT
);

CREATE TABLE IF NOT EXISTS scores (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    attempt_id    INTEGER NOT NULL REFERENCES attempts(id),
    scorer        TEXT NOT NULL,
    status        TEXT NOT NULL,
    success       INTEGER,
    violations    TEXT,
    verdict       TEXT,
    severity      TEXT,
    rationale     TEXT,
    evidence      TEXT,
    error         TEXT,
    input_tokens  INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_attempts_run ON attempts(run_id);
CREATE INDEX IF NOT EXISTS idx_scores_attempt ON scores(attempt_id);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# Open (creating if needed) the database and make sure the schema exists.
# row_factory gives dict-like rows so callers read columns by name.
def connect(path: Path = DEFAULT_DB_PATH) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


# Open a run and return its id; everything else is recorded against it.
def start_run(
    conn: sqlite3.Connection, target_model: str, judge_model: str | None, corpus_size: int, repeats: int, notes: str = ""
) -> int:
    cursor = conn.execute(
        "INSERT INTO runs (started_at, target_model, judge_model, corpus_size, repeats, notes)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (_now(), target_model, judge_model, corpus_size, repeats, notes),
    )
    conn.commit()
    return int(cursor.lastrowid)


def finish_run(conn: sqlite3.Connection, run_id: int) -> None:
    conn.execute("UPDATE runs SET finished_at = ? WHERE id = ?", (_now(), run_id))
    conn.commit()


# Store one execution of one attack. Canaries are stored alongside the
# transcript so an old attempt can still be re-scored later.
def record_attempt(
    conn: sqlite3.Connection,
    run_id: int,
    attack: Attack,
    repeat_index: int,
    transcript: Transcript,
    canaries: Canaries,
) -> int:
    cursor = conn.execute(
        "INSERT INTO attempts (run_id, attack_id, category, vector, repeat_index, user_message, objectives,"
        " transcript, canaries, turns, input_tokens, output_tokens, stop_reason, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            run_id,
            attack.id,
            attack.category,
            attack.vector,
            repeat_index,
            attack.user_message,
            json.dumps(list(attack.objectives)),
            json.dumps(asdict(transcript)),
            json.dumps(asdict(canaries)),
            transcript.turns_used,
            transcript.input_tokens,
            transcript.output_tokens,
            transcript.stop_reason,
            _now(),
        ),
    )
    conn.commit()
    return int(cursor.lastrowid)


def record_rule_score(conn: sqlite3.Connection, attempt_id: int, score: RuleScore) -> None:
    conn.execute(
        "INSERT INTO scores (attempt_id, scorer, status, success, violations, evidence)"
        " VALUES (?, 'rules', 'ok', ?, ?, ?)",
        (
            attempt_id,
            int(score.success),
            json.dumps(sorted(score.violations)),
            json.dumps([f"{f.kind}: {f.detail}" for f in score.findings]),
        ),
    )
    conn.commit()


def record_judge_score(conn: sqlite3.Connection, attempt_id: int, score: JudgeScore) -> None:
    conn.execute(
        "INSERT INTO scores (attempt_id, scorer, status, success, verdict, severity, rationale, evidence,"
        " input_tokens, output_tokens) VALUES (?, 'judge', 'ok', ?, ?, ?, ?, ?, ?, ?)",
        (
            attempt_id,
            int(score.is_violation),
            score.verdict,
            score.severity,
            score.rationale,
            json.dumps(score.evidence),
            score.input_tokens,
            score.output_tokens,
        ),
    )
    conn.commit()


# A judge failure is recorded, not raised: one flaky call must not discard the
# rest of a run, and an unscored attempt must not look like a clean one.
def record_judge_error(conn: sqlite3.Connection, attempt_id: int, error: str) -> None:
    conn.execute(
        "INSERT INTO scores (attempt_id, scorer, status, error) VALUES (?, 'judge', 'error', ?)",
        (attempt_id, error),
    )
    conn.commit()


# --- reading back ---

def get_run(conn: sqlite3.Connection, run_id: int) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()


def list_runs(conn: sqlite3.Connection, limit: int = 20) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()


# One row per attempt with both scorers' verdicts flattened onto it, which is
# what the report and the CLI viewer both want.
def attempts_with_scores(conn: sqlite3.Connection, run_id: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT a.*,
               r.success    AS rule_success,
               r.violations AS rule_violations,
               j.status     AS judge_status,
               j.success    AS judge_success,
               j.verdict    AS judge_verdict,
               j.severity   AS judge_severity,
               j.rationale  AS judge_rationale,
               j.error      AS judge_error
        FROM attempts a
        LEFT JOIN scores r ON r.attempt_id = a.id AND r.scorer = 'rules'
        LEFT JOIN scores j ON j.attempt_id = a.id AND j.scorer = 'judge'
        WHERE a.run_id = ?
        ORDER BY a.id
        """,
        (run_id,),
    ).fetchall()
    return [dict(row) for row in rows]


# --- attacker search (Phase 07) ---

# Store one search-tree node: its transcript, both scores, and its lineage.
# Returns the storage attempt id, which the caller maps to the node's own id so
# children can point at the right parent row.
def record_search_node(
    conn: sqlite3.Connection,
    run_id: int,
    node,
    parent_attempt_id: int | None,
) -> int:
    cursor = conn.execute(
        "INSERT INTO attempts (run_id, attack_id, category, vector, repeat_index, user_message,"
        " objectives, transcript, canaries, turns, input_tokens, output_tokens, stop_reason, created_at,"
        " parent_node_id, seed_id, objective, depth, attacker_message, attacker_rationale)"
        " VALUES (?, ?, 'ATTACKER', 'direct', 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            run_id,
            node.seed_id,
            node.user_message,
            json.dumps([node.objective]),
            json.dumps(asdict(node.transcript)),
            json.dumps(asdict(node.canaries)),
            node.transcript.turns_used,
            node.transcript.input_tokens,
            node.transcript.output_tokens,
            node.transcript.stop_reason,
            _now(),
            parent_attempt_id,
            node.seed_id,
            node.objective,
            node.depth,
            node.user_message,
            node.attacker_rationale,
        ),
    )
    conn.commit()
    return int(cursor.lastrowid)
