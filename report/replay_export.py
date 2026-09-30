"""Export a completed run's logged data as JSON for the replay visualization (Phase 11).

Nothing here is invented or simulated — every attempt comes straight from the
stored run. The replay plays these back in order. Outcome mapping (see the game
spec): a scorer FIRING means the attack succeeded (RedLoop scores violations,
not blocks), so:
  - clean       (no scorer flagged)                  -> the agent resisted (shield holds)
  - judge_only  (judge flagged, deterministic missed)-> soft catch (shield cracks)
  - hard_breach (a deterministic rule fired)          -> unambiguous breach (shield shatters)
"""

import json
import sqlite3
from pathlib import Path

from attacker.budget import estimate_cost
from harness import storage


# Classify one attempt into the three replay outcomes.
def _outcome(rule_flagged: bool, judge_flagged: bool | None) -> str:
    if rule_flagged:
        return "hard_breach"
    if judge_flagged:
        return "judge_only"
    return "clean"


# Recover the OWASP category for attacker-run rows (stored as 'ATTACKER').
def _category(row: dict) -> str:
    cat = row["category"]
    seed = row["seed_id"] or row["attack_id"]
    if cat == "ATTACKER" and seed and seed.startswith("LLM"):
        return seed.split("-")[0]
    return cat


# Build the replay payload for one run.
def export_replay(conn: sqlite3.Connection, run_id: int) -> dict:
    run = storage.get_run(conn, run_id)
    if run is None:
        raise ValueError(f"no run {run_id}")
    rows = storage.attempts_with_scores(conn, run_id)
    # Judge token usage isn't in the shared view; pull it directly per attempt.
    judge_tok = {
        r['attempt_id']: (r['input_tokens'], r['output_tokens'])
        for r in conn.execute("SELECT attempt_id, input_tokens, output_tokens FROM scores WHERE scorer='judge'")
    }
    judge_model = run['judge_model']
    target_model = run['target_model']
    total_tokens = 0
    total_cost = 0.0

    attempts = []
    breaches = 0
    # Targets (seed+objective) that were breached, to compute the headline meter.
    breached_targets: set[str] = set()
    all_targets: set[str] = set()
    for row in rows:
        rule_flagged = bool(row["rule_success"])
        judge_flagged = bool(row["judge_success"]) if row["judge_status"] == "ok" else None
        outcome = _outcome(rule_flagged, judge_flagged)
        if row["category"] != "CONTROL":
            key = f"{row['seed_id']}::{row['objective']}"
            all_targets.add(key)
            if outcome != "clean":
                breached_targets.add(key)
        if outcome != "clean":
            breaches += 1
        t_in, t_out = row["input_tokens"] or 0, row["output_tokens"] or 0
        j_in, j_out = judge_tok.get(row["id"], (0, 0))
        tokens = t_in + t_out + j_in + j_out
        cost = estimate_cost(target_model, t_in, t_out) + (
            estimate_cost(judge_model, j_in, j_out) if judge_model else 0.0
        )
        total_tokens += tokens
        total_cost += cost
        attempts.append({
            "id": row["id"],
            "parent_id": row["parent_node_id"],
            "seed_id": row["seed_id"] or row["attack_id"],
            "category": _category(row),
            "objective": row["objective"],
            "depth": row["depth"] or 0,
            "is_control": row["category"] == "CONTROL",
            "prompt": row["attacker_message"] or row["user_message"],
            "outcome": outcome,
            "rule_violations": json.loads(row["rule_violations"] or "[]"),
            "severity": row["judge_severity"],
            "rationale": row["judge_rationale"] or "",
            "turns": row["turns"] or 0,
            "tokens": tokens,
            "cost": round(cost, 5),
        })

    robustness = 100.0 * (1 - len(breached_targets) / len(all_targets)) if all_targets else 100.0
    return {
        "run_id": run_id,
        "target_model": run["target_model"],
        "judge_model": run["judge_model"],
        "notes": run["notes"] or "",
        "robustness_score": round(robustness, 1),
        "targets_total": len(all_targets),
        "targets_breached": len(breached_targets),
        "total_attempts": len(attempts),
        "breaches": breaches,
        "total_tokens": total_tokens,
        "total_cost_usd": round(total_cost, 4),
        "attempts": attempts,
    }


# CLI: write the JSON next to where the artifact build will read it.
def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Export a run's data for the replay visualization.")
    parser.add_argument("--run", type=int, required=True)
    parser.add_argument("--db", type=Path, default=storage.DEFAULT_DB_PATH)
    parser.add_argument("--out", type=Path, default=Path("replay_data.json"))
    args = parser.parse_args()
    conn = storage.connect(args.db)
    payload = export_replay(conn, args.run)
    args.out.write_text(json.dumps(payload, indent=2))
    print(f"wrote {args.out}: {payload['total_attempts']} attempts, {payload['breaches']} breaches, "
          f"robustness {payload['robustness_score']}")


if __name__ == "__main__":
    main()
