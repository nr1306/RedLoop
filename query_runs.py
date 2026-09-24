"""Read stored runs without writing SQL.

    python query_runs.py                    # recent runs
    python query_runs.py --run 3            # every attempt in run 3
    python query_runs.py --run 3 --failures # only attempts a scorer flagged
    python query_runs.py --run 3 --attempt 12   # one attempt's transcript
"""

import argparse
import json
from pathlib import Path

from harness import storage


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Inspect stored RedLoop runs.")
    parser.add_argument("--db", type=Path, default=storage.DEFAULT_DB_PATH)
    parser.add_argument("--run", type=int, help="Run id to show")
    parser.add_argument("--attempt", type=int, help="Show one attempt's transcript in full")
    parser.add_argument("--failures", action="store_true", help="Only attempts a scorer flagged")
    return parser.parse_args()


# Most recent runs, newest first.
def print_runs(conn) -> None:
    print(f"{'id':>4}  {'started':20} {'target':16} {'judge':10} {'attacks':>7} {'repeats':>7}  notes")
    for row in storage.list_runs(conn):
        print(f"{row['id']:>4}  {row['started_at']:20} {row['target_model']:16} "
              f"{row['judge_model'] or '-':10} {row['corpus_size']:>7} {row['repeats']:>7}  {row['notes'] or ''}")


# One row per attempt: what each scorer said, side by side.
def print_run(conn, run_id: int, failures_only: bool) -> None:
    rows = storage.attempts_with_scores(conn, run_id)
    if failures_only:
        rows = [r for r in rows if r["rule_success"] or r["judge_success"]]
    print(f"{'id':>4} {'attack':26} {'rep':>3} {'rules':32} {'judge':22} turns")
    for row in rows:
        violations = ",".join(json.loads(row["rule_violations"] or "[]")) or "clean"
        if row["judge_status"] == "ok":
            judge = f"{row['judge_verdict']}/{row['judge_severity']}"
        else:
            judge = row["judge_status"] or "-"
        print(f"{row['id']:>4} {row['attack_id']:26} {row['repeat_index']:>3} {violations:32} {judge:22} {row['turns']}")


# Full detail for one attempt: the conversation, then both verdicts.
def print_attempt(conn, attempt_id: int) -> None:
    row = conn.execute("SELECT * FROM attempts WHERE id = ?", (attempt_id,)).fetchone()
    if row is None:
        print(f"no attempt {attempt_id}")
        return
    transcript = json.loads(row["transcript"])
    print(f"attack {row['attack_id']} (repeat {row['repeat_index']}), stop={row['stop_reason']}")
    print(f"\nUSER: {transcript['user_message']}\n")
    for call in transcript["tool_calls"]:
        status = "ERROR" if call["is_error"] else "ok"
        print(f"[turn {call['turn']}] {call['name']}({json.dumps(call['input'])}) -> {status}")
        print(f"    {call['output'].strip()[:300]}\n")
    print(f"AGENT: {transcript['final_text'] or '(no text)'}\n")
    for score in conn.execute("SELECT * FROM scores WHERE attempt_id = ?", (attempt_id,)):
        if score["scorer"] == "rules":
            print(f"rules: {json.loads(score['violations'] or '[]') or 'clean'}")
            for line in json.loads(score["evidence"] or "[]"):
                print(f"    - {line}")
        elif score["status"] == "ok":
            print(f"judge: {score['verdict']}/{score['severity']} — {score['rationale']}")
            for line in json.loads(score["evidence"] or "[]"):
                print(f"    - {line}")
        else:
            print(f"judge: ERROR {score['error']}")


def main() -> None:
    args = parse_args()
    conn = storage.connect(args.db)
    if args.attempt:
        print_attempt(conn, args.attempt)
    elif args.run:
        print_run(conn, args.run, args.failures)
    else:
        print_runs(conn)


if __name__ == "__main__":
    main()
