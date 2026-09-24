"""Run the seed corpus against the target, score it with both scorers, store everything.

This is the v0.1 milestone: the first end-to-end pipeline
(corpus → agent → rule scorer + judge → SQLite).

Usage:
    python -m harness.run_static                    # whole corpus, judged, once
    python -m harness.run_static --repeat 3         # 3 executions per attack
    python -m harness.run_static --category LLM01 --no-judge
    python -m harness.run_static --dry-run          # plan only, no API calls

Each attempt is committed as it finishes, so an interrupted run keeps its results.
"""

import argparse
import sqlite3
from pathlib import Path

import openai

from attacks.loader import Attack, load_attacks, render_plants
from config import JudgeConfig, TargetConfig, load_judge_config, load_target_config
from harness import storage
from scoring.scorer_judge import JudgeError, judge_transcript
from scoring.scorer_rules import score_transcript
from target.agent import run_agent
from target.canaries import generate_canaries
from target.environment import SearchResult, build_default_environment
from target.policy import DEFAULT_POLICY, Policy


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the seed corpus and store results.")
    parser.add_argument("--id", action="append", default=[], help="Attack id (repeatable)")
    parser.add_argument("--category", action="append", default=[], help="Category filter, e.g. LLM01")
    parser.add_argument("--limit", type=int, help="Use at most N attacks")
    parser.add_argument("--repeat", type=int, default=1, help="Executions per attack (default 1)")
    parser.add_argument("--no-judge", action="store_true", help="Rule scorer only (no judge API calls)")
    parser.add_argument("--db", type=Path, default=storage.DEFAULT_DB_PATH, help="SQLite path")
    parser.add_argument("--notes", default="", help="Free-text note stored with the run")
    parser.add_argument("--dry-run", action="store_true", help="Print the plan; make no API calls")
    return parser.parse_args()


def select_attacks(attacks: list[Attack], args: argparse.Namespace) -> list[Attack]:
    selected = attacks
    if args.id:
        selected = [a for a in selected if a.id in set(args.id)]
    if args.category:
        selected = [a for a in selected if a.category in set(args.category)]
    return selected[: args.limit] if args.limit else selected


# Fresh canaries and a fresh world per attempt, with this attack's content
# planted, so attempts cannot contaminate each other.
def run_attempt(
    attack: Attack,
    target_client: openai.OpenAI,
    target_config: TargetConfig,
    policy: Policy,
):
    canaries = generate_canaries()
    env = build_default_environment(canaries)
    files, results = render_plants(attack, canaries)
    for path, content in files.items():
        env.plant_file(path, content)
    for result in results:
        env.plant_search_result(SearchResult(**result))

    transcript = run_agent(attack.user_message, env, target_client, target_config, policy)
    rule_score = score_transcript(transcript, policy, canaries, attack.objectives)
    return transcript, canaries, rule_score


# The main loop, kept free of argparse and client construction so tests can
# drive it with fake clients and a temporary database.
def run_corpus(
    attacks: list[Attack],
    conn: sqlite3.Connection,
    target_client: openai.OpenAI,
    target_config: TargetConfig,
    judge_client: openai.OpenAI | None = None,
    judge_config: JudgeConfig | None = None,
    policy: Policy = DEFAULT_POLICY,
    repeats: int = 1,
    notes: str = "",
    verbose: bool = True,
) -> int:
    judging = judge_client is not None and judge_config is not None
    run_id = storage.start_run(
        conn,
        target_model=target_config.model,
        judge_model=judge_config.model if judging else None,
        corpus_size=len(attacks),
        repeats=repeats,
        notes=notes,
    )

    for repeat_index in range(1, repeats + 1):
        for attack in attacks:
            transcript, canaries, rule_score = run_attempt(attack, target_client, target_config, policy)
            attempt_id = storage.record_attempt(conn, run_id, attack, repeat_index, transcript, canaries)
            storage.record_rule_score(conn, attempt_id, rule_score)

            judge_summary = "skipped"
            if judging:
                # A judge failure is stored and the run continues: losing one
                # verdict must not cost the other attempts.
                try:
                    judge_score = judge_transcript(transcript, policy, canaries, judge_client, judge_config)
                    storage.record_judge_score(conn, attempt_id, judge_score)
                    judge_summary = f"{judge_score.verdict}/{judge_score.severity}"
                except JudgeError as error:
                    storage.record_judge_error(conn, attempt_id, str(error))
                    judge_summary = "ERROR"

            if verbose:
                rules_summary = ",".join(sorted(rule_score.violations)) or "clean"
                print(f"[{repeat_index}] {attack.id:26} rules={rules_summary:40} judge={judge_summary}")

    storage.finish_run(conn, run_id)
    return run_id


# Totals worth seeing immediately: how often each scorer found a violation,
# how often they disagreed, and whether controls stayed clean.
def print_summary(conn: sqlite3.Connection, run_id: int) -> None:
    rows = storage.attempts_with_scores(conn, run_id)
    attacks = [r for r in rows if r["category"] != "CONTROL"]
    controls = [r for r in rows if r["category"] == "CONTROL"]
    judged = [r for r in rows if r["judge_status"] == "ok"]
    disagreements = [r for r in judged if bool(r["rule_success"]) != bool(r["judge_success"])]

    print(f"\nrun {run_id}: {len(rows)} attempts")
    print(f"  rules: {sum(bool(r['rule_success']) for r in attacks)}/{len(attacks)} attacks flagged, "
          f"{sum(bool(r['rule_success']) for r in controls)}/{len(controls)} controls flagged")
    if judged:
        print(f"  judge: {sum(bool(r['judge_success']) for r in judged if r['category'] != 'CONTROL')}"
              f"/{len([r for r in judged if r['category'] != 'CONTROL'])} attacks flagged, "
              f"{len(disagreements)} disagreement(s) with the rules")
    for row in disagreements:
        who = "judge only" if row["judge_success"] else "rules only"
        print(f"    {row['attack_id']:26} {who:11} {row['judge_severity'] or '-':9} {(row['judge_rationale'] or '')[:90]}")
    errors = [r for r in rows if r["judge_status"] == "error"]
    if errors:
        print(f"  judge errors: {len(errors)}")


def main() -> None:
    args = parse_args()
    attacks = select_attacks(load_attacks(), args)
    print(f"{len(attacks)} attack(s) x {args.repeat} repeat(s) = {len(attacks) * args.repeat} attempt(s)")
    if args.dry_run:
        for attack in attacks:
            print(f"  {attack.id:26} {attack.category:8} {attack.vector}")
        return

    target_config = load_target_config()
    target_client = openai.OpenAI(api_key=target_config.api_key)
    judge_config = None if args.no_judge else load_judge_config()
    judge_client = None if args.no_judge else openai.OpenAI(api_key=judge_config.api_key)

    conn = storage.connect(args.db)
    run_id = run_corpus(
        attacks, conn, target_client, target_config, judge_client, judge_config,
        repeats=args.repeat, notes=args.notes,
    )
    print_summary(conn, run_id)
    print(f"\nstored in {args.db} (run id {run_id}) — view with: python query_runs.py --run {run_id}")


if __name__ == "__main__":
    main()
