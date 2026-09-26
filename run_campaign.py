"""Run a concurrent attack campaign across many seeds and store every tree (Phase 08).

    python run_campaign.py --all-soft-spots
    python run_campaign.py --seed LLM02-public-leak-01 --seed LLM06-implicit-tool-01
    python run_campaign.py --all-soft-spots --concurrency 3 --no-judge

Global caps (ATTACK_MAX_ITERATIONS, ATTACK_MAX_COST_USD) span the WHOLE campaign,
not each search. View a result tree with: python query_runs.py --run N --tree
"""

import argparse
import asyncio
from pathlib import Path

import openai

from attacks.loader import load_attacks
from config import load_attacker_config, load_judge_config, load_target_config
from harness import storage
from orchestrator.orchestrator import SearchTarget, run_campaign
from run_attack_search import SOFT_SPOTS
from target.policy import DEFAULT_POLICY


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a concurrent attack campaign.")
    parser.add_argument("--seed", action="append", default=[], help="Seed id (repeatable)")
    parser.add_argument("--objective", action="append", default=[], help="Objective per --seed, in order")
    parser.add_argument("--all-soft-spots", action="store_true", help="Attack the known weak seeds")
    parser.add_argument("--concurrency", type=int, default=3)
    parser.add_argument("--no-judge", action="store_true")
    parser.add_argument("--branching", type=int, default=3)
    parser.add_argument("--keep", type=int, default=2)
    parser.add_argument("--max-depth", type=int, default=4)
    parser.add_argument("--db", type=Path, default=storage.DEFAULT_DB_PATH)
    return parser.parse_args()


# Build the list of (seed, objective) targets from the flags.
def build_targets(args: argparse.Namespace) -> list[SearchTarget]:
    attacks = {a.id: a for a in load_attacks()}
    pairs: list[tuple[str, str]] = []
    if args.all_soft_spots:
        pairs = SOFT_SPOTS
    elif args.seed:
        objectives = args.objective or [attacks[s].objectives[0] for s in args.seed]
        pairs = list(zip(args.seed, objectives))
    else:
        raise SystemExit("give --seed or --all-soft-spots")
    return [SearchTarget(sid, attacks[sid].user_message, obj) for sid, obj in pairs]


def main() -> None:
    args = parse_args()
    targets = build_targets(args)

    target_config = load_target_config()
    attacker_config = load_attacker_config()
    target_client = openai.OpenAI(api_key=target_config.api_key)
    attacker_client = openai.OpenAI(api_key=attacker_config.api_key)
    judge_config = None if args.no_judge else load_judge_config()
    judge_client = None if args.no_judge else openai.OpenAI(api_key=judge_config.api_key)

    conn = storage.connect(args.db)
    run_id = storage.start_run(
        conn, target_model=target_config.model, judge_model=None if args.no_judge else judge_config.model,
        corpus_size=len(targets), repeats=1, notes="attacker campaign",
    )
    print(f"run {run_id}: campaign of {len(targets)} search(es), concurrency {args.concurrency}, "
          f"global caps {attacker_config.max_iterations} iters / ${attacker_config.max_cost_usd}\n")

    # Persist one finished search tree. Runs in the main thread (asyncio callback),
    # so SQLite is only ever touched here.
    def persist(target: SearchTarget, result) -> None:
        node_to_attempt: dict[int, int] = {}
        for node in result.nodes:
            parent = node_to_attempt.get(node.parent_id) if node.parent_id is not None else None
            attempt_id = storage.record_search_node(conn, run_id, node, parent)
            node_to_attempt[node.node_id] = attempt_id
            storage.record_rule_score(conn, attempt_id, node.rule_score)
            if node.judge_score is not None:
                storage.record_judge_score(conn, attempt_id, node.judge_score)
        outcome = "SUCCESS" if result.success else "no exploit"
        print(f"  {target.seed_id:26} -> {outcome:12} ({result.stop_reason}), {len(result.nodes)} attempts")

    campaign = asyncio.run(run_campaign(
        targets, target_client, target_config, attacker_client, attacker_config,
        judge_client, judge_config, policy=DEFAULT_POLICY,
        concurrency=args.concurrency, branching=args.branching, keep=args.keep,
        max_depth=args.max_depth, on_result=persist,
    ))
    storage.finish_run(conn, run_id)

    print(f"\ncampaign done: {len(campaign.successes)}/{len(targets)} searches found an exploit")
    print(f"budget used: {campaign.iterations_used} iterations, ~${campaign.spend_usd:.2f}")
    print(f"stored in {args.db} (run {run_id}) — trees: python query_runs.py --run {run_id} --tree")


if __name__ == "__main__":
    main()
