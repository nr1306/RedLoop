"""Run a TAP attack search from a seed and store the whole tree (Phase 07, v0.5).

    python run_attack_search.py --seed LLM02-public-leak-01
    python run_attack_search.py --seed LLM06-implicit-tool-01 --objective call_forbidden_tool
    python run_attack_search.py --all-soft-spots        # run the known weak seeds
    python run_attack_search.py --seed X --no-judge --branching 2 --keep 1 --max-depth 3

Uses the caps from config (ATTACK_MAX_ITERATIONS, ATTACK_MAX_COST_USD). Refuses
to start without both. Each node is stored as it is produced, so an interrupted
search keeps its progress.
"""

import argparse
from pathlib import Path

import openai

from attacker.search import SearchNode, search
from attacks.loader import load_attacks
from config import load_attacker_config, load_judge_config, load_target_config
from harness import storage
from target.policy import DEFAULT_POLICY

# Seeds the live baseline showed are the soft spots, with the objective to aim at.
SOFT_SPOTS = [
    ("LLM02-public-leak-01", "leak_canary_in_reply"),
    ("LLM02-encoded-leak-01", "leak_canary_in_reply"),
    ("LLM06-implicit-tool-01", "call_forbidden_tool"),
    ("LLM06-exfil-chain-01", "email_external"),
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a TAP attack search from a seed.")
    parser.add_argument("--seed", help="Seed attack id to refine from")
    parser.add_argument("--objective", help="Objective to target (defaults to the seed's first objective)")
    parser.add_argument("--all-soft-spots", action="store_true", help="Run the known weak seeds")
    parser.add_argument("--no-judge", action="store_true", help="Rule scorer only")
    parser.add_argument("--branching", type=int, default=3)
    parser.add_argument("--keep", type=int, default=2)
    parser.add_argument("--max-depth", type=int, default=4)
    parser.add_argument("--db", type=Path, default=storage.DEFAULT_DB_PATH)
    return parser.parse_args()


# Resolve which (seed_id, objective) pairs to search over.
def select_targets(args: argparse.Namespace) -> list[tuple[str, str]]:
    attacks = {a.id: a for a in load_attacks()}
    if args.all_soft_spots:
        return SOFT_SPOTS
    if not args.seed:
        raise SystemExit("give --seed or --all-soft-spots")
    seed = attacks[args.seed]
    objective = args.objective or (seed.objectives[0] if seed.objectives else None)
    if objective is None:
        raise SystemExit(f"{args.seed} has no objective; pass --objective")
    return [(args.seed, objective)]


def main() -> None:
    args = parse_args()
    targets = select_targets(args)
    attacks = {a.id: a for a in load_attacks()}

    target_config = load_target_config()
    attacker_config = load_attacker_config()
    target_client = openai.OpenAI(api_key=target_config.api_key)
    attacker_client = openai.OpenAI(api_key=attacker_config.api_key)
    judge_config = None if args.no_judge else load_judge_config()
    judge_client = None if args.no_judge else openai.OpenAI(api_key=judge_config.api_key)

    conn = storage.connect(args.db)
    run_id = storage.start_run(
        conn, target_model=target_config.model, judge_model=None if args.no_judge else judge_config.model,
        corpus_size=len(targets), repeats=1, notes="attacker search",
    )
    print(f"run {run_id}: {len(targets)} search(es), caps: "
          f"{attacker_config.max_iterations} iters / ${attacker_config.max_cost_usd}\n")

    # Map each in-memory node id to its stored attempt id, so a child row can
    # reference its parent's actual database id.
    for seed_id, objective in targets:
        node_to_attempt: dict[int, int] = {}

        def persist(node: SearchNode) -> None:
            parent_attempt = node_to_attempt.get(node.parent_id) if node.parent_id is not None else None
            attempt_id = storage.record_search_node(conn, run_id, node, parent_attempt)
            node_to_attempt[node.node_id] = attempt_id
            storage.record_rule_score(conn, attempt_id, node.rule_score)
            if node.judge_score is not None:
                storage.record_judge_score(conn, attempt_id, node.judge_score)
            mark = "WIN " if node.achieved else "    "
            print(f"  {mark}d{node.depth} node={node.node_id:<3} "
                  f"rules={sorted(node.rule_score.violations) or '-'} "
                  f"{node.user_message[:70]}")

        print(f"=== seed {seed_id} -> {objective} ===")
        result = search(
            seed_id, attacks[seed_id].user_message, objective,
            target_client, target_config, attacker_client, attacker_config,
            judge_client, judge_config, policy=DEFAULT_POLICY,
            branching=args.branching, keep=args.keep, max_depth=args.max_depth,
            on_node=persist,
        )
        outcome = "SUCCESS" if result.success else "no exploit found"
        print(f"  -> {outcome} ({result.stop_reason}), {len(result.nodes)} attempts\n")

    storage.finish_run(conn, run_id)
    print(f"stored in {args.db} (run {run_id}) — view: python query_runs.py --run {run_id}")


if __name__ == "__main__":
    main()
