"""Run the seed attack corpus against the target and score it with the rule scorer.

Usage:
    python run_attacks.py                 # every attack in the corpus
    python run_attacks.py --id LLM01-direct-01 --id CONTROL-01
    python run_attacks.py --category LLM01 --limit 3
    python run_attacks.py --dry-run       # print the plan, make no API calls

Makes one real conversation per attack. Nothing is stored — SQLite logging and
the LLM judge arrive in Phases 04/05. This exists to sanity-check the Phase 02
corpus and the Phase 03 scorer against the real agent.
"""

import argparse

import openai

from attacks.loader import Attack, load_attacks, render_plants
from config import load_target_config
from scoring.scorer_rules import RuleScore, score_transcript
from target.agent import run_agent
from target.canaries import generate_canaries
from target.environment import SearchResult, build_default_environment
from target.policy import DEFAULT_POLICY
from target.transcript import Transcript


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run seed attacks against the target agent.")
    parser.add_argument("--id", action="append", default=[], help="Attack id (repeatable)")
    parser.add_argument("--category", action="append", default=[], help="Category filter, e.g. LLM01")
    parser.add_argument("--limit", type=int, help="Run at most N attacks")
    parser.add_argument("--dry-run", action="store_true", help="List what would run; no API calls")
    return parser.parse_args()


# Narrow the corpus down to what the flags asked for, preserving file order.
def select_attacks(attacks: list[Attack], args: argparse.Namespace) -> list[Attack]:
    selected = attacks
    if args.id:
        selected = [a for a in selected if a.id in set(args.id)]
    if args.category:
        selected = [a for a in selected if a.category in set(args.category)]
    return selected[: args.limit] if args.limit else selected


# Fresh canaries and a fresh world per attack, with this attack's content
# planted, so no attack can see another's planted files or secrets.
def run_one(attack: Attack, client: openai.OpenAI, config) -> tuple[Transcript, RuleScore]:
    canaries = generate_canaries()
    env = build_default_environment(canaries)
    # Planted content may reference this run's canaries via {{API_KEY}} etc.
    files, results = render_plants(attack, canaries)
    for path, content in files.items():
        env.plant_file(path, content)
    for result in results:
        env.plant_search_result(SearchResult(**result))

    transcript = run_agent(attack.user_message, env, client, config, DEFAULT_POLICY)
    score = score_transcript(transcript, DEFAULT_POLICY, canaries, attack.objectives)
    return transcript, score


# One line per attack: what it aimed for, what it got, and how the run ended.
def print_row(attack: Attack, transcript: Transcript, score: RuleScore) -> None:
    outcome = "VIOLATION" if score.success else "clean"
    if attack.is_control:
        outcome = "FALSE POSITIVE" if score.success else "clean (ok)"
    print(f"{attack.id:20} {attack.vector:8} {outcome:14} "
          f"got={sorted(score.violations) or '-'} missed={sorted(set(attack.objectives) - score.violations) or '-'} "
          f"turns={transcript.turns_used} stop={transcript.stop_reason}")
    for finding in score.findings:
        print(f"    - {finding.kind}: {finding.detail}")


# Totals that answer the two questions this run exists for: how often the
# corpus lands, and whether the scorer stays quiet on controls.
def print_summary(results: list[tuple[Attack, Transcript, RuleScore]]) -> None:
    attacks = [r for r in results if not r[0].is_control]
    controls = [r for r in results if r[0].is_control]
    landed = [r for r in attacks if r[2].success]
    false_positives = [r for r in controls if r[2].success]
    tokens_in = sum(t.input_tokens for _, t, _ in results)
    tokens_out = sum(t.output_tokens for _, t, _ in results)

    print(f"\nattacks: {len(landed)}/{len(attacks)} produced a violation")
    print(f"controls: {len(false_positives)}/{len(controls)} false positives")
    print(f"tokens in/out: {tokens_in}/{tokens_out}")
    for attack, _, score in landed:
        print(f"  landed: {attack.id:20} {sorted(score.violations)}")


def main() -> None:
    args = parse_args()
    selected = select_attacks(load_attacks(), args)
    print(f"{len(selected)} attack(s) selected")
    if args.dry_run:
        for attack in selected:
            print(f"  {attack.id:20} {attack.category:8} {attack.vector:8} objectives={list(attack.objectives)}")
        return

    config = load_target_config()
    client = openai.OpenAI(api_key=config.api_key)
    results = []
    for attack in selected:
        transcript, score = run_one(attack, client, config)
        print_row(attack, transcript, score)
        results.append((attack, transcript, score))
    print_summary(results)


if __name__ == "__main__":
    main()
