"""Run many attack searches concurrently under one shared budget (Phase 08).

Concurrency without rewriting the sync stack: each search still runs the tested
synchronous `search()`, but the orchestrator launches several at once with
asyncio.to_thread. Because API calls are I/O-bound (mostly waiting on the
network), threads overlap that waiting and the campaign finishes far sooner than
running searches one after another.

Two rails:
- ONE shared Budget across all searches — the campaign's global iteration + cost
  cap, not a per-search cap.
- A Semaphore limiting how many searches are in flight, to avoid rate-limit storms.

Searches run in threads; results come back to the main thread, where SQLite
writes happen — so the database is only ever touched from one thread.
"""

import asyncio
from dataclasses import dataclass
from typing import Callable

import openai

from attacker.attacker import AttackerConfig
from attacker.budget import Budget
from attacker.search import SearchResult, search
from config import JudgeConfig, TargetConfig
from target.policy import DEFAULT_POLICY, Policy

# One thing to attack: a seed and the objective to drive it toward.
@dataclass(frozen=True)
class SearchTarget:
    seed_id: str
    seed_message: str
    objective: str


# The whole campaign's outcome: each search's result, in the order given, plus
# how much of the shared budget was consumed.
@dataclass
class CampaignResult:
    results: list[SearchResult]
    iterations_used: int
    spend_usd: float

    @property
    def successes(self) -> list[SearchResult]:
        return [r for r in self.results if r.success]


# Run all targets concurrently. clients are shared across searches (the OpenAI
# client is safe for concurrent use); one shared Budget enforces the global caps.
# on_result fires as each search finishes, in the main thread, for persistence.
async def run_campaign(
    targets: list[SearchTarget],
    target_client: openai.OpenAI,
    target_config: TargetConfig,
    attacker_client: openai.OpenAI,
    attacker_config: AttackerConfig,
    judge_client: openai.OpenAI | None = None,
    judge_config: JudgeConfig | None = None,
    policy: Policy = DEFAULT_POLICY,
    concurrency: int = 3,
    branching: int = 3,
    keep: int = 2,
    max_depth: int = 4,
    on_result: Callable[[SearchTarget, SearchResult], None] | None = None,
) -> CampaignResult:
    # The campaign's global caps live in one Budget shared by every search.
    budget = Budget(attacker_config.max_iterations, attacker_config.max_cost_usd)
    # The semaphore caps how many searches run at the same instant.
    limiter = asyncio.Semaphore(concurrency)

    # Run one search in a worker thread, holding a semaphore slot while it runs.
    async def run_one(target: SearchTarget) -> SearchResult:
        async with limiter:
            result = await asyncio.to_thread(
                search,
                target.seed_id, target.seed_message, target.objective,
                target_client, target_config, attacker_client, attacker_config,
                judge_client, judge_config, policy, branching, keep, max_depth,
                None,       # on_node: skip per-node streaming; persist per-search instead
                budget,     # the shared campaign budget
            )
        if on_result is not None:
            on_result(target, result)  # back on the main thread — safe for SQLite
        return result

    results = await asyncio.gather(*(run_one(t) for t in targets))
    return CampaignResult(list(results), budget.iterations_used, budget.spend_usd)
