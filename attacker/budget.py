"""Cost and iteration caps for a search run.

CLAUDE.md requires every attack run to respect a hard iteration cap AND a cost
cap; the search refuses to start without both. Dollar cost is ESTIMATED from
token counts using the rough per-model rates below — it is a runaway-spend
safety rail, not billing-grade accounting. Update the rates if they drift.
"""

import threading
from dataclasses import dataclass, field

# Rough USD per 1,000,000 tokens (input, output). ESTIMATES — adjust as needed.
# Unknown models fall back to a deliberately high rate so the cap trips early
# rather than late.
PRICE_PER_MTOK: dict[str, tuple[float, float]] = {
    "gpt-4.1-mini": (0.40, 1.60),
    "gpt-4.1": (2.00, 8.00),
    "gpt-5.4": (2.50, 10.00),
}
_FALLBACK_RATE = (5.00, 20.00)


# Estimate the dollar cost of one call's token usage.
def estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    in_rate, out_rate = PRICE_PER_MTOK.get(model, _FALLBACK_RATE)
    return (input_tokens * in_rate + output_tokens * out_rate) / 1_000_000


# Tracks how much of each cap a run has consumed. iterations counts target
# attempts (the expensive, rate-limited unit); spend accumulates every call.
@dataclass
class Budget:
    max_iterations: int
    max_cost_usd: float
    iterations_used: int = 0
    spend_usd: float = 0.0
    # Guards the counters so concurrent searches can share one Budget. Excluded
    # from repr/compare — it is machinery, not data.
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.max_iterations < 1 or self.max_cost_usd <= 0:
            raise ValueError("a run requires both an iteration cap (>=1) and a positive cost cap")

    # Record one call's tokens against the cost cap.
    def add_spend(self, model: str, input_tokens: int, output_tokens: int) -> None:
        with self._lock:
            self.spend_usd += estimate_cost(model, input_tokens, output_tokens)

    # Record one target attempt against the iteration cap.
    def add_iteration(self) -> None:
        with self._lock:
            self.iterations_used += 1

    # True while there is room for at least one more attempt.
    def has_room(self) -> bool:
        with self._lock:
            return self.iterations_used < self.max_iterations and self.spend_usd < self.max_cost_usd

    # Why the run stopped, for the report and logs.
    def exhausted_reason(self) -> str | None:
        if self.iterations_used >= self.max_iterations:
            return "iteration cap reached"
        if self.spend_usd >= self.max_cost_usd:
            return "cost cap reached"
        return None
