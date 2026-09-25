"""Tests for the search budget (both caps mandatory)."""

import pytest

from attacker.budget import Budget, estimate_cost


def test_both_caps_required() -> None:
    with pytest.raises(ValueError):
        Budget(max_iterations=0, max_cost_usd=1.0)
    with pytest.raises(ValueError):
        Budget(max_iterations=5, max_cost_usd=0.0)


def test_iteration_cap() -> None:
    b = Budget(max_iterations=2, max_cost_usd=10.0)
    assert b.has_room()
    b.add_iteration(); b.add_iteration()
    assert not b.has_room()
    assert b.exhausted_reason() == "iteration cap reached"


def test_cost_cap() -> None:
    b = Budget(max_iterations=100, max_cost_usd=0.001)
    b.add_spend("gpt-5.4", 1000, 200)  # ~$0.0045, over the cap
    assert not b.has_room()
    assert b.exhausted_reason() == "cost cap reached"


# Unknown models use the high fallback rate so the cap trips early, not late.
def test_unknown_model_uses_fallback_rate() -> None:
    assert estimate_cost("who-knows", 1_000_000, 0) == 5.00
