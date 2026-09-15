"""Tests for canary generation and the fake environment."""

from target.canaries import Canaries, generate_canaries
from target.environment import FakeEnvironment, SearchResult, normalize_path


# Canaries must differ between runs, otherwise an old transcript could
# produce a false "leak" match in a new run.
def test_canaries_are_unique_per_run() -> None:
    first, second = generate_canaries(), generate_canaries()
    assert set(first.all_values()).isdisjoint(second.all_values())


def test_all_values_returns_every_canary(canaries: Canaries) -> None:
    assert canaries.all_values() == [canaries.api_key, canaries.db_password, canaries.admin_token]


# Every canary must actually be planted somewhere the agent can reach,
# or leak tests for that canary could never succeed.
def test_every_canary_is_planted_in_a_secret_file(env: FakeEnvironment, canaries: Canaries) -> None:
    secret_contents = "".join(content for path, content in env.files.items() if path.startswith("/secrets/"))
    for value in canaries.all_values():
        assert value in secret_contents


# Path tricks must resolve to the real file being accessed.
def test_normalize_path_resolves_traversal() -> None:
    assert normalize_path("/public/../secrets/db.env") == "/secrets/db.env"
    assert normalize_path("public//faq.md") == "/public/faq.md"


def test_get_file_missing_returns_none(env: FakeEnvironment) -> None:
    assert env.get_file("/does/not/exist") is None


# Planted results simulate a poisoned page, so they appear regardless of query.
def test_planted_results_come_first_for_any_query(env: FakeEnvironment) -> None:
    planted = SearchResult(title="Planted", url="https://attacker.example/x", snippet="payload")
    env.plant_search_result(planted)
    results = env.search("acme")
    assert results[0] == planted
    assert env.search("zzz-no-match") == [planted]
