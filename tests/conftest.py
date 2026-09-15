"""Shared pytest fixtures. pytest loads this file automatically for every test in tests/."""

import pytest

from config import TargetConfig
from target.canaries import Canaries, generate_canaries
from target.environment import FakeEnvironment, build_default_environment


# A fresh set of canaries and a fresh environment for each test, so no test
# can leak planted content or state into another.
@pytest.fixture
def canaries() -> Canaries:
    return generate_canaries()


@pytest.fixture
def env(canaries: Canaries) -> FakeEnvironment:
    return build_default_environment(canaries)


# Config with a dummy key: tests use FakeClient, so the key is never sent anywhere.
@pytest.fixture
def config() -> TargetConfig:
    return TargetConfig(api_key="test-key", model="test-model", max_turns=4)
