from __future__ import annotations

from pathlib import Path

import pytest

from crypto_agility.paths import algorithm_registry_path, risk_policy_path
from crypto_agility.registry import AlgorithmRegistry
from crypto_agility.risk import RiskPolicy


@pytest.fixture(scope="session")
def repository_root() -> Path:
    return Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def fixture_root(repository_root: Path) -> Path:
    return repository_root / "fixtures" / "inventory"


@pytest.fixture(scope="session")
def registry() -> AlgorithmRegistry:
    return AlgorithmRegistry.load(algorithm_registry_path())


@pytest.fixture(scope="session")
def policy() -> RiskPolicy:
    return RiskPolicy.load(risk_policy_path())
