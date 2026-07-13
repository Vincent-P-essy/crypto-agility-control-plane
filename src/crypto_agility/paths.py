"""Configuration path resolution for source checkouts and installed wheels."""

from __future__ import annotations

import os
from importlib.resources import as_file, files
from pathlib import Path


def _resource_or_checkout(environment: str, checkout_relative: str, resource_name: str) -> Path:
    if configured := os.environ.get(environment):
        return Path(configured).resolve(strict=True)
    checkout = Path(__file__).resolve().parents[2] / checkout_relative
    if checkout.is_file():
        return checkout
    resource = files("crypto_agility").joinpath("resources", resource_name)
    # Wheel resources are normal files for this non-zipped installation. The context
    # fallback keeps the error readable on unusual importers.
    with as_file(resource) as path:
        if not path.is_file():
            raise FileNotFoundError(f"required resource {resource_name} is missing")
        return Path(path)


def algorithm_registry_path() -> Path:
    return _resource_or_checkout(
        "CAP_ALGORITHM_REGISTRY", "data/algorithm-registry.json", "algorithm-registry.json"
    )


def risk_policy_path() -> Path:
    return _resource_or_checkout("CAP_RISK_POLICY", "config/risk-policy.yaml", "risk-policy.yaml")


def cbom_schema_path() -> Path:
    return _resource_or_checkout(
        "CAP_CBOM_SCHEMA", "schemas/cbom-1.0.0.schema.json", "cbom-1.0.0.schema.json"
    )
