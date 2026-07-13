from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from jsonschema import Draft202012Validator

from crypto_agility.cbom import build_cbom
from crypto_agility.inventory import InventoryScanner, ScanOptions
from crypto_agility.paths import cbom_schema_path
from crypto_agility.registry import AlgorithmRegistry
from crypto_agility.risk import RiskPolicy


def test_cbom_is_schema_valid_deterministic_and_matches_golden(
    fixture_root: Path,
    repository_root: Path,
    registry: AlgorithmRegistry,
    policy: RiskPolicy,
) -> None:
    findings = InventoryScanner(ScanOptions(root=fixture_root, confidentiality_years=12)).scan()
    generated = datetime(2026, 7, 13, 12, 0, tzinfo=UTC)
    cbom = build_cbom(
        findings,
        source={"type": "local-tree", "label": "golden-fixture"},
        registry=registry,
        policy=policy,
        generated_at=generated,
        current_year=2026,
    )
    second = build_cbom(
        findings,
        source={"type": "local-tree", "label": "golden-fixture"},
        registry=registry,
        policy=policy,
        generated_at=datetime(2026, 7, 14, 12, 0, tzinfo=UTC),
        current_year=2026,
    )
    assert cbom.document_id == second.document_id
    schema = json.loads(cbom_schema_path().read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(cbom.model_dump(mode="json"))
    actual = {
        "document_id": cbom.document_id,
        "summary": cbom.summary,
        "algorithms": sorted({item.algorithm for item in cbom.findings}),
        "transition_kinds": sorted({item.transition_kind for item in cbom.migration_plan}),
    }
    expected = json.loads(
        (repository_root / "tests" / "golden" / "fixture-cbom-summary.json").read_text(
            encoding="utf-8"
        )
    )
    assert actual == expected
