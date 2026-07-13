"""CBOM assembly and report-safe deterministic summaries."""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any

from crypto_agility.migration import build_migration_plan
from crypto_agility.models import CBOM, CryptoFinding
from crypto_agility.registry import AlgorithmRegistry
from crypto_agility.risk import RiskPolicy, assess_finding
from crypto_agility.util import canonical_json, sha256_hex, utc_now


def build_cbom(
    findings: list[CryptoFinding],
    *,
    source: dict[str, Any],
    registry: AlgorithmRegistry,
    policy: RiskPolicy,
    generated_at: datetime | None = None,
    current_year: int | None = None,
) -> CBOM:
    ordered = sorted(findings, key=lambda item: item.finding_id)
    assessments = [
        assess_finding(item, registry, policy, current_year=current_year) for item in ordered
    ]
    plan = build_migration_plan(ordered, assessments, registry)
    severity_counts = Counter(item.severity for item in assessments)
    algorithm_counts = Counter(item.algorithm for item in ordered)
    identity_payload = {
        "schema_version": "1.0.0",
        "source": source,
        "policy": policy.as_dict(),
        "findings": [item.model_dump(mode="json") for item in ordered],
        "assessments": [item.model_dump(mode="json") for item in assessments],
        "migration_plan": [item.model_dump(mode="json") for item in plan],
    }
    document_id = f"urn:cbom:sha256:{sha256_hex(canonical_json(identity_payload))}"
    return CBOM(
        document_id=document_id,
        generated_at=generated_at or utc_now(),
        source=source,
        policy=policy.as_dict(),
        findings=ordered,
        assessments=assessments,
        migration_plan=plan,
        summary={
            "finding_count": len(ordered),
            "algorithm_counts": dict(sorted(algorithm_counts.items())),
            "severity_counts": {
                "critical": severity_counts["critical"],
                "high": severity_counts["high"],
                "medium": severity_counts["medium"],
                "low": severity_counts["low"],
            },
            "hndl_relevant_count": sum(item.hndl_relevant for item in assessments),
            "migration_action_count": len(plan),
            "registry_version": registry.version,
        },
    )
