from __future__ import annotations

from crypto_agility.migration import build_migration_plan
from crypto_agility.models import CryptoFinding, Evidence
from crypto_agility.registry import AlgorithmRegistry
from crypto_agility.risk import RiskPolicy, assess_finding


def _finding(identifier: str, algorithm: str, use: str) -> CryptoFinding:
    return CryptoFinding(
        finding_id=identifier,
        asset_id="asset-migration",
        asset_kind="configuration",
        algorithm=algorithm,
        use=use,
        confidentiality_years=10,
        evidence=[
            Evidence(
                source="fixture",
                locator="line:1",
                detector="test",
                excerpt_hash="sha256:" + "1" * 64,
                confidence=1,
            )
        ],
    )


def test_plan_keeps_tls_and_application_hybrid_profiles_distinct(
    registry: AlgorithmRegistry, policy: RiskPolicy
) -> None:
    findings = [
        _finding("finding-tls", "X25519", "tls key agreement"),
        _finding("finding-app", "ECDH", "application key agreement"),
        _finding("finding-sign", "RSA", "document signature"),
    ]
    assessments = [assess_finding(item, registry, policy, current_year=2026) for item in findings]
    plan = build_migration_plan(findings, assessments, registry)
    by_kind = {action.transition_kind: action for action in plan}
    assert by_kind["true-hybrid-tls"].target.startswith("TLS 1.3 X25519MLKEM768")
    assert "ServerHello key_share" in by_kind["true-hybrid-tls"].acceptance_tests[0]
    assert "not TLS negotiation" in by_kind["application-encapsulation"].compatibility_note
    assert "not an ML-DSA TLS certificate" in by_kind["signature-transition"].compatibility_note


def test_deprecated_protocol_is_removed_before_pqc(
    registry: AlgorithmRegistry, policy: RiskPolicy
) -> None:
    item = _finding("finding-tls10", "TLS-1.0", "transport protocol")
    assessment = assess_finding(item, registry, policy, current_year=2026)
    action = build_migration_plan([item], [assessment], registry)[0]
    assert action.phase == "now"
    assert action.transition_kind == "protocol-hardening"
    assert "PQC does not compensate" in action.compatibility_note
