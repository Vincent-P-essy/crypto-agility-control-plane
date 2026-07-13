from __future__ import annotations

from crypto_agility.models import CryptoFinding, Evidence
from crypto_agility.registry import AlgorithmRegistry
from crypto_agility.risk import RiskPolicy, assess_finding


def finding(
    algorithm: str,
    *,
    key_bits: int | None = None,
    years: int = 5,
    exposure: str = "internal",
    private: bool = False,
) -> CryptoFinding:
    return CryptoFinding(
        finding_id=f"finding-{algorithm.lower()}-{key_bits}-{years}-{exposure}",
        asset_id="asset-test",
        asset_kind="key",
        algorithm=algorithm,
        use="tls key agreement" if algorithm in {"X25519", "ML-KEM-768"} else "signature",
        key_bits=key_bits,
        exposure=exposure,  # type: ignore[arg-type]
        confidentiality_years=years,
        metadata={"private_key_present": private},
        evidence=[
            Evidence(
                source="fixture",
                locator="line:1",
                detector="test",
                excerpt_hash="sha256:" + "0" * 64,
                confidence=1,
            )
        ],
    )


def test_hndl_flag_is_explainable_and_increases_priority(
    registry: AlgorithmRegistry, policy: RiskPolicy
) -> None:
    short = assess_finding(finding("X25519", years=1), registry, policy, current_year=2026)
    retained = assess_finding(finding("X25519", years=12), registry, policy, current_year=2026)
    assert short.hndl_relevant is False
    assert retained.hndl_relevant is True
    assert retained.score > short.score
    assert any("HNDL planning horizon" in reason for reason in retained.reasons)


def test_weak_external_rsa_is_critical(registry: AlgorithmRegistry, policy: RiskPolicy) -> None:
    assessment = assess_finding(
        finding("RSA", key_bits=1024, years=12, exposure="internet", private=True),
        registry,
        policy,
        current_year=2026,
    )
    assert assessment.score == 100
    assert assessment.severity == "critical"
    assert any("below policy minimum" in reason for reason in assessment.reasons)


def test_pqc_standard_does_not_get_hndl_penalty(
    registry: AlgorithmRegistry, policy: RiskPolicy
) -> None:
    assessment = assess_finding(
        finding("ML-KEM-768", years=30), registry, policy, current_year=2026
    )
    assert assessment.hndl_relevant is False
    assert assessment.score < 35
