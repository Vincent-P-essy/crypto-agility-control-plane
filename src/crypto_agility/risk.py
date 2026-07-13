"""Transparent risk scoring, including an explicit HNDL planning heuristic."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from crypto_agility.models import CryptoFinding, RiskAssessment, Severity
from crypto_agility.registry import AlgorithmRegistry


@dataclass(frozen=True)
class RiskPolicy:
    version: str
    transition_target_year: int
    hndl_threshold_years: int
    minimum_rsa_bits: int
    exposure_weights: dict[str, int]
    severity_thresholds: dict[str, int]

    @classmethod
    def load(cls, path: Path) -> RiskPolicy:
        raw: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8"))
        return cls(
            version=str(raw["policy_version"]),
            transition_target_year=int(raw["transition_target_year"]),
            hndl_threshold_years=int(raw["hndl_threshold_years"]),
            minimum_rsa_bits=int(raw["minimum_rsa_bits"]),
            exposure_weights={str(k): int(v) for k, v in raw["exposure_weights"].items()},
            severity_thresholds={str(k): int(v) for k, v in raw["severity_thresholds"].items()},
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "policy_version": self.version,
            "transition_target_year": self.transition_target_year,
            "hndl_threshold_years": self.hndl_threshold_years,
            "minimum_rsa_bits": self.minimum_rsa_bits,
            "exposure_weights": self.exposure_weights,
            "severity_thresholds": self.severity_thresholds,
            "hndl_definition": (
                "Planning flag: quantum-vulnerable data remains confidential beyond the configured "
                "transition horizon. It is not a prediction of a cryptographically relevant quantum computer."
            ),
        }


def _severity(score: int, thresholds: dict[str, int]) -> Severity:
    if score >= thresholds["critical"]:
        return "critical"
    if score >= thresholds["high"]:
        return "high"
    if score >= thresholds["medium"]:
        return "medium"
    return "low"


def assess_finding(
    finding: CryptoFinding,
    registry: AlgorithmRegistry,
    policy: RiskPolicy,
    *,
    current_year: int | None = None,
) -> RiskAssessment:
    """Score a finding using inspectable additive factors, capped at 100."""
    year = current_year or datetime.now(UTC).year
    entry = registry.lookup(finding.algorithm)
    score = int(entry["base_risk"])
    reasons = [f"registry base risk: {score} ({entry['status']})"]

    exposure = policy.exposure_weights[finding.exposure]
    score += exposure
    if exposure:
        reasons.append(f"{finding.exposure} exposure: +{exposure}")

    minimum_bits = int(entry.get("minimum_bits", 0))
    if finding.algorithm == "RSA":
        minimum_bits = max(minimum_bits, policy.minimum_rsa_bits)
    if minimum_bits and finding.key_bits is not None and finding.key_bits < minimum_bits:
        score += 30
        reasons.append(f"key size {finding.key_bits} is below policy minimum {minimum_bits}: +30")

    end_year = year + finding.confidentiality_years
    quantum = str(entry.get("quantum", "unknown"))
    hndl = quantum == "vulnerable" and (
        finding.confidentiality_years >= policy.hndl_threshold_years
        or end_year >= policy.transition_target_year
    )
    if hndl:
        horizon_weight = min(20, 12 + max(0, end_year - policy.transition_target_year))
        score += horizon_weight
        reasons.append(
            f"HNDL planning horizon ends in {end_year}, at/after transition target "
            f"{policy.transition_target_year}: +{horizon_weight}"
        )

    if finding.metadata.get("private_key_present") is True:
        score += 8
        reasons.append("private-key material is present in the scanned boundary: +8")

    score = max(0, min(100, score))
    return RiskAssessment(
        finding_id=finding.finding_id,
        score=score,
        severity=_severity(score, policy.severity_thresholds),
        hndl_relevant=hndl,
        confidentiality_end_year=end_year,
        reasons=reasons,
        policy_version=policy.version,
    )
