"""Versioned domain models used by scanners, reports, API, and benchmarks."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Exposure = Literal["local", "internal", "partner", "internet"]
Severity = Literal["low", "medium", "high", "critical"]


class Evidence(BaseModel):
    """A location and digest, never a copied secret or raw token."""

    model_config = ConfigDict(extra="forbid")

    source: str
    locator: str
    detector: str
    excerpt_hash: str
    confidence: float = Field(ge=0, le=1)


class CryptoFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    asset_id: str
    asset_kind: Literal[
        "certificate",
        "key",
        "jwt",
        "library",
        "tls-endpoint",
        "ssh-endpoint",
        "configuration",
        "protocol",
    ]
    algorithm: str
    use: str
    key_bits: int | None = Field(default=None, ge=0)
    protocol_version: str | None = None
    library_version: str | None = None
    exposure: Exposure = "internal"
    confidentiality_years: int = Field(default=5, ge=0, le=100)
    metadata: dict[str, Any] = Field(default_factory=dict)
    evidence: list[Evidence] = Field(min_length=1)


class RiskAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    score: int = Field(ge=0, le=100)
    severity: Severity
    hndl_relevant: bool
    confidentiality_end_year: int
    reasons: list[str]
    policy_version: str


class MigrationAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_id: str
    finding_ids: list[str]
    phase: Literal["now", "classic-hardening", "hybrid-transition", "pqc-target"]
    priority: int = Field(ge=1, le=100)
    title: str
    transition_kind: Literal[
        "standard-tls",
        "true-hybrid-tls",
        "application-encapsulation",
        "signature-transition",
        "protocol-hardening",
        "inventory-governance",
    ]
    target: str
    prerequisites: list[str]
    acceptance_tests: list[str]
    rollback: str
    compatibility_note: str


class CBOM(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0.0"] = "1.0.0"
    document_id: str
    generated_at: datetime
    source: dict[str, Any]
    policy: dict[str, Any]
    findings: list[CryptoFinding]
    assessments: list[RiskAssessment]
    migration_plan: list[MigrationAction]
    summary: dict[str, Any]


class MetricDistribution(BaseModel):
    model_config = ConfigDict(extra="forbid")

    unit: str
    samples: int = Field(ge=1)
    minimum: float
    p50: float
    p95: float
    maximum: float
    mean: float


class TLSBenchmark(BaseModel):
    model_config = ConfigDict(extra="forbid")

    profile: Literal["standard-tls-1.3", "true-hybrid-tls-1.3"]
    configured_policy: str
    negotiated_group: str
    negotiated_group_id: str
    server_key_share_bytes: int
    cipher: str
    client_to_server_handshake_bytes: int
    server_to_client_handshake_bytes: int
    wall_latency: MetricDistribution
    cpu_time: MetricDistribution
    throughput_handshakes_per_second: float


class OperationBenchmark(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operation: str
    wall_latency: MetricDistribution
    cpu_time: MetricDistribution
    throughput_operations_per_second: float


class PQCBenchmark(BaseModel):
    model_config = ConfigDict(extra="forbid")

    profile: Literal["experimental-application-encapsulation"]
    library: str
    library_version: str
    kem: str
    signature: str
    sizes_bytes: dict[str, int]
    operations: list[OperationBenchmark]
    rss_baseline_bytes: int
    rss_high_water_bytes: int
    validation: dict[str, bool]


class CompatibilityResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    client_policy: str
    server_policy: str
    success: bool
    negotiated_group: str | None
    note: str


class BenchmarkReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0.0"] = "1.0.0"
    report_id: str
    generated_at: datetime
    environment: dict[str, Any]
    scope_boundaries: dict[str, str]
    tls: list[TLSBenchmark]
    application_pqc: PQCBenchmark
    compatibility_matrix: list[CompatibilityResult]
