"""Classic-to-hybrid-to-PQC migration plan generation with compatibility gates."""

from __future__ import annotations

from collections import defaultdict

from crypto_agility.models import CryptoFinding, MigrationAction, RiskAssessment
from crypto_agility.registry import AlgorithmRegistry
from crypto_agility.util import stable_id


def _action(
    findings: list[CryptoFinding],
    phase: str,
    priority: int,
    title: str,
    kind: str,
    target: str,
    prerequisites: list[str],
    acceptance_tests: list[str],
    rollback: str,
    compatibility_note: str,
) -> MigrationAction:
    ids = sorted(item.finding_id for item in findings)
    action_id = stable_id("migration", {"ids": ids, "phase": phase, "target": target})
    return MigrationAction(
        action_id=action_id,
        finding_ids=ids,
        phase=phase,  # type: ignore[arg-type]
        priority=max(1, min(100, priority)),
        title=title,
        transition_kind=kind,  # type: ignore[arg-type]
        target=target,
        prerequisites=prerequisites,
        acceptance_tests=acceptance_tests,
        rollback=rollback,
        compatibility_note=compatibility_note,
    )


def build_migration_plan(
    findings: list[CryptoFinding],
    assessments: list[RiskAssessment],
    registry: AlgorithmRegistry,
) -> list[MigrationAction]:
    """Create deduplicated actions; no unsupported protocol claim is synthesized."""
    risk_by_id = {item.finding_id: item.score for item in assessments}
    grouped: dict[tuple[str, str], list[CryptoFinding]] = defaultdict(list)
    for finding in findings:
        grouped[(finding.algorithm, finding.use)].append(finding)

    actions: list[MigrationAction] = []
    for (algorithm, use), items in sorted(grouped.items()):
        entry = registry.lookup(algorithm)
        status = str(entry["status"])
        quantum = str(entry["quantum"])
        priority = max(risk_by_id[item.finding_id] for item in items)

        if status in {"broken", "deprecated"} or algorithm in {"TLS-1.0", "TLS-1.1"}:
            actions.append(
                _action(
                    items,
                    "now",
                    priority,
                    f"Remove {algorithm} before PQC migration",
                    "protocol-hardening",
                    "TLS 1.3 and currently approved classical algorithms",
                    ["Inventory peer compatibility", "Define an emergency rollback window"],
                    [
                        "Negative test rejects the deprecated algorithm",
                        "Business flow regression passes",
                    ],
                    "Restore the prior policy only for a time-bounded, owner-approved exception.",
                    "PQC does not compensate for a currently broken or deprecated primitive.",
                )
            )
            continue

        if algorithm == "TLS-1.2":
            actions.append(
                _action(
                    items,
                    "classic-hardening",
                    priority,
                    "Prefer TLS 1.3 while preserving a measured TLS 1.2 exception",
                    "standard-tls",
                    "TLS 1.3 with authenticated modern cipher suites",
                    ["Measure TLS 1.3 support by named client population"],
                    [
                        "Canary success rate is within SLO",
                        "TLS 1.2 fallback population is reported",
                    ],
                    "Retain a scoped TLS 1.2 listener until the incompatible clients are remediated.",
                    "This step is standard TLS hardening; it is not post-quantum protection.",
                )
            )

        if quantum != "vulnerable":
            continue

        use_lower = use.lower()
        if "key" in use_lower or algorithm in {"ECDH", "X25519", "DH"}:
            if "tls" in use_lower:
                actions.append(
                    _action(
                        items,
                        "hybrid-transition",
                        priority,
                        f"Canary true hybrid TLS for {algorithm} consumers",
                        "true-hybrid-tls",
                        "TLS 1.3 X25519MLKEM768 negotiated key agreement",
                        [
                            "OpenSSL 3.5+ on both measured peers",
                            "Per-client compatibility matrix",
                            "Classical fallback policy approved",
                        ],
                        [
                            "ServerHello key_share group is 0x11ec",
                            "p50/p95 latency and handshake bytes stay within budgets",
                            "Fallback is visible in telemetry",
                        ],
                        "Return the affected canary to X25519 while preserving collected evidence.",
                        (
                            "True hybrid TLS negotiation is distinct from placing ML-KEM in an "
                            "application message. No browser compatibility is inferred."
                        ),
                    )
                )
            else:
                actions.append(
                    _action(
                        items,
                        "hybrid-transition",
                        priority,
                        f"Prototype a versioned hybrid envelope for {algorithm}",
                        "application-encapsulation",
                        "Explicit classical + ML-KEM-768 application protocol",
                        [
                            "Protocol threat model",
                            "Downgrade binding",
                            "Independent key separation",
                        ],
                        [
                            "Classical and PQC components are both transcript-bound",
                            "Downgrade test fails closed",
                        ],
                        "Negotiate the previous version using an authenticated, audited capability flag.",
                        (
                            "This is experimental application encapsulation, not TLS negotiation or "
                            "a claim of standards-track interoperability."
                        ),
                    )
                )

        if "signature" in use_lower or algorithm in {
            "RSA",
            "ECDSA",
            "ED25519",
            "RS256",
            "ES256",
            "EDDSA",
        }:
            actions.append(
                _action(
                    items,
                    "pqc-target",
                    priority,
                    f"Introduce ML-DSA-65 verification beside {algorithm}",
                    "signature-transition",
                    "Versioned dual-verification profile, then ML-DSA-65 after ecosystem approval",
                    [
                        "Format and protocol support ML-DSA identifiers",
                        "Trust-anchor and revocation design",
                        "Verifier rollout precedes signer rollout",
                    ],
                    [
                        "Both signatures bind identical canonical bytes",
                        "Missing required signature fails closed",
                    ],
                    "Continue classical signing while retaining dual-verifier telemetry.",
                    (
                        "The demo's ML-DSA application signature is not an ML-DSA TLS certificate "
                        "and does not imply JOSE or browser support."
                    ),
                )
            )

    return sorted(actions, key=lambda item: (-item.priority, item.phase, item.action_id))
