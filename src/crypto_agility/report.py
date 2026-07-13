"""Human-readable reports generated from structured evidence."""

from __future__ import annotations

from crypto_agility.models import CBOM, BenchmarkReport


def _cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def render_cbom_markdown(cbom: CBOM) -> str:
    risk_by_id = {item.finding_id: item for item in cbom.assessments}
    lines = [
        "# Crypto Bill of Materials",
        "",
        f"Document: `{cbom.document_id}`  ",
        f"Generated: `{cbom.generated_at.isoformat()}`  ",
        f"Schema: `{cbom.schema_version}`",
        "",
        "## Executive summary",
        "",
        f"- Findings: {cbom.summary['finding_count']}",
        f"- Critical/high: {cbom.summary['severity_counts']['critical']} / {cbom.summary['severity_counts']['high']}",
        f"- HNDL planning flags: {cbom.summary['hndl_relevant_count']}",
        f"- Migration actions: {cbom.summary['migration_action_count']}",
        "",
        "The HNDL flag is a configurable planning horizon, not a forecast of quantum-computer availability.",
        "Evidence stores locations and hashes only; JWT payloads, key bytes, and configuration values are not copied.",
        "",
        "## Findings",
        "",
        "| Algorithm | Use | Asset | Bits | Exposure | Risk | HNDL | Evidence |",
        "|---|---|---|---:|---|---:|---|---|",
    ]
    for finding in cbom.findings:
        risk = risk_by_id[finding.finding_id]
        evidence = ", ".join(f"{item.source}:{item.locator}" for item in finding.evidence)
        lines.append(
            "| "
            + " | ".join(
                _cell(value)
                for value in (
                    finding.algorithm,
                    finding.use,
                    finding.asset_kind,
                    finding.key_bits or "—",
                    finding.exposure,
                    f"{risk.score} ({risk.severity})",
                    "yes" if risk.hndl_relevant else "no",
                    evidence,
                )
            )
            + " |"
        )
    lines.extend(
        [
            "",
            "## Migration plan",
            "",
            "| Priority | Phase | Kind | Target | Compatibility gate |",
            "|---:|---|---|---|---|",
        ]
    )
    for action in cbom.migration_plan:
        lines.append(
            "| "
            + " | ".join(
                _cell(value)
                for value in (
                    action.priority,
                    action.phase,
                    action.transition_kind,
                    action.target,
                    action.compatibility_note,
                )
            )
            + " |"
        )
    lines.extend(
        [
            "",
            "## Interpretation boundaries",
            "",
            "- Standard TLS means the TLS 1.3/X25519 baseline.",
            "- True hybrid TLS requires an observed TLS key_share for `X25519MLKEM768`; naming ML-KEM in an application payload is not enough.",
            "- Experimental application encapsulation is versioned separately and is not presented as TLS, an ML-DSA certificate, JOSE support, or browser compatibility.",
            "",
        ]
    )
    return "\n".join(lines)


def render_benchmark_markdown(report: BenchmarkReport) -> str:
    lines = [
        "# Reproducible cryptographic benchmark",
        "",
        f"Report: `{report.report_id}`  ",
        f"Generated: `{report.generated_at.isoformat()}`  ",
        f"OpenSSL: `{report.environment['openssl']}`  ",
        f"liboqs: `{report.environment['liboqs']}`  ",
        f"CPU: `{report.environment['cpu']}`",
        "",
        "## TLS handshakes",
        "",
        "| Profile | Negotiated group | Key share | Wire C→S | Wire S→C | p50 | p95 | Throughput |",
        "|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for tls_result in report.tls:
        lines.append(
            f"| {_cell(tls_result.profile)} | {_cell(tls_result.negotiated_group)} "
            f"({tls_result.negotiated_group_id}) | {tls_result.server_key_share_bytes} B "
            f"| {tls_result.client_to_server_handshake_bytes} B "
            f"| {tls_result.server_to_client_handshake_bytes} B "
            f"| {tls_result.wall_latency.p50:.3f} ms "
            f"| {tls_result.wall_latency.p95:.3f} ms "
            f"| {tls_result.throughput_handshakes_per_second:.1f}/s |"
        )
    lines.extend(
        [
            "",
            "## Real application-layer PQC operations",
            "",
            "These measurements call liboqs directly. They describe an experimental application envelope, not TLS negotiation.",
            "",
            "| Operation | p50 wall | p95 wall | p50 CPU | Throughput |",
            "|---|---:|---:|---:|---:|",
        ]
    )
    for operation_result in report.application_pqc.operations:
        lines.append(
            f"| {_cell(operation_result.operation)} "
            f"| {operation_result.wall_latency.p50:.3f} ms "
            f"| {operation_result.wall_latency.p95:.3f} ms "
            f"| {operation_result.cpu_time.p50:.3f} ms "
            f"| {operation_result.throughput_operations_per_second:.1f}/s |"
        )
    lines.extend(
        [
            "",
            "## Client/server compatibility matrix",
            "",
            "| Client policy | Server policy | Success | Negotiated group | Scope |",
            "|---|---|---|---|---|",
        ]
    )
    for compatibility_result in report.compatibility_matrix:
        lines.append(
            f"| {_cell(compatibility_result.client_policy)} "
            f"| {_cell(compatibility_result.server_policy)} "
            f"| {'yes' if compatibility_result.success else 'no'} "
            f"| {_cell(compatibility_result.negotiated_group or '—')} "
            f"| {_cell(compatibility_result.note)} |"
        )
    lines.extend(
        [
            "",
            "## Boundaries",
            "",
            *[
                f"- **{key.replace('_', ' ')}:** {value}"
                for key, value in report.scope_boundaries.items()
            ],
            "",
        ]
    )
    return "\n".join(lines)
