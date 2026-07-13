from __future__ import annotations

import json
from pathlib import Path

from crypto_agility.models import CBOM, BenchmarkReport
from crypto_agility.report import render_benchmark_markdown, render_cbom_markdown


def test_checked_evidence_renders_claim_boundaries(repository_root: Path) -> None:
    cbom = CBOM.model_validate_json(
        (repository_root / "reports" / "evidence" / "inventory" / "cbom.json").read_text(
            encoding="utf-8"
        )
    )
    cbom_markdown = render_cbom_markdown(cbom)
    assert "True hybrid TLS requires an observed TLS key_share" in cbom_markdown
    assert "Experimental application encapsulation" in cbom_markdown
    assert "fixture-user" not in cbom_markdown

    benchmark_payload = json.loads(
        (repository_root / "reports" / "evidence" / "benchmark-local.json").read_text(
            encoding="utf-8"
        )
    )
    report = BenchmarkReport.model_validate(benchmark_payload)
    benchmark_markdown = render_benchmark_markdown(report)
    assert "X25519MLKEM768" in benchmark_markdown
    assert "not evidence of browser" in benchmark_markdown
    assert "ML-DSA-65 signing" in benchmark_markdown
