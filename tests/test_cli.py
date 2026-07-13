from __future__ import annotations

import json
from pathlib import Path

import pytest

from crypto_agility.cli import main


def _run_success(arguments: list[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(arguments)
    assert exit_info.value.code == 0


def test_cli_scan_validate_and_certificate_workflow(
    fixture_root: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "scan-output"
    _run_success(
        [
            "scan",
            str(fixture_root),
            "--source-label",
            "cli-fixture",
            "--confidentiality-years",
            "12",
            "--out",
            str(output),
        ]
    )
    summary = json.loads(capsys.readouterr().out)
    assert summary["summary"]["finding_count"] == 22
    assert (output / "cbom.json").is_file()
    assert (output / "report.md").is_file()

    _run_success(["validate", "cbom", str(output / "cbom.json")])
    validation = json.loads(capsys.readouterr().out)
    assert validation["valid"] is True

    certificate_directory = tmp_path / "certificates"
    _run_success(["generate-lab-cert", "--out", str(certificate_directory)])
    certificate_result = json.loads(capsys.readouterr().out)
    assert Path(certificate_result["server_certificate"]).is_file()


def test_cli_benchmark_fails_explicitly_without_native_library(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("OQS_INSTALL_PATH", raising=False)
    with pytest.raises(SystemExit) as exit_info:
        main(["benchmark", "--iterations", "3"])
    assert exit_info.value.code == 2
    assert "OQS_INSTALL_PATH is required" in capsys.readouterr().err


def test_cli_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.strip() == "0.1.0"
