"""Command-line interface for inventories, reports, benchmarks, API, and lab services."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from contextlib import nullcontext
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from pydantic import ValidationError

from crypto_agility import __version__
from crypto_agility.api import APISettings, create_app
from crypto_agility.benchmark import run_benchmark
from crypto_agility.cbom import build_cbom
from crypto_agility.demo import generate_lab_certificate, run_demo_client, serve_demo
from crypto_agility.errors import CryptoAgilityError
from crypto_agility.inventory import EndpointTarget, InventoryScanner, ScanOptions
from crypto_agility.models import CBOM, BenchmarkReport
from crypto_agility.paths import algorithm_registry_path, risk_policy_path
from crypto_agility.registry import AlgorithmRegistry
from crypto_agility.report import render_benchmark_markdown, render_cbom_markdown
from crypto_agility.risk import RiskPolicy
from crypto_agility.util import atomic_json_write


def _endpoint(value: str, verify: bool = True) -> EndpointTarget:
    try:
        host, raw_port = value.rsplit(":", 1)
        host = host.strip("[]")
        return EndpointTarget(host=host, port=int(raw_port), verify=verify)
    except (ValueError, TypeError) as exc:
        raise argparse.ArgumentTypeError("endpoint must be HOST:PORT") from exc


def _load_policy_and_registry(args: argparse.Namespace) -> tuple[AlgorithmRegistry, RiskPolicy]:
    registry_path = (
        Path(args.registry) if getattr(args, "registry", None) else algorithm_registry_path()
    )
    policy_path = Path(args.policy) if getattr(args, "policy", None) else risk_policy_path()
    return AlgorithmRegistry.load(registry_path), RiskPolicy.load(policy_path)


def _json_print(payload: dict[str, Any]) -> None:
    json.dump(payload, sys.stdout, indent=2, sort_keys=True, ensure_ascii=False)
    sys.stdout.write("\n")


def _scan(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve(strict=True)
    registry, policy = _load_policy_and_registry(args)
    tls_targets = tuple(
        _endpoint(value, verify=not args.insecure_tls_probe) for value in args.tls_target
    )
    ssh_targets = tuple(_endpoint(value) for value in args.ssh_target)
    findings = InventoryScanner(
        ScanOptions(
            root=root,
            confidentiality_years=args.confidentiality_years,
            exposure=args.exposure,
            max_file_bytes=args.max_file_bytes,
            tls_targets=tls_targets,
            ssh_targets=ssh_targets,
            timeout_seconds=args.timeout,
        )
    ).scan()
    cbom = build_cbom(
        findings,
        source={"type": "local-tree", "label": args.source_label or root.name},
        registry=registry,
        policy=policy,
    )
    payload = cbom.model_dump(mode="json")
    if args.out:
        output = Path(args.out)
        output.mkdir(parents=True, exist_ok=True)
        atomic_json_write(output / "cbom.json", payload)
        (output / "report.md").write_text(render_cbom_markdown(cbom), encoding="utf-8")
    _json_print(
        {
            "document_id": cbom.document_id,
            "summary": cbom.summary,
            "output_directory": str(Path(args.out).resolve()) if args.out else None,
        }
    )
    return 0


def _benchmark(args: argparse.Namespace) -> int:
    report = run_benchmark(
        args.iterations, Path(args.oqs_install_path) if args.oqs_install_path else None
    )
    payload = report.model_dump(mode="json")
    if args.out:
        output = Path(args.out)
        atomic_json_write(output, payload)
        output.with_suffix(".md").write_text(render_benchmark_markdown(report), encoding="utf-8")
    _json_print(
        {
            "report_id": report.report_id,
            "tls_profiles": [item.profile for item in report.tls],
            "liboqs": report.application_pqc.library_version,
            "validation": report.application_pqc.validation,
            "output": str(Path(args.out).resolve()) if args.out else None,
        }
    )
    return 0


def _validate(args: argparse.Namespace) -> int:
    payload = json.loads(Path(args.document).read_text(encoding="utf-8"))
    if args.kind == "cbom":
        cbom_document = CBOM.model_validate(payload)
        identifier = cbom_document.document_id
    else:
        benchmark_document = BenchmarkReport.model_validate(payload)
        identifier = benchmark_document.report_id
    _json_print({"valid": True, "kind": args.kind, "identifier": identifier})
    return 0


def _api(args: argparse.Namespace) -> int:
    import uvicorn

    roots = tuple(Path(item).resolve(strict=True) for item in args.allowed_root)
    settings = APISettings(
        state_directory=Path(args.state_dir).resolve(),
        allowed_roots=roots,
        oqs_install_path=Path(args.oqs_install_path).resolve() if args.oqs_install_path else None,
    )
    uvicorn.run(
        create_app(settings),
        host=args.host,
        port=args.port,
        log_level=args.log_level,
        proxy_headers=False,
        server_header=False,
    )
    return 0


def _generate_certificate(args: argparse.Namespace) -> int:
    paths = generate_lab_certificate(Path(args.out), overwrite=args.overwrite)
    _json_print({name: str(path.resolve()) for name, path in paths.items()})
    return 0


def _demo_server(args: argparse.Namespace) -> int:
    certificate_context = (
        TemporaryDirectory(prefix="crypto-agility-service-")
        if args.ephemeral_certificate
        else nullcontext(None)
    )
    with certificate_context as temporary:
        if temporary is not None:
            paths = generate_lab_certificate(Path(temporary))
            certificate = paths["server_certificate"]
            private_key = paths["server_private_key"]
        elif args.certificate and args.private_key:
            certificate = Path(args.certificate)
            private_key = Path(args.private_key)
        else:
            raise ValueError(
                "provide --certificate and --private-key, or select --ephemeral-certificate"
            )
        asyncio.run(
            serve_demo(
                mode=args.mode,
                host=args.host,
                port=args.port,
                certificate=certificate,
                private_key=private_key,
                oqs_install_path=Path(args.oqs_install_path) if args.oqs_install_path else None,
            )
        )
    return 0


def _demo_client(args: argparse.Namespace) -> int:
    result = run_demo_client(
        mode=args.mode,
        host=args.host,
        port=args.port,
        ca_certificate=Path(args.ca_certificate) if args.ca_certificate else None,
        insecure=args.insecure,
        oqs_install_path=Path(args.oqs_install_path) if args.oqs_install_path else None,
    )
    _json_print(result)
    return 0 if result.get("validated") is True else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="crypto-agility",
        description="Evidence-driven cryptographic inventory and migration control plane",
    )
    parser.add_argument("--version", action="version", version=__version__)
    subcommands = parser.add_subparsers(dest="command", required=True)

    scan = subcommands.add_parser("scan", help="create a versioned CBOM from a bounded tree")
    scan.add_argument("root")
    scan.add_argument("--out")
    scan.add_argument("--source-label")
    scan.add_argument("--confidentiality-years", type=int, default=5)
    scan.add_argument(
        "--exposure", choices=("local", "internal", "partner", "internet"), default="internal"
    )
    scan.add_argument("--max-file-bytes", type=int, default=2 * 1024 * 1024)
    scan.add_argument("--tls-target", action="append", default=[], metavar="HOST:PORT")
    scan.add_argument("--ssh-target", action="append", default=[], metavar="HOST:PORT")
    scan.add_argument(
        "--insecure-tls-probe",
        action="store_true",
        help="explicitly disable certificate validation for named lab TLS targets",
    )
    scan.add_argument("--timeout", type=float, default=3.0)
    scan.add_argument("--registry")
    scan.add_argument("--policy")
    scan.set_defaults(handler=_scan)

    benchmark = subcommands.add_parser(
        "benchmark", help="measure true TLS and native PQC operations"
    )
    benchmark.add_argument("--iterations", type=int, default=25)
    benchmark.add_argument("--oqs-install-path")
    benchmark.add_argument("--out")
    benchmark.set_defaults(handler=_benchmark)

    validate = subcommands.add_parser("validate", help="validate a structured artifact")
    validate.add_argument("kind", choices=("cbom", "benchmark"))
    validate.add_argument("document")
    validate.set_defaults(handler=_validate)

    api = subcommands.add_parser("api", help="serve the local control plane and dashboard")
    api.add_argument("--host", default="127.0.0.1")
    api.add_argument("--port", type=int, default=8080)
    api.add_argument("--state-dir", default=".state")
    api.add_argument("--allowed-root", action="append", required=True)
    api.add_argument("--oqs-install-path")
    api.add_argument(
        "--log-level", choices=("critical", "error", "warning", "info"), default="info"
    )
    api.set_defaults(handler=_api)

    certificate = subcommands.add_parser(
        "generate-lab-cert", help="generate short-lived lab-only TLS material"
    )
    certificate.add_argument("--out", required=True)
    certificate.add_argument("--overwrite", action="store_true")
    certificate.set_defaults(handler=_generate_certificate)

    server = subcommands.add_parser("demo-server", help="run the bounded classic or hybrid service")
    server.add_argument("--mode", choices=("classic", "hybrid"), required=True)
    server.add_argument("--host", default="127.0.0.1")
    server.add_argument("--port", type=int, required=True)
    server.add_argument("--certificate")
    server.add_argument("--private-key")
    server.add_argument(
        "--ephemeral-certificate",
        action="store_true",
        help="generate a short-lived untrusted certificate for container health/demo use",
    )
    server.add_argument("--oqs-install-path")
    server.set_defaults(handler=_demo_server)

    client = subcommands.add_parser(
        "demo-client", help="verify transport group and application envelope"
    )
    client.add_argument("--mode", choices=("classic", "hybrid"), required=True)
    client.add_argument("--host", default="localhost")
    client.add_argument("--port", type=int, required=True)
    client.add_argument("--ca-certificate")
    client.add_argument("--insecure", action="store_true")
    client.add_argument("--oqs-install-path")
    client.set_defaults(handler=_demo_client)
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        code = args.handler(args)
    except KeyboardInterrupt:
        raise SystemExit(130) from None
    except (CryptoAgilityError, ValidationError, ValueError, FileNotFoundError) as exc:
        parser.exit(2, f"error: {exc}\n")
    raise SystemExit(code)


if __name__ == "__main__":
    main()
