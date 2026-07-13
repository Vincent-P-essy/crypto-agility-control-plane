"""Measured TLS and application-PQC benchmark orchestration."""

from __future__ import annotations

import hashlib
import os
import platform
import resource
import ssl
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from crypto_agility.models import (
    BenchmarkReport,
    OperationBenchmark,
    PQCBenchmark,
)
from crypto_agility.native_oqs import KEM_NAME, MLDSA65, MLKEM768, SIGNATURE_NAME, OQSLibrary
from crypto_agility.tlsbench import benchmark_tls, distribution
from crypto_agility.util import canonical_json, sha256_hex, utc_now


def _rss_bytes() -> int:
    status = Path("/proc/self/status")
    if status.is_file():
        for line in status.read_text(encoding="utf-8").splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024
    maximum = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(maximum * (1024 if platform.system() == "Linux" else 1))


def _rss_high_water_bytes() -> int:
    maximum = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(maximum * (1024 if platform.system() == "Linux" else 1))


def _measure(operation: str, function: Callable[[], Any], iterations: int) -> OperationBenchmark:
    function()  # warm-up
    wall_values: list[float] = []
    cpu_values: list[float] = []
    wall_total_start = time.perf_counter_ns()
    for _ in range(iterations):
        wall_start = time.perf_counter_ns()
        cpu_start = time.process_time_ns()
        function()
        cpu_values.append((time.process_time_ns() - cpu_start) / 1_000_000)
        wall_values.append((time.perf_counter_ns() - wall_start) / 1_000_000)
    elapsed = (time.perf_counter_ns() - wall_total_start) / 1_000_000_000
    return OperationBenchmark(
        operation=operation,
        wall_latency=distribution(wall_values, "milliseconds"),
        cpu_time=distribution(cpu_values, "milliseconds"),
        throughput_operations_per_second=iterations / elapsed,
    )


def benchmark_application_pqc(iterations: int, library: OQSLibrary) -> PQCBenchmark:
    """Measure real liboqs calls; every cryptographic result is validated."""
    baseline_rss = _rss_bytes()
    message = hashlib.sha256(b"crypto-agility-controlled-benchmark-message").digest()

    with MLKEM768(library) as server_kem, MLKEM768(library) as client_kem:
        kem_public = server_kem.generate_keypair()
        kem_ciphertext, client_secret = client_kem.encapsulate(kem_public)
        decapsulated = server_kem.decapsulate(kem_ciphertext)

        def kem_keygen() -> None:
            with MLKEM768(library) as instance:
                instance.generate_keypair()

        def encapsulate() -> None:
            client_kem.encapsulate(kem_public)

        def decapsulate() -> None:
            server_kem.decapsulate(kem_ciphertext)

        kem_details = {
            "kem_public_key": server_kem.public_key_bytes,
            "kem_secret_key": server_kem.secret_key_bytes,
            "kem_ciphertext": server_kem.ciphertext_bytes,
            "kem_shared_secret": server_kem.shared_secret_bytes,
        }
        kem_operations = [
            _measure("ML-KEM-768 key generation", kem_keygen, iterations),
            _measure("ML-KEM-768 encapsulation", encapsulate, iterations),
            _measure("ML-KEM-768 decapsulation", decapsulate, iterations),
        ]

    with MLDSA65(library) as signer, MLDSA65(library) as verifier:
        signature_public = signer.generate_keypair()
        signature = signer.sign(message)
        verified = verifier.verify(message, signature, signature_public)
        tamper_rejected = not verifier.verify(message + b"!", signature, signature_public)

        def signature_keygen() -> None:
            with MLDSA65(library) as instance:
                instance.generate_keypair()

        def sign() -> None:
            signer.sign(message)

        def verify() -> None:
            if not verifier.verify(message, signature, signature_public):
                raise RuntimeError("ML-DSA verification unexpectedly failed")

        signature_details = {
            "signature_public_key": signer.public_key_bytes,
            "signature_secret_key": signer.secret_key_bytes,
            "signature": len(signature),
            "application_envelope_components": len(kem_ciphertext) + len(signature) + len(message),
        }
        signature_operations = [
            _measure("ML-DSA-65 key generation", signature_keygen, iterations),
            _measure("ML-DSA-65 signing", sign, iterations),
            _measure("ML-DSA-65 verification", verify, iterations),
        ]

    if client_secret != decapsulated or not verified or not tamper_rejected:
        raise RuntimeError("post-quantum benchmark validation failed; metrics are discarded")
    return PQCBenchmark(
        profile="experimental-application-encapsulation",
        library="liboqs",
        library_version=library.version,
        kem=KEM_NAME,
        signature=SIGNATURE_NAME,
        sizes_bytes={**kem_details, **signature_details},
        operations=kem_operations + signature_operations,
        rss_baseline_bytes=baseline_rss,
        rss_high_water_bytes=_rss_high_water_bytes(),
        validation={
            "kem_shared_secrets_equal": client_secret == decapsulated,
            "signature_verified": verified,
            "tampered_message_rejected": tamper_rejected,
        },
    )


def _cpu_model() -> str:
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.is_file():
        for line in cpuinfo.read_text(encoding="utf-8").splitlines():
            if line.lower().startswith("model name"):
                return line.split(":", 1)[1].strip()
    return platform.processor() or "unknown"


def run_benchmark(iterations: int, oqs_install_path: Path | None = None) -> BenchmarkReport:
    if not 3 <= iterations <= 10_000:
        raise ValueError("iterations must be between 3 and 10000")
    library = OQSLibrary(oqs_install_path)
    tls_results, compatibility = benchmark_tls(iterations)
    pqc_result = benchmark_application_pqc(iterations, library)
    environment: dict[str, Any] = {
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "openssl": ssl.OPENSSL_VERSION,
        "liboqs": library.version,
        "liboqs_path_sha256": sha256_hex(library.path.read_bytes()),
        "os": platform.platform(),
        "machine": platform.machine(),
        "cpu": _cpu_model(),
        "logical_cpus": os.cpu_count(),
        "iterations_per_operation": iterations,
        "process_id_recorded": False,
    }
    identity = {
        "environment": environment,
        "tls": [item.model_dump(mode="json") for item in tls_results],
        "application_pqc": pqc_result.model_dump(mode="json"),
        "compatibility": [item.model_dump(mode="json") for item in compatibility],
    }
    return BenchmarkReport(
        report_id=f"benchmark-sha256-{sha256_hex(canonical_json(identity))}",
        generated_at=utc_now(),
        environment=environment,
        scope_boundaries={
            "standard_tls": "TLS 1.3 with X25519 forced on both MemoryBIO peers.",
            "true_hybrid_tls": (
                "A real TLS 1.3 ServerHello negotiated X25519MLKEM768 (0x11ec). The OpenSSL "
                "3.5 default policy is used and each sample is wire-verified; it is not a browser claim."
            ),
            "application_pqc": (
                "Real ML-KEM-768 encapsulation and ML-DSA-65 signatures using liboqs 0.16.0. "
                "This experimental envelope is not TLS negotiation or an ML-DSA certificate."
            ),
            "memory": "RSS is process-level baseline/high-water telemetry, not per-operation allocation.",
        },
        tls=tls_results,
        application_pqc=pqc_result,
        compatibility_matrix=compatibility,
    )
