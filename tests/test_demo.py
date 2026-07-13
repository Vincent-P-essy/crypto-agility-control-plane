from __future__ import annotations

import multiprocessing
import os
import socket
import time
from pathlib import Path

import pytest
from cryptography import x509

from crypto_agility.demo import (
    DemoApplication,
    generate_lab_certificate,
    run_demo_client,
    serve_demo,
)
from crypto_agility.errors import BenchmarkUnavailable, ProtocolError


def _serve_hybrid_process(
    port: int, certificate: str, private_key: str, oqs_install_path: str
) -> None:
    import asyncio

    asyncio.run(
        serve_demo(
            mode="hybrid",
            host="127.0.0.1",
            port=port,
            certificate=Path(certificate),
            private_key=Path(private_key),
            oqs_install_path=Path(oqs_install_path),
        )
    )


def test_lab_certificate_is_short_lived_and_private_keys_are_restricted(tmp_path: Path) -> None:
    paths = generate_lab_certificate(tmp_path / "certs")
    certificate = x509.load_pem_x509_certificate(paths["server_certificate"].read_bytes())
    assert (certificate.not_valid_after_utc - certificate.not_valid_before_utc).days <= 3
    assert paths["ca_private_key"].stat().st_mode & 0o777 == 0o600
    assert paths["server_private_key"].stat().st_mode & 0o777 == 0o600


def test_classic_application_exposes_no_arbitrary_operation() -> None:
    application = DemoApplication("classic")
    capabilities = application.handle(
        {"protocol": "crypto-agility-demo/1", "operation": "capabilities"}
    )
    assert capabilities["transport_profile"] == "standard TLS 1.3 / X25519"
    assert "kem_public_key" not in capabilities


@pytest.mark.integration
def test_hybrid_service_negotiates_real_group_and_validates_envelope(tmp_path: Path) -> None:
    oqs_install_path = os.environ.get("OQS_INSTALL_PATH")
    if not oqs_install_path:
        pytest.skip("OQS_INSTALL_PATH is not configured; no integration result is fabricated")
    certificate_paths = generate_lab_certificate(tmp_path / "certs")
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    context = multiprocessing.get_context("spawn")
    process = context.Process(
        target=_serve_hybrid_process,
        args=(
            port,
            str(certificate_paths["server_certificate"]),
            str(certificate_paths["server_private_key"]),
            oqs_install_path,
        ),
    )
    process.start()
    try:
        result = None
        last_error: Exception | None = None
        for _ in range(30):
            try:
                result = run_demo_client(
                    mode="hybrid",
                    host="localhost",
                    port=port,
                    ca_certificate=certificate_paths["ca_certificate"],
                    oqs_install_path=Path(oqs_install_path),
                )
                break
            except (ConnectionError, OSError, BenchmarkUnavailable, ProtocolError) as exc:
                last_error = exc
                time.sleep(0.1)
        assert result is not None, f"hybrid service did not become ready: {last_error}"
        assert result["negotiated_group_id"] == "0x11ec"
        assert result["server_key_share_bytes"] == 1120
        assert result["kem_shared_secret_confirmed"] is True
        assert result["application_signature_verified"] is True
        assert result["validated"] is True
    finally:
        process.terminate()
        process.join(timeout=5)
