from __future__ import annotations

import os
from pathlib import Path

import pytest

from crypto_agility.benchmark import benchmark_application_pqc
from crypto_agility.errors import BenchmarkUnavailable
from crypto_agility.native_oqs import MLDSA65, MLKEM768, OQSLibrary


def _library_or_skip() -> OQSLibrary:
    configured = os.environ.get("OQS_INSTALL_PATH")
    if not configured:
        pytest.skip("OQS_INSTALL_PATH is not configured; no native metric is fabricated")
    try:
        return OQSLibrary(Path(configured))
    except BenchmarkUnavailable as exc:
        pytest.skip(str(exc))


def test_native_library_requires_explicit_install_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OQS_INSTALL_PATH", raising=False)
    with pytest.raises(BenchmarkUnavailable, match="OQS_INSTALL_PATH"):
        OQSLibrary()


@pytest.mark.integration
def test_exact_native_primitives_and_sizes() -> None:
    library = _library_or_skip()
    with MLKEM768(library) as server, MLKEM768(library) as client:
        public_key = server.generate_keypair()
        ciphertext, client_secret = client.encapsulate(public_key)
        assert (len(public_key), len(ciphertext), len(client_secret)) == (1184, 1088, 32)
        assert server.decapsulate(ciphertext) == client_secret
    with MLDSA65(library) as signer, MLDSA65(library) as verifier:
        public_key = signer.generate_keypair()
        signature = signer.sign(b"fixture")
        assert (len(public_key), len(signature)) == (1952, 3309)
        assert verifier.verify(b"fixture", signature, public_key)
        assert not verifier.verify(b"tampered", signature, public_key)


@pytest.mark.integration
def test_native_benchmark_validates_before_returning_metrics() -> None:
    result = benchmark_application_pqc(3, _library_or_skip())
    assert all(result.validation.values())
    assert result.library_version == "0.16.0"
    assert result.operations[0].wall_latency.samples == 3
    assert result.sizes_bytes["application_envelope_components"] == 4429
