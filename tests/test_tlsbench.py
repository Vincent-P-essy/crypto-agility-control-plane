from __future__ import annotations

import ssl

import pytest

from crypto_agility.errors import BenchmarkUnavailable
from crypto_agility.tlsbench import benchmark_tls, parse_server_hello_key_share


@pytest.mark.skipif(ssl.OPENSSL_VERSION_INFO < (3, 5, 0), reason="OpenSSL 3.5+ required")
def test_real_tls_benchmark_observes_classic_and_hybrid_groups() -> None:
    results, matrix = benchmark_tls(3)
    by_profile = {item.profile: item for item in results}
    classic = by_profile["standard-tls-1.3"]
    hybrid = by_profile["true-hybrid-tls-1.3"]
    assert classic.negotiated_group_id == "0x001d"
    assert classic.server_key_share_bytes == 32
    assert hybrid.negotiated_group_id == "0x11ec"
    assert hybrid.server_key_share_bytes == 1120
    assert hybrid.client_to_server_handshake_bytes > classic.client_to_server_handshake_bytes
    assert hybrid.wall_latency.samples == 3
    assert len(matrix) == 4
    assert all("browser" in item.note for item in matrix if item.success)


def test_server_hello_parser_rejects_non_handshake_data() -> None:
    with pytest.raises(BenchmarkUnavailable, match="ServerHello"):
        parse_server_hello_key_share(b"not a TLS record")
