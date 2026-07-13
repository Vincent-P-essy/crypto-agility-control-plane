"""TLS 1.3 MemoryBIO benchmark with wire-level ServerHello evidence."""

from __future__ import annotations

import math
import ssl
import struct
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Literal

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from crypto_agility.errors import BenchmarkUnavailable
from crypto_agility.models import CompatibilityResult, MetricDistribution, TLSBenchmark

X25519_GROUP_ID = 0x001D
X25519_MLKEM768_GROUP_ID = 0x11EC
GROUP_NAMES = {
    X25519_GROUP_ID: "X25519",
    X25519_MLKEM768_GROUP_ID: "X25519MLKEM768",
}
Policy = Literal["classic-only", "hybrid-preferred"]


@dataclass(frozen=True)
class HandshakeObservation:
    wall_ms: float
    cpu_ms: float
    client_bytes: int
    server_bytes: int
    group_id: int
    key_share_bytes: int
    cipher: str


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    index = max(0, math.ceil(percentile * len(ordered)) - 1)
    return ordered[index]


def distribution(values: list[float], unit: str) -> MetricDistribution:
    if not values:
        raise ValueError("at least one metric sample is required")
    return MetricDistribution(
        unit=unit,
        samples=len(values),
        minimum=min(values),
        p50=_percentile(values, 0.50),
        p95=_percentile(values, 0.95),
        maximum=max(values),
        mean=sum(values) / len(values),
    )


def _ephemeral_certificate(directory: Path) -> tuple[Path, Path]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "crypto-agility-lab")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(private_key, hashes.SHA256())
    )
    certificate_path = directory / "certificate.pem"
    private_key_path = directory / "private-key.pem"
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    private_key_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    private_key_path.chmod(0o600)
    return certificate_path, private_key_path


def _contexts(
    certificate: Path, private_key: Path, client: Policy, server: Policy
) -> tuple[ssl.SSLContext, ssl.SSLContext]:
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.minimum_version = ssl.TLSVersion.TLSv1_3
    server_context.maximum_version = ssl.TLSVersion.TLSv1_3
    server_context.load_cert_chain(certificate, private_key)
    server_context.num_tickets = 0
    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.minimum_version = ssl.TLSVersion.TLSv1_3
    client_context.maximum_version = ssl.TLSVersion.TLSv1_3
    client_context.check_hostname = False
    client_context.verify_mode = ssl.CERT_NONE
    if client == "classic-only":
        client_context.set_ecdh_curve("X25519")
    if server == "classic-only":
        server_context.set_ecdh_curve("X25519")
    return client_context, server_context


def parse_server_hello_key_share(wire: bytes) -> tuple[int, int]:
    """Extract key_share(group, key_exchange length) from the cleartext ServerHello."""
    record_position = 0
    while record_position + 5 <= len(wire):
        record_type, _legacy_version, record_length = struct.unpack(
            "!BHH", wire[record_position : record_position + 5]
        )
        record = wire[record_position + 5 : record_position + 5 + record_length]
        record_position += 5 + record_length
        if record_type != 22:
            continue
        handshake_position = 0
        while handshake_position + 4 <= len(record):
            handshake_type = record[handshake_position]
            handshake_length = int.from_bytes(
                record[handshake_position + 1 : handshake_position + 4], "big"
            )
            message = record[handshake_position + 4 : handshake_position + 4 + handshake_length]
            handshake_position += 4 + handshake_length
            if handshake_type != 2 or len(message) < 40:
                continue
            position = 2 + 32
            session_id_length = message[position]
            position += 1 + session_id_length + 2 + 1
            extensions_length = int.from_bytes(message[position : position + 2], "big")
            position += 2
            extensions_end = position + extensions_length
            while position + 4 <= extensions_end:
                extension_type, extension_length = struct.unpack(
                    "!HH", message[position : position + 4]
                )
                extension = message[position + 4 : position + 4 + extension_length]
                position += 4 + extension_length
                if extension_type == 51 and len(extension) >= 4:
                    return (
                        int.from_bytes(extension[:2], "big"),
                        int.from_bytes(extension[2:4], "big"),
                    )
    raise BenchmarkUnavailable("TLS ServerHello did not contain a parseable key_share extension")


def observe_handshake(
    client_context: ssl.SSLContext, server_context: ssl.SSLContext
) -> HandshakeObservation:
    client_in, client_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    server_in, server_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    client = client_context.wrap_bio(
        client_in, client_out, server_side=False, server_hostname="localhost"
    )
    server = server_context.wrap_bio(server_in, server_out, server_side=True)
    client_wire = bytearray()
    server_wire = bytearray()
    client_done = server_done = False
    wall_start = time.perf_counter_ns()
    cpu_start = time.process_time_ns()
    for _ in range(100):
        if not client_done:
            try:
                client.do_handshake()
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                pass
            else:
                client_done = True
        outbound = client_out.read()
        if outbound:
            client_wire.extend(outbound)
            server_in.write(outbound)

        if not server_done:
            try:
                server.do_handshake()
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                pass
            else:
                server_done = True
        outbound = server_out.read()
        if outbound:
            server_wire.extend(outbound)
            client_in.write(outbound)
        if client_done and server_done:
            break
    else:
        raise BenchmarkUnavailable("TLS MemoryBIO handshake did not converge")
    cpu_ms = (time.process_time_ns() - cpu_start) / 1_000_000
    wall_ms = (time.perf_counter_ns() - wall_start) / 1_000_000
    group_id, key_share_bytes = parse_server_hello_key_share(bytes(server_wire))
    cipher = client.cipher()
    return HandshakeObservation(
        wall_ms=wall_ms,
        cpu_ms=cpu_ms,
        client_bytes=len(client_wire),
        server_bytes=len(server_wire),
        group_id=group_id,
        key_share_bytes=key_share_bytes,
        cipher=cipher[0] if cipher else "unknown",
    )


def _require_openssl_35() -> None:
    if ssl.OPENSSL_VERSION_INFO < (3, 5, 0):
        raise BenchmarkUnavailable(
            f"true hybrid TLS benchmark requires OpenSSL 3.5+; found {ssl.OPENSSL_VERSION}"
        )


def benchmark_tls(iterations: int) -> tuple[list[TLSBenchmark], list[CompatibilityResult]]:
    if not 3 <= iterations <= 10_000:
        raise ValueError("iterations must be between 3 and 10000")
    _require_openssl_35()
    with TemporaryDirectory(prefix="crypto-agility-tls-") as temporary:
        certificate, private_key = _ephemeral_certificate(Path(temporary))
        results: list[TLSBenchmark] = []
        profile_pairs: tuple[tuple[Policy, Policy, int, str], ...] = (
            ("classic-only", "classic-only", X25519_GROUP_ID, "standard-tls-1.3"),
            (
                "hybrid-preferred",
                "hybrid-preferred",
                X25519_MLKEM768_GROUP_ID,
                "true-hybrid-tls-1.3",
            ),
        )
        for client_policy, server_policy, expected_group, profile in profile_pairs:
            client_context, server_context = _contexts(
                certificate, private_key, client_policy, server_policy
            )
            observe_handshake(client_context, server_context)  # warm-up
            observations = [
                observe_handshake(client_context, server_context) for _ in range(iterations)
            ]
            if any(item.group_id != expected_group for item in observations):
                observed = sorted({hex(item.group_id) for item in observations})
                raise BenchmarkUnavailable(
                    f"{profile} did not negotiate its required group; observed {observed}; "
                    "no hybrid metric will be reported"
                )
            wall = [item.wall_ms for item in observations]
            cpu = [item.cpu_ms for item in observations]
            elapsed_seconds = sum(wall) / 1000
            representative = observations[-1]
            results.append(
                TLSBenchmark(
                    profile=profile,  # type: ignore[arg-type]
                    configured_policy=(
                        "X25519 forced through SSLContext.set_ecdh_curve"
                        if profile == "standard-tls-1.3"
                        else (
                            "OpenSSL 3.5 default preference; every observed ServerHello is "
                            "required to contain X25519MLKEM768 or the benchmark fails"
                        )
                    ),
                    negotiated_group=GROUP_NAMES[expected_group],
                    negotiated_group_id=f"0x{expected_group:04x}",
                    server_key_share_bytes=representative.key_share_bytes,
                    cipher=representative.cipher,
                    client_to_server_handshake_bytes=round(
                        sum(item.client_bytes for item in observations) / iterations
                    ),
                    server_to_client_handshake_bytes=round(
                        sum(item.server_bytes for item in observations) / iterations
                    ),
                    wall_latency=distribution(wall, "milliseconds"),
                    cpu_time=distribution(cpu, "milliseconds"),
                    throughput_handshakes_per_second=iterations / elapsed_seconds,
                )
            )

        matrix: list[CompatibilityResult] = []
        policies: tuple[Policy, ...] = ("classic-only", "hybrid-preferred")
        for client_policy in policies:
            for server_policy in policies:
                client_context, server_context = _contexts(
                    certificate, private_key, client_policy, server_policy
                )
                try:
                    observation = observe_handshake(client_context, server_context)
                except (ssl.SSLError, BenchmarkUnavailable) as exc:
                    matrix.append(
                        CompatibilityResult(
                            client_policy=client_policy,
                            server_policy=server_policy,
                            success=False,
                            negotiated_group=None,
                            note=f"OpenSSL-to-OpenSSL lab handshake failed: {type(exc).__name__}",
                        )
                    )
                else:
                    matrix.append(
                        CompatibilityResult(
                            client_policy=client_policy,
                            server_policy=server_policy,
                            success=True,
                            negotiated_group=GROUP_NAMES.get(
                                observation.group_id, f"unknown-{observation.group_id:#06x}"
                            ),
                            note=(
                                "Measured only with this report's Python/OpenSSL build; this is not "
                                "evidence of browser or third-party client compatibility."
                            ),
                        )
                    )
    return results, matrix
