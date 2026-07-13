"""Two bounded microservices and a verifying client for the migration lab."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import socket
import ssl
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from crypto_agility.errors import BenchmarkUnavailable, ProtocolError
from crypto_agility.native_oqs import MLDSA65, MLKEM768, OQSLibrary
from crypto_agility.tlsbench import (
    GROUP_NAMES,
    X25519_GROUP_ID,
    X25519_MLKEM768_GROUP_ID,
    parse_server_hello_key_share,
)
from crypto_agility.util import sha256_hex

DemoMode = Literal["classic", "hybrid"]
MAX_MESSAGE_BYTES = 32 * 1024
PROTOCOL_VERSION = "crypto-agility-demo/1"


def generate_lab_certificate(output_directory: Path, *, overwrite: bool = False) -> dict[str, Path]:
    """Create a short-lived CA and server certificate; private files are mode 0600."""
    output_directory.mkdir(parents=True, exist_ok=True)
    paths = {
        "ca_certificate": output_directory / "ca.pem",
        "ca_private_key": output_directory / "ca-key.pem",
        "server_certificate": output_directory / "server.pem",
        "server_private_key": output_directory / "server-key.pem",
    }
    if not overwrite and any(path.exists() for path in paths.values()):
        raise FileExistsError("lab certificate output already exists; pass overwrite explicitly")

    now = datetime.now(UTC)
    ca_key = ec.generate_private_key(ec.SECP384R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Crypto Agility Lab CA")])
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=7))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA384())
    )
    server_key = ec.generate_private_key(ec.SECP256R1())
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "crypto-agility-demo")])
    server_certificate = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.DNSName("classic-service"),
                    x509.DNSName("hybrid-service"),
                    x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA384())
    )

    paths["ca_certificate"].write_bytes(ca_certificate.public_bytes(serialization.Encoding.PEM))
    paths["server_certificate"].write_bytes(
        server_certificate.public_bytes(serialization.Encoding.PEM)
    )
    paths["ca_private_key"].write_bytes(
        ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    paths["server_private_key"].write_bytes(
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    paths["ca_private_key"].chmod(0o600)
    paths["server_private_key"].chmod(0o600)
    paths["ca_certificate"].chmod(0o644)
    paths["server_certificate"].chmod(0o644)
    return paths


def _server_context(mode: DemoMode, certificate: Path, private_key: Path) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(certificate, private_key)
    context.num_tickets = 0
    if mode == "classic":
        context.set_ecdh_curve("X25519")
    elif ssl.OPENSSL_VERSION_INFO < (3, 5, 0):
        raise BenchmarkUnavailable(
            f"hybrid service requires OpenSSL 3.5+; found {ssl.OPENSSL_VERSION}"
        )
    return context


class DemoApplication:
    """Stateful bounded protocol; it exposes no arbitrary command or network primitive."""

    def __init__(self, mode: DemoMode, oqs_install_path: Path | None = None) -> None:
        self.mode = mode
        self.library: OQSLibrary | None = None
        self.kem: MLKEM768 | None = None
        self.signature: MLDSA65 | None = None
        self.kem_public: bytes | None = None
        self.signature_public: bytes | None = None
        if mode == "hybrid":
            self.library = OQSLibrary(oqs_install_path)
            self.kem = MLKEM768(self.library)
            self.signature = MLDSA65(self.library)
            self.kem_public = self.kem.generate_keypair()
            self.signature_public = self.signature.generate_keypair()

    def close(self) -> None:
        if self.kem is not None:
            self.kem.close()
        if self.signature is not None:
            self.signature.close()

    def capabilities(self) -> dict[str, Any]:
        common: dict[str, Any] = {
            "protocol": PROTOCOL_VERSION,
            "mode": self.mode,
            "tls_certificate_algorithm": "ECDSA P-256",
            "transport_profile": (
                "standard TLS 1.3 / X25519"
                if self.mode == "classic"
                else "true hybrid TLS 1.3 preferred / X25519MLKEM768; client must verify"
            ),
        }
        if self.mode == "hybrid":
            assert self.library is not None
            assert self.kem_public is not None
            assert self.signature_public is not None
            common.update(
                {
                    "application_profile": "experimental application encapsulation v1",
                    "application_kem": "ML-KEM-768",
                    "application_signature": "ML-DSA-65",
                    "liboqs_version": self.library.version,
                    "kem_public_key": base64.b64encode(self.kem_public).decode("ascii"),
                    "signature_public_key": base64.b64encode(self.signature_public).decode("ascii"),
                    "trust_note": (
                        "Application public keys are authenticated by this ECDSA TLS channel; "
                        "the ML-DSA signature is not the TLS certificate."
                    ),
                }
            )
        return common

    def handle(self, request: dict[str, Any]) -> dict[str, Any]:
        if request.get("protocol") != PROTOCOL_VERSION:
            raise ProtocolError("unsupported or missing protocol version")
        operation = request.get("operation")
        if operation == "capabilities":
            return self.capabilities()
        if operation == "ping":
            return {
                "protocol": PROTOCOL_VERSION,
                "mode": self.mode,
                "reply": "pong",
                "request_digest": f"sha256:{sha256_hex(str(request.get('nonce', '')).encode())}",
            }
        if operation != "encapsulated-request" or self.mode != "hybrid":
            raise ProtocolError("operation is not allowed for this service profile")
        assert self.kem is not None
        assert self.signature is not None
        try:
            challenge = base64.b64decode(request["challenge"], validate=True)
            ciphertext = base64.b64decode(request["ciphertext"], validate=True)
        except (KeyError, ValueError, TypeError) as exc:
            raise ProtocolError("challenge and ciphertext must be valid base64") from exc
        if len(challenge) != 32:
            raise ProtocolError("challenge must be exactly 32 bytes")
        if len(ciphertext) != self.kem.ciphertext_bytes:
            raise ProtocolError("ciphertext length does not match ML-KEM-768")
        shared_secret = self.kem.decapsulate(ciphertext)
        authenticator = hmac.new(shared_secret, challenge, hashlib.sha256).digest()
        transcript = b"crypto-agility-envelope-v1\0" + challenge + ciphertext + authenticator
        signature = self.signature.sign(transcript)
        return {
            "protocol": PROTOCOL_VERSION,
            "mode": self.mode,
            "authenticator": base64.b64encode(authenticator).decode("ascii"),
            "signature": base64.b64encode(signature).decode("ascii"),
            "transcript_digest": f"sha256:{sha256_hex(transcript)}",
        }


async def _handle_connection(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, application: DemoApplication
) -> None:
    try:
        raw = await asyncio.wait_for(reader.readline(), timeout=5)
        if not raw or len(raw) > MAX_MESSAGE_BYTES:
            raise ProtocolError("request is empty or exceeds the 32 KiB limit")
        request = json.loads(raw)
        if not isinstance(request, dict):
            raise ProtocolError("request must be a JSON object")
        response = application.handle(request)
        status = 200
    except (TimeoutError, json.JSONDecodeError, ProtocolError) as exc:
        status = 400
        response = {"protocol": PROTOCOL_VERSION, "error": str(exc)}
    except Exception:
        status = 500
        response = {"protocol": PROTOCOL_VERSION, "error": "internal service error"}
    response["status"] = status
    writer.write(json.dumps(response, separators=(",", ":")).encode() + b"\n")
    await writer.drain()
    writer.close()
    with suppress(ConnectionResetError, BrokenPipeError):
        await writer.wait_closed()


async def serve_demo(
    *,
    mode: DemoMode,
    host: str,
    port: int,
    certificate: Path,
    private_key: Path,
    oqs_install_path: Path | None = None,
) -> None:
    context = _server_context(mode, certificate, private_key)
    application = DemoApplication(mode, oqs_install_path)
    try:
        server = await asyncio.start_server(
            lambda reader, writer: _handle_connection(reader, writer, application),
            host,
            port,
            ssl=context,
            limit=MAX_MESSAGE_BYTES + 1,
        )
        async with server:
            await server.serve_forever()
    finally:
        application.close()


@dataclass
class _BIOSocket:
    raw_socket: socket.socket
    ssl_object: ssl.SSLObject
    incoming: ssl.MemoryBIO
    outgoing: ssl.MemoryBIO
    server_wire: bytearray

    def _flush(self) -> None:
        while outgoing := self.outgoing.read():
            self.raw_socket.sendall(outgoing)

    def _receive(self) -> None:
        incoming = self.raw_socket.recv(16 * 1024)
        if not incoming:
            raise ProtocolError("TLS peer closed the connection")
        self.server_wire.extend(incoming)
        self.incoming.write(incoming)

    def handshake(self) -> tuple[int, int]:
        for _ in range(100):
            try:
                self.ssl_object.do_handshake()
            except ssl.SSLWantReadError:
                self._flush()
                self._receive()
            except ssl.SSLWantWriteError:
                self._flush()
            else:
                self._flush()
                return parse_server_hello_key_share(bytes(self.server_wire))
        raise ProtocolError("TLS handshake did not converge")

    def request(self, payload: dict[str, Any]) -> dict[str, Any]:
        wire = json.dumps(payload, separators=(",", ":")).encode() + b"\n"
        sent = 0
        while sent < len(wire):
            with suppress(ssl.SSLWantWriteError):
                sent += self.ssl_object.write(wire[sent:])
            self._flush()
        plaintext = bytearray()
        while b"\n" not in plaintext:
            try:
                plaintext.extend(self.ssl_object.read(MAX_MESSAGE_BYTES))
            except ssl.SSLWantReadError:
                self._flush()
                self._receive()
            if len(plaintext) > MAX_MESSAGE_BYTES:
                raise ProtocolError("response exceeds the 32 KiB limit")
        decoded = json.loads(plaintext.split(b"\n", 1)[0])
        if not isinstance(decoded, dict):
            raise ProtocolError("response must be a JSON object")
        return decoded

    def close(self) -> None:
        self.raw_socket.close()


def _connect(
    host: str, port: int, mode: DemoMode, ca_certificate: Path | None, insecure: bool
) -> tuple[_BIOSocket, int, int]:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    else:
        if ca_certificate is None:
            raise ValueError("a CA certificate is required unless insecure mode is explicit")
        context.load_verify_locations(cafile=ca_certificate)
    if mode == "classic":
        context.set_ecdh_curve("X25519")
    elif ssl.OPENSSL_VERSION_INFO < (3, 5, 0):
        raise BenchmarkUnavailable("hybrid demo client requires OpenSSL 3.5+")
    raw_socket = socket.create_connection((host, port), timeout=5)
    raw_socket.settimeout(5)
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls_object = context.wrap_bio(incoming, outgoing, server_side=False, server_hostname=host)
    connection = _BIOSocket(raw_socket, tls_object, incoming, outgoing, bytearray())
    group_id, key_share_bytes = connection.handshake()
    expected = X25519_GROUP_ID if mode == "classic" else X25519_MLKEM768_GROUP_ID
    if group_id != expected:
        connection.close()
        raise ProtocolError(
            f"service negotiated {GROUP_NAMES.get(group_id, hex(group_id))}, expected {GROUP_NAMES[expected]}"
        )
    return connection, group_id, key_share_bytes


def run_demo_client(
    *,
    mode: DemoMode,
    host: str,
    port: int,
    ca_certificate: Path | None,
    insecure: bool = False,
    oqs_install_path: Path | None = None,
) -> dict[str, Any]:
    connection, group_id, key_share_bytes = _connect(host, port, mode, ca_certificate, insecure)
    try:
        capabilities = connection.request(
            {"protocol": PROTOCOL_VERSION, "operation": "capabilities"}
        )
    finally:
        connection.close()
    reported_capabilities = {
        key: value
        for key, value in capabilities.items()
        if key not in {"kem_public_key", "signature_public_key"}
    }
    if mode == "hybrid":
        reported_capabilities.update(
            {
                "kem_public_key_bytes": len(base64.b64decode(capabilities["kem_public_key"])),
                "kem_public_key_sha256": sha256_hex(
                    base64.b64decode(capabilities["kem_public_key"])
                ),
                "signature_public_key_bytes": len(
                    base64.b64decode(capabilities["signature_public_key"])
                ),
                "signature_public_key_sha256": sha256_hex(
                    base64.b64decode(capabilities["signature_public_key"])
                ),
            }
        )
    result: dict[str, Any] = {
        "mode": mode,
        "negotiated_group": GROUP_NAMES[group_id],
        "negotiated_group_id": f"0x{group_id:04x}",
        "server_key_share_bytes": key_share_bytes,
        "certificate_validation": "disabled-explicitly" if insecure else "verified",
        "capabilities": reported_capabilities,
    }
    if mode == "classic":
        result["validated"] = capabilities.get("mode") == "classic"
        return result

    library = OQSLibrary(oqs_install_path)
    kem_public = base64.b64decode(capabilities["kem_public_key"], validate=True)
    signature_public = base64.b64decode(capabilities["signature_public_key"], validate=True)
    with MLKEM768(library) as kem, MLDSA65(library) as verifier:
        ciphertext, shared_secret = kem.encapsulate(kem_public)
        challenge = os.urandom(32)
        connection, repeated_group, _ = _connect(host, port, mode, ca_certificate, insecure)
        try:
            response = connection.request(
                {
                    "protocol": PROTOCOL_VERSION,
                    "operation": "encapsulated-request",
                    "challenge": base64.b64encode(challenge).decode("ascii"),
                    "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
                }
            )
        finally:
            connection.close()
        if repeated_group != X25519_MLKEM768_GROUP_ID:
            raise ProtocolError("second request did not retain the true hybrid TLS group")
        authenticator = base64.b64decode(response["authenticator"], validate=True)
        signature = base64.b64decode(response["signature"], validate=True)
        expected_authenticator = hmac.new(shared_secret, challenge, hashlib.sha256).digest()
        transcript = b"crypto-agility-envelope-v1\0" + challenge + ciphertext + authenticator
        authentication_valid = hmac.compare_digest(authenticator, expected_authenticator)
        signature_valid = verifier.verify(transcript, signature, signature_public)
    result.update(
        {
            "application_profile": "experimental application encapsulation v1",
            "kem_shared_secret_confirmed": authentication_valid,
            "application_signature_verified": signature_valid,
            "validated": authentication_valid and signature_valid,
        }
    )
    return result
