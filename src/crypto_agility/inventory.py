"""Bounded cryptographic inventory for files and explicitly named endpoints."""

from __future__ import annotations

import base64
import json
import re
import shutil
import socket
import ssl
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa, x25519

from crypto_agility.errors import ScanSafetyError
from crypto_agility.models import CryptoFinding, Evidence, Exposure
from crypto_agility.registry import normalize_algorithm
from crypto_agility.util import redact_excerpt, sha256_hex, stable_id

MAX_FILE_BYTES = 2 * 1024 * 1024
IGNORED_DIRECTORIES = {
    ".git",
    ".venv",
    ".local",
    ".state",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
}
TEXT_SUFFIXES = {
    "",
    ".cfg",
    ".conf",
    ".cnf",
    ".env",
    ".example",
    ".ini",
    ".json",
    ".jwt",
    ".lock",
    ".properties",
    ".pub",
    ".py",
    ".sh",
    ".toml",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}
MANIFEST_NAMES = {
    "cargo.lock",
    "cargo.toml",
    "go.mod",
    "go.sum",
    "package-lock.json",
    "package.json",
    "poetry.lock",
    "pyproject.toml",
    "requirements.txt",
    "uv.lock",
}
CRYPTO_LIBRARIES = {
    "bcrypt",
    "boringssl",
    "cryptography",
    "gnutls",
    "jose",
    "jsonwebtoken",
    "liboqs",
    "libsodium",
    "mbedtls",
    "nacl",
    "openssl",
    "pyjwt",
    "pyopenssl",
    "ring",
    "rustls",
    "tink",
}

JWT_RE = re.compile(
    r"(?<![A-Za-z0-9_-])([A-Za-z0-9_-]{8,})\.([A-Za-z0-9_-]{2,})\.([A-Za-z0-9_-]*)(?![A-Za-z0-9_-])"
)
ALGORITHM_RE = re.compile(
    r"(?i)\b("
    r"TLSv?1(?:\.[0-3])?|X25519MLKEM768|ML[-_ ]?KEM[-_ ]?768|ML[-_ ]?DSA[-_ ]?65|"
    r"RSA|ECDSA|ECDH|Ed25519|"
    r"ssh-rsa|rsa-sha2-(?:256|512)|ssh-ed25519|ssh-dss|ecdsa-sha2-nistp256|"
    r"curve25519-sha256|diffie-hellman(?:-[a-z0-9-]+)?|"
    r"HS256|RS256|ES256|EdDSA|AES[-_ ]?(?:128|256)|3DES|DES|RC4|MD5|SHA[-_ ]?1"
    r")\b"
)
PEM_RE = re.compile(
    rb"-----BEGIN ([A-Z0-9 ]+)-----\r?\n.*?-----END \1-----\r?\n?",
    re.DOTALL,
)


@dataclass(frozen=True)
class EndpointTarget:
    host: str
    port: int
    verify: bool = True

    def __post_init__(self) -> None:
        if not self.host or any(char.isspace() for char in self.host):
            raise ValueError("endpoint host must be a non-empty hostname or address")
        if not 1 <= self.port <= 65535:
            raise ValueError("endpoint port must be between 1 and 65535")


@dataclass(frozen=True)
class ScanOptions:
    root: Path
    confidentiality_years: int = 5
    exposure: Exposure = "internal"
    max_file_bytes: int = MAX_FILE_BYTES
    tls_targets: tuple[EndpointTarget, ...] = field(default_factory=tuple)
    ssh_targets: tuple[EndpointTarget, ...] = field(default_factory=tuple)
    timeout_seconds: float = 3.0

    def __post_init__(self) -> None:
        if not 0 <= self.confidentiality_years <= 100:
            raise ValueError("confidentiality_years must be between 0 and 100")
        if not 1024 <= self.max_file_bytes <= 32 * 1024 * 1024:
            raise ValueError("max_file_bytes must be between 1 KiB and 32 MiB")
        if not 0.1 <= self.timeout_seconds <= 30:
            raise ValueError("timeout_seconds must be between 0.1 and 30")


def _key_description(public_key: Any) -> tuple[str, int | None, dict[str, Any]]:
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size, {}
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return "ECDSA", public_key.key_size, {"curve": public_key.curve.name}
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "ED25519", 256, {}
    if isinstance(public_key, ed448.Ed448PublicKey):
        return "ED25519", 448, {"variant": "Ed448"}
    if isinstance(public_key, x25519.X25519PublicKey):
        return "X25519", 256, {}
    if isinstance(public_key, dsa.DSAPublicKey):
        return "DSA", public_key.key_size, {}
    return type(public_key).__name__.upper(), None, {}


def _public_fingerprint(public_key: Any) -> str:
    encoded = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return f"sha256:{sha256_hex(encoded)}"


class InventoryScanner:
    """Collect metadata while keeping file contents and token payloads out of output."""

    def __init__(self, options: ScanOptions) -> None:
        self.options = options
        self.root = options.root.resolve(strict=True)
        if not self.root.is_dir():
            raise ScanSafetyError("scan root must be an existing directory")
        self._findings: dict[str, CryptoFinding] = {}

    def scan(self) -> list[CryptoFinding]:
        for path in self._candidate_files():
            self._scan_file(path)
        for target in self.options.tls_targets:
            self._scan_tls_endpoint(target)
        for target in self.options.ssh_targets:
            self._scan_ssh_endpoint(target)
        return sorted(self._findings.values(), key=lambda item: item.finding_id)

    def _candidate_files(self) -> list[Path]:
        candidates: list[Path] = []
        for path in self.root.rglob("*"):
            relative = path.relative_to(self.root)
            if any(part in IGNORED_DIRECTORIES for part in relative.parts):
                continue
            if path.is_symlink() or not path.is_file():
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size <= self.options.max_file_bytes and (
                path.suffix.lower() in TEXT_SUFFIXES
                or path.name.lower() in MANIFEST_NAMES
                or path.suffix.lower() in {".pem", ".crt", ".cer", ".key"}
            ):
                candidates.append(path)
        return sorted(candidates)

    def _scan_file(self, path: Path) -> None:
        try:
            raw = path.read_bytes()
        except OSError:
            return
        relative = path.relative_to(self.root).as_posix()
        for match in PEM_RE.finditer(raw):
            self._scan_pem_block(relative, raw[: match.start()].count(b"\n") + 1, match.group(0))

        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return
        self._scan_text_algorithms(relative, text)
        self._scan_jwts(relative, text)
        self._scan_ssh_public_keys(relative, text)
        if path.name.lower() in MANIFEST_NAMES:
            self._scan_manifest(relative, text)

    def _evidence(
        self,
        source: str,
        locator: str,
        detector: str,
        excerpt: str,
        confidence: float,
    ) -> Evidence:
        return Evidence(
            source=source,
            locator=locator,
            detector=detector,
            excerpt_hash=redact_excerpt(excerpt),
            confidence=confidence,
        )

    def _add(
        self,
        *,
        source: str,
        locator: str,
        asset_kind: str,
        algorithm: str,
        use: str,
        detector: str,
        excerpt: str,
        confidence: float,
        key_bits: int | None = None,
        protocol_version: str | None = None,
        library_version: str | None = None,
        metadata: dict[str, Any] | None = None,
        exposure: Exposure | None = None,
    ) -> None:
        canonical = normalize_algorithm(algorithm)
        clean_metadata = metadata or {}
        identity = {
            "source": source,
            "locator": locator,
            "kind": asset_kind,
            "algorithm": canonical,
            "use": use,
            "key_bits": key_bits,
            "protocol": protocol_version,
            "version": library_version,
            "metadata": clean_metadata,
        }
        finding_id = stable_id("finding", identity)
        if finding_id in self._findings:
            return
        self._findings[finding_id] = CryptoFinding(
            finding_id=finding_id,
            asset_id=stable_id("asset", {"source": source, "kind": asset_kind}),
            asset_kind=asset_kind,  # type: ignore[arg-type]
            algorithm=canonical,
            use=use,
            key_bits=key_bits,
            protocol_version=protocol_version,
            library_version=library_version,
            exposure=exposure or self.options.exposure,
            confidentiality_years=self.options.confidentiality_years,
            metadata=clean_metadata,
            evidence=[self._evidence(source, locator, detector, excerpt, confidence)],
        )

    def _scan_pem_block(self, source: str, line: int, block: bytes) -> None:
        locator = f"line:{line}"
        header = block.splitlines()[0].decode("ascii", errors="replace")
        if b"CERTIFICATE" in block.splitlines()[0]:
            try:
                certificate = x509.load_pem_x509_certificate(block)
            except ValueError:
                return
            public_key = certificate.public_key()
            algorithm, bits, details = _key_description(public_key)
            details.update(
                {
                    "fingerprint": f"sha256:{certificate.fingerprint(hashes.SHA256()).hex()}",
                    "public_key_fingerprint": _public_fingerprint(public_key),
                    "subject_hash": f"sha256:{sha256_hex(certificate.subject.rfc4514_string().encode())}",
                    "issuer_hash": f"sha256:{sha256_hex(certificate.issuer.rfc4514_string().encode())}",
                    "not_before": certificate.not_valid_before_utc.isoformat(),
                    "not_after": certificate.not_valid_after_utc.isoformat(),
                    "expired": certificate.not_valid_after_utc < datetime.now(UTC),
                }
            )
            self._add(
                source=source,
                locator=locator,
                asset_kind="certificate",
                algorithm=algorithm,
                use="certificate public key signature",
                detector="x509-parser",
                excerpt=header,
                confidence=1.0,
                key_bits=bits,
                metadata=details,
            )
            signature_hash = certificate.signature_hash_algorithm
            if signature_hash is not None:
                self._add(
                    source=source,
                    locator=locator,
                    asset_kind="certificate",
                    algorithm=signature_hash.name,
                    use="certificate digest",
                    detector="x509-parser",
                    excerpt=header,
                    confidence=1.0,
                    metadata={"certificate_fingerprint": details["fingerprint"]},
                )
            return

        private_present = b"PRIVATE KEY" in block.splitlines()[0]
        try:
            if private_present:
                key = serialization.load_pem_private_key(block, password=None)
                loaded_public_key: Any = key.public_key()
            else:
                loaded_public_key = serialization.load_pem_public_key(block)
        except (TypeError, ValueError):
            if private_present:
                # Encrypted or unsupported private keys are still inventoried without decryption.
                self._add(
                    source=source,
                    locator=locator,
                    asset_kind="key",
                    algorithm="UNKNOWN-ENCRYPTED-PRIVATE-KEY",
                    use="private key storage",
                    detector="pem-header",
                    excerpt=header,
                    confidence=0.7,
                    metadata={"private_key_present": True, "encrypted_or_unreadable": True},
                )
            return
        algorithm, bits, details = _key_description(loaded_public_key)
        details.update(
            {
                "public_key_fingerprint": _public_fingerprint(loaded_public_key),
                "private_key_present": private_present,
            }
        )
        self._add(
            source=source,
            locator=locator,
            asset_kind="key",
            algorithm=algorithm,
            use="private key storage" if private_present else "public key storage",
            detector="pem-parser",
            excerpt=header,
            confidence=1.0,
            key_bits=bits,
            metadata=details,
        )

    def _scan_text_algorithms(self, source: str, text: str) -> None:
        for line_number, line in enumerate(text.splitlines(), 1):
            for match in ALGORITHM_RE.finditer(line):
                raw = match.group(1)
                canonical = normalize_algorithm(raw)
                if canonical.startswith("TLS-"):
                    kind, use, protocol = "protocol", "transport protocol", canonical
                elif raw.lower().startswith(("ssh-", "curve25519", "diffie-hellman")):
                    kind, use, protocol = "configuration", "ssh algorithm configuration", "SSH-2"
                elif canonical in {"HS256", "RS256", "ES256", "EDDSA", "NONE"}:
                    kind, use, protocol = "configuration", "jwt signature", "JWT"
                elif canonical in {"ECDH", "X25519", "DH"} and "key_agreement" in line.lower():
                    kind, use, protocol = "configuration", "tls key agreement", "TLS"
                elif canonical in {"RSA", "ECDSA", "ED25519"} and "certificate" in line.lower():
                    kind, use, protocol = "configuration", "tls certificate signature", "TLS"
                else:
                    kind, use, protocol = "configuration", "declared cryptographic algorithm", None
                self._add(
                    source=source,
                    locator=f"line:{line_number}",
                    asset_kind=kind,
                    algorithm=canonical,
                    use=use,
                    detector="configuration-token",
                    excerpt=line,
                    confidence=0.82,
                    protocol_version=protocol,
                )

    def _scan_jwts(self, source: str, text: str) -> None:
        for match in JWT_RE.finditer(text):
            header_segment = match.group(1)
            padding = "=" * (-len(header_segment) % 4)
            try:
                header = json.loads(base64.urlsafe_b64decode(header_segment + padding))
            except (ValueError, json.JSONDecodeError):
                continue
            algorithm = header.get("alg")
            if not isinstance(algorithm, str):
                continue
            line = text.count("\n", 0, match.start()) + 1
            self._add(
                source=source,
                locator=f"line:{line}",
                asset_kind="jwt",
                algorithm=algorithm,
                use="jwt signature",
                detector="jwt-header-only",
                excerpt=header_segment,
                confidence=1.0,
                protocol_version="JWT",
                metadata={
                    "header_fields": sorted(str(key) for key in header),
                    "token_fingerprint": f"sha256:{sha256_hex(match.group(0).encode())}",
                    "payload_inspected": False,
                },
            )

    def _scan_ssh_public_keys(self, source: str, text: str) -> None:
        for line_number, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if not stripped.startswith(("ssh-rsa ", "ssh-ed25519 ", "ssh-dss ", "ecdsa-")):
                continue
            fields = stripped.split()
            if len(fields) < 2:
                continue
            encoded = " ".join(fields[:2]).encode()
            try:
                public_key = serialization.load_ssh_public_key(encoded)
                algorithm, bits, details = _key_description(public_key)
                details["public_key_fingerprint"] = _public_fingerprint(public_key)
                confidence = 1.0
            except (TypeError, ValueError):
                algorithm, bits, details, confidence = fields[0], None, {}, 0.72
            self._add(
                source=source,
                locator=f"line:{line_number}",
                asset_kind="key",
                algorithm=algorithm,
                use="ssh host or user public key",
                detector="ssh-public-key-parser",
                excerpt=fields[0],
                confidence=confidence,
                key_bits=bits,
                protocol_version="SSH-2",
                metadata=details,
            )

    def _scan_manifest(self, source: str, text: str) -> None:
        for line_number, line in enumerate(text.splitlines(), 1):
            lowered = line.lower()
            for package in CRYPTO_LIBRARIES:
                if not re.search(rf"(?<![a-z0-9_-]){re.escape(package)}(?![a-z0-9_-])", lowered):
                    continue
                version_match = re.search(
                    rf"(?i){re.escape(package)}[^\n\d]{{0,12}}(?:v|==|=|\^|~|>=)?\s*([0-9]+(?:\.[0-9A-Za-z+.-]+)+)",
                    line,
                )
                version = version_match.group(1) if version_match else None
                self._add(
                    source=source,
                    locator=f"line:{line_number}",
                    asset_kind="library",
                    algorithm=f"LIBRARY-{package}",
                    use="cryptographic library dependency",
                    detector="dependency-manifest",
                    excerpt=line,
                    confidence=0.9,
                    library_version=version,
                    metadata={"package": package},
                )

    def _scan_tls_endpoint(self, target: EndpointTarget) -> None:
        endpoint = f"{target.host}:{target.port}"
        context = ssl.create_default_context()
        if not target.verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        with (
            socket.create_connection(
                (target.host, target.port), timeout=self.options.timeout_seconds
            ) as raw_socket,
            context.wrap_socket(raw_socket, server_hostname=target.host) as tls_socket,
        ):
            protocol = tls_socket.version() or "unknown"
            cipher = tls_socket.cipher()
            certificate_der = tls_socket.getpeercert(binary_form=True)
        self._add(
            source=f"tls://{endpoint}",
            locator="negotiated-session",
            asset_kind="tls-endpoint",
            algorithm=protocol,
            use="transport protocol",
            detector="explicit-tls-probe",
            excerpt=f"{protocol}:{cipher[0] if cipher else 'unknown'}",
            confidence=1.0,
            protocol_version=protocol,
            metadata={
                "cipher": cipher[0] if cipher else None,
                "certificate_validation": "verified" if target.verify else "explicitly-disabled",
            },
            exposure="internet"
            if target.host not in {"localhost", "127.0.0.1", "::1"}
            else "local",
        )
        if certificate_der:
            certificate = x509.load_der_x509_certificate(certificate_der)
            public_key = certificate.public_key()
            algorithm, bits, details = _key_description(public_key)
            details["fingerprint"] = f"sha256:{certificate.fingerprint(hashes.SHA256()).hex()}"
            self._add(
                source=f"tls://{endpoint}",
                locator="peer-certificate",
                asset_kind="certificate",
                algorithm=algorithm,
                use="tls certificate signature",
                detector="explicit-tls-probe",
                excerpt=details["fingerprint"],
                confidence=1.0,
                key_bits=bits,
                metadata=details,
                exposure="internet"
                if target.host not in {"localhost", "127.0.0.1", "::1"}
                else "local",
            )

    def _scan_ssh_endpoint(self, target: EndpointTarget) -> None:
        endpoint = f"{target.host}:{target.port}"
        with socket.create_connection(
            (target.host, target.port), timeout=self.options.timeout_seconds
        ) as connection:
            connection.settimeout(self.options.timeout_seconds)
            banner = connection.recv(255).decode("ascii", errors="replace").strip()
        if not banner.startswith("SSH-2.0-"):
            raise ScanSafetyError(
                f"explicit SSH target {endpoint} did not present an SSH-2.0 banner"
            )
        self._add(
            source=f"ssh://{endpoint}",
            locator="server-banner",
            asset_kind="ssh-endpoint",
            algorithm="SSH-2",
            use="transport protocol",
            detector="explicit-ssh-banner-probe",
            excerpt=banner,
            confidence=1.0,
            protocol_version="SSH-2",
            metadata={"implementation_hash": f"sha256:{sha256_hex(banner.encode())}"},
            exposure="internet"
            if target.host not in {"localhost", "127.0.0.1", "::1"}
            else "local",
        )

        keyscan = shutil.which("ssh-keyscan")
        if keyscan is None:
            return
        # The executable is resolved locally and arguments are passed as a vector; no shell
        # or scanned file content is involved. Host/port came from an explicit CLI target.
        completed = subprocess.run(  # noqa: S603
            [
                keyscan,
                "-T",
                str(max(1, int(self.options.timeout_seconds))),
                "-p",
                str(target.port),
                target.host,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=self.options.timeout_seconds + 1,
        )
        self._scan_ssh_public_keys(f"ssh://{endpoint}", completed.stdout)
