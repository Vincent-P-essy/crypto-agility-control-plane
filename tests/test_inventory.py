from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from crypto_agility.inventory import InventoryScanner, ScanOptions


def test_fixture_inventory_finds_all_supported_asset_classes(fixture_root: Path) -> None:
    findings = InventoryScanner(ScanOptions(root=fixture_root, confidentiality_years=12)).scan()
    algorithms = {finding.algorithm for finding in findings}
    assert {
        "TLS-1.0",
        "TLS-1.2",
        "X25519",
        "DH",
        "RSA",
        "ED25519",
        "HS256",
        "RS256",
        "AES-128",
        "3DES",
        "ML-KEM-768",
        "ML-DSA-65",
        "X25519MLKEM768",
    } <= algorithms
    assert {finding.asset_kind for finding in findings} >= {
        "configuration",
        "protocol",
        "jwt",
        "library",
    }


def test_jwt_output_contains_header_metadata_but_no_token_or_payload(fixture_root: Path) -> None:
    token = (fixture_root / "sample.jwt").read_text(encoding="utf-8").strip()
    findings = InventoryScanner(ScanOptions(root=fixture_root)).scan()
    jwt = next(finding for finding in findings if finding.asset_kind == "jwt")
    serialized = jwt.model_dump_json()
    assert jwt.algorithm == "RS256"
    assert jwt.metadata["payload_inspected"] is False
    assert jwt.metadata["header_fields"] == ["alg", "kid", "typ"]
    assert token not in serialized
    assert "fixture-user" not in serialized
    assert jwt.evidence[0].excerpt_hash.startswith("sha256:")


def test_scanner_ignores_symlinks_and_oversized_files(tmp_path: Path) -> None:
    external = tmp_path.parent / "external-secret.env"
    external.write_text("JWT_ALGORITHM=none", encoding="utf-8")
    (tmp_path / "linked.env").symlink_to(external)
    (tmp_path / "oversized.conf").write_text("TLSv1 " * 1000, encoding="utf-8")
    findings = InventoryScanner(ScanOptions(root=tmp_path, max_file_bytes=1024)).scan()
    assert findings == []


def test_pem_private_key_is_fingerprinted_not_serialized(tmp_path: Path) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture.example")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(private_key, hashes.SHA256())
    )
    private_bytes = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    (tmp_path / "key.pem").write_bytes(private_bytes)
    (tmp_path / "certificate.pem").write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    findings = InventoryScanner(ScanOptions(root=tmp_path)).scan()
    private_finding = next(
        finding for finding in findings if finding.metadata.get("private_key_present") is True
    )
    assert private_finding.algorithm == "RSA"
    assert private_finding.key_bits == 2048
    assert private_finding.metadata["public_key_fingerprint"].startswith("sha256:")
    assert private_bytes.decode() not in private_finding.model_dump_json()
    certificate_finding = next(
        finding for finding in findings if finding.asset_kind == "certificate"
    )
    assert "fixture.example" not in certificate_finding.model_dump_json()
