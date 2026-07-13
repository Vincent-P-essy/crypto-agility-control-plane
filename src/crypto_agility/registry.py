"""Algorithm normalization and versioned registry access."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ALIASES = {
    "none": "NONE",
    "rsa": "RSA",
    "rsa-sha2-256": "RSA",
    "rsa-sha2-512": "RSA",
    "ssh-rsa": "RSA",
    "ecdsa": "ECDSA",
    "ecdsa-sha2-nistp256": "ECDSA",
    "ecdh": "ECDH",
    "curve25519-sha256": "X25519",
    "x25519": "X25519",
    "ed25519": "ED25519",
    "ssh-ed25519": "ED25519",
    "dsa": "DSA",
    "ssh-dss": "DSA",
    "diffie-hellman": "DH",
    "ml-kem-768": "ML-KEM-768",
    "mlkem768": "ML-KEM-768",
    "ml-dsa-65": "ML-DSA-65",
    "mldsa65": "ML-DSA-65",
    "x25519mlkem768": "X25519MLKEM768",
    "tlsv1": "TLS-1.0",
    "tlsv1.0": "TLS-1.0",
    "tls1.0": "TLS-1.0",
    "tlsv1.1": "TLS-1.1",
    "tls1.1": "TLS-1.1",
    "tlsv1.2": "TLS-1.2",
    "tls1.2": "TLS-1.2",
    "tlsv1.3": "TLS-1.3",
    "tls1.3": "TLS-1.3",
    "ssh-2.0": "SSH-2",
    "hs256": "HS256",
    "rs256": "RS256",
    "es256": "ES256",
    "eddsa": "EDDSA",
    "sha1": "SHA-1",
    "sha-1": "SHA-1",
    "sha256": "SHA-256",
    "sha-256": "SHA-256",
    "sha384": "SHA-384",
    "sha-384": "SHA-384",
    "aes128": "AES-128",
    "aes-128": "AES-128",
    "aes256": "AES-256",
    "aes-256": "AES-256",
    "3des": "3DES",
    "des-ede3": "3DES",
    "rc4": "RC4",
    "md5": "MD5",
}


def normalize_algorithm(value: str) -> str:
    compact = re.sub(r"[_ ]+", "-", value.strip()).lower()
    if compact.startswith("diffie-hellman"):
        return "DH"
    return ALIASES.get(compact, value.strip().upper())


@dataclass(frozen=True)
class AlgorithmRegistry:
    version: str
    algorithms: dict[str, dict[str, Any]]

    @classmethod
    def load(cls, path: Path) -> AlgorithmRegistry:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return cls(version=str(raw["registry_version"]), algorithms=dict(raw["algorithms"]))

    def lookup(self, algorithm: str) -> dict[str, Any]:
        canonical = normalize_algorithm(algorithm)
        if canonical.startswith("LIBRARY-"):
            return {
                "family": "software-library",
                "use": "implementation",
                "status": "inventory-only",
                "quantum": "not-applicable",
                "base_risk": 5,
            }
        return self.algorithms.get(
            canonical,
            {
                "family": "unknown",
                "use": "unknown",
                "status": "unclassified",
                "quantum": "unknown",
                "base_risk": 45,
            },
        )
