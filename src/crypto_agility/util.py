"""Small deterministic and filesystem-safe helpers."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Mapping, Sequence
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(UTC)


def canonical_json(value: Any) -> bytes:
    """Serialize JSON deterministically for IDs and evidence hashes."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def stable_id(namespace: str, value: Any, length: int = 24) -> str:
    digest = hashlib.sha256(canonical_json(value)).hexdigest()
    return f"{namespace}-{digest[:length]}"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def redact_excerpt(value: str) -> str:
    """Return a non-reversible digest instead of sensitive configuration text."""
    normalized = " ".join(value.strip().split())
    return f"sha256:{sha256_hex(normalized.encode())}"


def atomic_json_write(path: Path, payload: Mapping[str, Any] | Sequence[Any]) -> None:
    """Write a JSON document atomically with owner-only permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        with suppress(FileNotFoundError):
            os.unlink(temporary)
        raise


def within_root(path: Path, root: Path) -> bool:
    """Return whether a resolved path is inside an allowed resolved root."""
    try:
        path.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (FileNotFoundError, ValueError):
        return False
    return True
