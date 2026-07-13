from __future__ import annotations

from pathlib import Path

import pytest

from crypto_agility.storage import ArtifactStore


def test_artifact_store_uses_atomic_private_json(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "state")
    identifier = "urn:cbom:sha256:" + "a" * 64
    store.put("cbom", identifier, {"document_id": identifier, "summary": {"finding_count": 1}})
    assert store.get("cbom", identifier) == {
        "document_id": identifier,
        "summary": {"finding_count": 1},
    }
    path = next((tmp_path / "state" / "cbom").glob("*.json"))
    assert path.stat().st_mode & 0o777 == 0o600


def test_artifact_store_rejects_path_traversal(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "state")
    with pytest.raises(ValueError, match="identifier"):
        store.get("cbom", "../../etc/passwd")
