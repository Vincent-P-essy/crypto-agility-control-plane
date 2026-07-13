"""Small atomic local artifact store for the control-plane demo."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from crypto_agility.util import atomic_json_write

SAFE_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9:._-]{7,160}$")


class ArtifactStore:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.root.chmod(0o700)

    def _path(self, kind: str, identifier: str) -> Path:
        if kind not in {"cbom", "benchmark"}:
            raise ValueError("unsupported artifact kind")
        if not SAFE_ID.fullmatch(identifier):
            raise ValueError("invalid artifact identifier")
        filename = identifier.replace(":", "_") + ".json"
        return self.root / kind / filename

    def put(self, kind: str, identifier: str, payload: dict[str, Any]) -> None:
        atomic_json_write(self._path(kind, identifier), payload)

    def get(self, kind: str, identifier: str) -> dict[str, Any] | None:
        path = self._path(kind, identifier)
        if not path.is_file():
            return None
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("stored artifact is not a JSON object")
        return value

    def list(self, kind: str) -> list[dict[str, Any]]:
        directory = self.root / kind
        if not directory.is_dir():
            return []
        result: list[dict[str, Any]] = []
        for path in sorted(directory.glob("*.json"), reverse=True):
            payload = json.loads(path.read_text(encoding="utf-8"))
            identifier = payload.get("document_id") or payload.get("report_id")
            result.append(
                {
                    "id": identifier,
                    "generated_at": payload.get("generated_at"),
                    "summary": payload.get("summary"),
                    "environment": payload.get("environment"),
                }
            )
        return result
