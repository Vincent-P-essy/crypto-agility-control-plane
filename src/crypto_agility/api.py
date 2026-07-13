"""Local-first FastAPI control plane with constrained filesystem scans."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi import Path as APIPath
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from crypto_agility.benchmark import run_benchmark
from crypto_agility.cbom import build_cbom
from crypto_agility.errors import BenchmarkUnavailable, CryptoAgilityError
from crypto_agility.inventory import InventoryScanner, ScanOptions
from crypto_agility.paths import algorithm_registry_path, risk_policy_path
from crypto_agility.registry import AlgorithmRegistry
from crypto_agility.risk import RiskPolicy
from crypto_agility.storage import ArtifactStore
from crypto_agility.util import within_root


@dataclass(frozen=True)
class APISettings:
    state_directory: Path
    allowed_roots: tuple[Path, ...]
    oqs_install_path: Path | None = None

    @classmethod
    def from_environment(cls) -> APISettings:
        default_fixture = Path(__file__).resolve().parents[2] / "fixtures"
        raw_roots = os.environ.get("CAP_ALLOWED_ROOTS", str(default_fixture))
        roots = tuple(Path(item).resolve() for item in raw_roots.split(os.pathsep) if item)
        oqs = os.environ.get("OQS_INSTALL_PATH")
        return cls(
            state_directory=Path(os.environ.get("CAP_STATE_DIR", ".state")).resolve(),
            allowed_roots=roots,
            oqs_install_path=Path(oqs).resolve() if oqs else None,
        )


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    local_path: str
    source_label: str = Field(default="api-scan", min_length=1, max_length=80)
    confidentiality_years: int = Field(default=5, ge=0, le=100)
    exposure: Literal["local", "internal", "partner", "internet"] = "internal"


class BenchmarkRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    iterations: int = Field(default=25, ge=3, le=500)


def create_app(settings: APISettings | None = None) -> FastAPI:
    configured = settings or APISettings.from_environment()
    store = ArtifactStore(configured.state_directory)
    registry = AlgorithmRegistry.load(algorithm_registry_path())
    policy = RiskPolicy.load(risk_policy_path())
    static_directory = Path(__file__).with_name("static")
    counters = {"scans": 0, "benchmarks": 0, "errors": 0}
    app = FastAPI(
        title="Crypto Agility Control Plane",
        version="0.1.0",
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
    app.mount("/static", StaticFiles(directory=static_directory), name="static")

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Any) -> Any:
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response

    @app.exception_handler(CryptoAgilityError)
    async def domain_error(_request: Request, exc: CryptoAgilityError) -> PlainTextResponse:
        counters["errors"] += 1
        status = 409 if isinstance(exc, BenchmarkUnavailable) else 400
        return PlainTextResponse(str(exc), status_code=status)

    @app.get("/", include_in_schema=False)
    def dashboard() -> FileResponse:
        return FileResponse(static_directory / "index.html")

    @app.get("/healthz")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "registry_version": registry.version,
            "policy_version": policy.version,
            "allowed_root_count": len(configured.allowed_roots),
        }

    @app.get("/metrics", response_class=PlainTextResponse)
    def metrics() -> str:
        return "".join(
            f"crypto_agility_{name}_total {value}\n" for name, value in sorted(counters.items())
        )

    @app.get("/api/v1/algorithms")
    def algorithms() -> dict[str, Any]:
        return {"registry_version": registry.version, "algorithms": registry.algorithms}

    @app.get("/api/v1/cboms")
    def list_cboms() -> list[dict[str, Any]]:
        return store.list("cbom")

    @app.get("/api/v1/cboms/{identifier}")
    def get_cbom(
        identifier: Annotated[str, APIPath(min_length=8, max_length=160)],
    ) -> dict[str, Any]:
        try:
            payload = store.get("cbom", identifier)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if payload is None:
            raise HTTPException(status_code=404, detail="CBOM not found")
        return payload

    @app.post("/api/v1/scans", status_code=201)
    def scan(request: ScanRequest) -> dict[str, Any]:
        target = Path(request.local_path)
        if not target.is_absolute():
            raise HTTPException(status_code=400, detail="local_path must be absolute")
        if not any(within_root(target, root) for root in configured.allowed_roots):
            raise HTTPException(status_code=403, detail="scan target is outside CAP_ALLOWED_ROOTS")
        findings = InventoryScanner(
            ScanOptions(
                root=target,
                confidentiality_years=request.confidentiality_years,
                exposure=request.exposure,
            )
        ).scan()
        cbom = build_cbom(
            findings,
            source={"type": "local-tree", "label": request.source_label},
            registry=registry,
            policy=policy,
        )
        payload = cbom.model_dump(mode="json")
        store.put("cbom", cbom.document_id, payload)
        counters["scans"] += 1
        return payload

    @app.get("/api/v1/benchmarks")
    def list_benchmarks() -> list[dict[str, Any]]:
        return store.list("benchmark")

    @app.get("/api/v1/benchmarks/{identifier}")
    def get_benchmark(
        identifier: Annotated[str, APIPath(min_length=8, max_length=160)],
    ) -> dict[str, Any]:
        try:
            payload = store.get("benchmark", identifier)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if payload is None:
            raise HTTPException(status_code=404, detail="benchmark not found")
        return payload

    @app.post("/api/v1/benchmarks", status_code=201)
    async def benchmark(request: BenchmarkRequest) -> dict[str, Any]:
        report = await run_in_threadpool(
            run_benchmark, request.iterations, configured.oqs_install_path
        )
        payload = report.model_dump(mode="json")
        store.put("benchmark", report.report_id, payload)
        counters["benchmarks"] += 1
        return payload

    return app
