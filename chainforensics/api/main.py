from __future__ import annotations

import logging

from pathlib import Path

from fastapi import Depends, FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from chainforensics.api.dependencies import get_db, require_api_key
from chainforensics.api.errors import (
    create_correlation_id,
    generic_error_response,
    generic_exception_handler,
)
from chainforensics.api.schemas import (
    BaseMetricsResponse,
    IncidentReplayResponse,
    TrafficDetectionRequest,
)
from chainforensics.database.repository import get_base_metrics
from chainforensics.api.dashboard import router as dashboard_router
from chainforensics.api.incidents import process_traffic_detection, router as incidents_router
from chainforensics.api.threats import router as threats_router
from chainforensics.api.prevention import router as prevention_router
from chainforensics.api.simulator import router as simulator_router


logging.basicConfig(
    level=logging.INFO,
    format=(
        "%(asctime)s | %(levelname)s | "
        "%(name)s | %(message)s"
    ),
)

logger = logging.getLogger("chainforensics.api")


app = FastAPI(
    title="ChainForensics API",
    description="Real-time AI blockchain forensic recovery API",
    version="1.0.0",
)


@app.middleware("http")
async def add_no_cache_headers(request: Request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/dashboard") or request.url.path in ("/", "/v2"):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


# ============================================================
# API ROUTERS
# ============================================================

app.include_router(dashboard_router)
app.include_router(incidents_router)
app.include_router(threats_router)
app.include_router(prevention_router)
app.include_router(simulator_router)

# Auto-initialize database tables on app startup
from chainforensics.database.database import init_db
init_db()

# Mount Unified Stable SOC Dashboard
dashboard_dir = Path(__file__).resolve().parent.parent.parent / "dashboard" / "v2"
if dashboard_dir.exists():
    app.mount("/dashboard", StaticFiles(directory=str(dashboard_dir), html=True), name="dashboard")
    app.mount("/dashboard/v2", StaticFiles(directory=str(dashboard_dir), html=True), name="dashboard_v2")

@app.get("/", include_in_schema=False)
def root_redirect() -> RedirectResponse:
    return RedirectResponse(url="/dashboard/")

@app.get("/v2", include_in_schema=False)
def v2_redirect() -> RedirectResponse:
    return RedirectResponse(url="/dashboard/")


# ============================================================
# GLOBAL ERROR HANDLERS
# ============================================================

@app.exception_handler(Exception)
async def handle_unexpected_exception(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    return await generic_exception_handler(
        request,
        exc,
    )


@app.exception_handler(RequestValidationError)
async def handle_validation_error(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    correlation_id = create_correlation_id()

    logger.warning(
        "Validation error | correlation_id=%s | "
        "method=%s | path=%s | detail=%s",
        correlation_id,
        request.method,
        request.url.path,
        exc.errors(),
    )

    return generic_error_response(
        status_code=422,
        correlation_id=correlation_id,
    )


# ============================================================
# PUBLIC HEALTH CHECK
# ============================================================

@app.get("/health")
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "ChainForensics API",
    }


# ============================================================
# PROTECTED HEALTH CHECK
# ============================================================

@app.get(
    "/protected-health",
    dependencies=[Depends(require_api_key)],
)
def protected_health() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "ChainForensics API",
        "authentication": "api-key",
    }


# ============================================================
# BASE FRAMEWORK METRICS (SPRINT 5 — S5-12)
# ============================================================

@app.get(
    "/metrics",
    response_model=BaseMetricsResponse,
    dependencies=[Depends(require_api_key)],
)
@app.get(
    "/metrics/base",
    response_model=BaseMetricsResponse,
    dependencies=[Depends(require_api_key)],
)
def metrics(
    db: Session = Depends(get_db),
) -> BaseMetricsResponse:
    """
    Return BASE framework metrics calculated from persisted incident history.
    """
    return BaseMetricsResponse(**get_base_metrics(db))


# ============================================================
# TRAFFIC DETECTION ENDPOINT (SPRINT 5)
# ============================================================

@app.post(
    "/detect",
    response_model=IncidentReplayResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_api_key)],
)
def detect_traffic(
    req: TrafficDetectionRequest,
    db: Session = Depends(get_db),
) -> IncidentReplayResponse:
    """
    Submit network traffic for real-time forensic detection, blockchain commitment,
    AI explanation, and SQLite persistence.
    """
    return process_traffic_detection(req, db)