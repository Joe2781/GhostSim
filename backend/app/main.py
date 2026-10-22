"""GhostSim API application entry point."""

from future import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import get_settings
from app.db import (
check_database_connection,
close_database_connections,
)
from app.api.devices import router as devices_router
from app.api.auth import router as auth_router

settings = get_settings()

logging.basicConfig(
level=logging.INFO,
format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

logger = logging.getLogger("ghostsim.api")

@asynccontextmanager
async def lifespan(application: FastAPI):
"""Manage application startup and shutdown."""

logger.info(
    "Starting %s version %s",
    settings.app_name,
    settings.app_version,
)

application.state.started = True

try:
    yield
finally:
    application.state.started = False

    try:
        await close_database_connections()
    except Exception:
        logger.exception("Database connection cleanup failed.")

    logger.info("GhostSim API shutdown complete.")

app = FastAPI(
title=settings.app_name,
version=settings.app_version,
description=(
"GhostSim identity and connectivity platform API."
),
debug=settings.debug,
lifespan=lifespan,
docs_url=(
"/docs"
if settings.environment != "production"
else None
),
redoc_url=(
"/redoc"
if settings.environment != "production"
else None
),
openapi_url=(
"/openapi.json"
if settings.environment != "production"
else None
),
)

Register the device management API.

app.include_router(devices_router)
app.include_router(auth_router)

if settings.cors_origins:
app.add_middleware(
CORSMiddleware,
allow_origins=settings.cors_origins,
allow_credentials=True,
allow_methods=[
"GET",
"POST",
"PUT",
"PATCH",
"DELETE",
"OPTIONS",
],
allow_headers=[
"Authorization",
"Content-Type",
"Idempotency-Key",
],
max_age=600,
)

@app.middleware("http")
async def add_security_headers(
request: Request,
call_next,
) -> Response:
"""Add basic browser security headers to API responses."""

response = await call_next(request)

response.headers["X-Content-Type-Options"] = "nosniff"
response.headers["X-Frame-Options"] = "DENY"
response.headers["Referrer-Policy"] = "no-referrer"
response.headers["Cache-Control"] = "no-store"

if settings.environment == "production":
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains"
    )

return response

@app.exception_handler(Exception)
async def handle_unexpected_exception(
request: Request,
exc: Exception,
) -> JSONResponse:
"""Return a generic response for unexpected server errors.

Detailed exception information is retained in server logs,
never returned to the client.
"""

logger.error(
    "Unhandled application error on %s %s",
    request.method,
    request.url.path,
    exc_info=(
        type(exc),
        exc,
        exc.__traceback__,
    ),
)

return JSONResponse(
    status_code=500,
    content={
        "error": {
            "code": "INTERNAL_SERVER_ERROR",
            "message": (
                "The server could not complete the request."
            ),
        }
    },
)

@app.get("/", tags=["system"])
async def root() -> dict[str, Any]:
"""Return basic API identity information."""

return {
    "service": "GhostSim",
    "version": settings.app_version,
    "status": "running",
}

@app.get("/health/live", tags=["health"])
async def liveness() -> dict[str, str]:
"""Confirm that the application process is responding.

This endpoint does not claim that the database or other
dependencies are healthy.
"""

return {
    "status": "alive",
}

@app.get("/health/ready", tags=["health"])
async def readiness() -> JSONResponse:
"""Report whether the API can currently reach PostgreSQL."""

database_ready = await check_database_connection()

if database_ready:
    return JSONResponse(
        status_code=200,
        content={
            "status": "ready",
            "checks": {
                "database": "available",
            },
        },
    )

return JSONResponse(
    status_code=503,
    content={
        "status": "not_ready",
        "checks": {
            "database": "unavailable",
        },
    },
)
