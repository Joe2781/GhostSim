"""Async PostgreSQL connection and session management for GhostSim."""

from __future__ import annotations

import logging
from functools import lru_cache
from typing import AsyncIterator

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.config import get_settings

logger = logging.getLogger("ghostsim.database")


@lru_cache(maxsize=1)
def get_engine():
    """Create one pooled async SQLAlchemy engine per process."""
    settings = get_settings()

    return create_async_engine(
        settings.get_database_url(),
        pool_pre_ping=True,
        pool_size=settings.database_pool_size,
        max_overflow=settings.database_max_overflow,
        pool_timeout=settings.database_pool_timeout_seconds,
        pool_recycle=1800,
        echo=(
            settings.debug
            and settings.environment != "production"
        ),
    )


@lru_cache(maxsize=1)
def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Return the shared factory used to create database sessions."""
    return async_sessionmaker(
        bind=get_engine(),
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
        autocommit=False,
    )


async def get_db() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency that safely scopes a database session."""
    session_factory = get_session_factory()

    async with session_factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


async def check_database_connection() -> bool:
    """Return true only when PostgreSQL responds to a real query."""
    try:
        async with get_engine().connect() as connection:
            await connection.execute(text("SELECT 1"))

        return True

    except SQLAlchemyError as exc:
        # Do not expose database URLs or credentials to API callers.
        logger.warning(
            "Database readiness check failed (%s).",
            type(exc).__name__,
        )
        return False


async def close_database_connections() -> None:
    """Dispose the connection pool during application shutdown."""
    engine = get_engine()

    try:
        await engine.dispose()
    finally:
        get_session_factory.cache_clear()
        get_engine.cache_clear()
