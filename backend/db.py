"""GhostSim asynchronous database infrastructure.

Provides a managed SQLAlchemy async engine, request-scoped
sessions, and a real PostgreSQL connectivity check.

No database credentials are logged or returned to clients.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from functools import lru_cache

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.config import Settings, get_settings

logger = logging.getLogger("ghostsim.database")


@lru_cache(maxsize=1)
def get_engine() -> AsyncEngine:
    """Create and cache the asynchronous database engine.

    The engine is created only when database access is requested.
    Configuration errors are raised without logging credentials.
    """
    settings = get_settings()

    database_url = settings.get_database_url()

    return create_async_engine(
        database_url,
        echo=False,
        pool_pre_ping=True,
        pool_size=settings.database_pool_size,
        max_overflow=settings.database_max_overflow,
        pool_timeout=settings.database_pool_timeout_seconds,
        pool_recycle=1800,
        connect_args={
            "server_settings": {
                "application_name": "ghostsim-api",
            },
            "timeout": 10,
            "command_timeout": 15,
        },
    )


@lru_cache(maxsize=1)
def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Return the shared factory for request-scoped sessions."""
    return async_sessionmaker(
        bind=get_engine(),
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
        autocommit=False,
    )


async def get_db() -> AsyncIterator[AsyncSession]:
    """Yield a database session and always close it.

    Use this function as a FastAPI dependency.

    Transaction commits should be explicit in service functions.
    This dependency rolls back any unfinished transaction when
    an exception occurs.
    """
    session_factory = get_session_factory()

    async with session_factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


async def check_database_connection() -> bool:
    """Check actual PostgreSQL connectivity.

    Returns True only when PostgreSQL successfully executes
    a simple query. It does not merely check whether the
    engine object exists.

    Detailed exceptions are logged server-side without exposing
    database URLs, passwords, or query parameters.
    """
    try:
        engine = get_engine()

        async with engine.connect() as connection:
            result = await connection.execute(text("SELECT 1"))
            value = result.scalar_one()

            return value == 1

    except (SQLAlchemyError, OSError, TimeoutError, ValueError):
        logger.warning(
            "PostgreSQL connectivity check failed.",
            exc_info=False,
        )
        return False


async def close_database_connections() -> None:
    """Dispose of pooled database connections during shutdown."""
    engine = get_engine.cache_info()

    if engine.currsize == 0:
        return

    try:
        await get_engine().dispose()
    except Exception:
        logger.exception("Failed to dispose of database connections.")
        raise
    finally:
        get_session_factory.cache_clear()
        get_engine.cache_clear()


def get_database_settings() -> Settings:
    """Return validated application settings for database services."""
    return get_settings()
