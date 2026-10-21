"""Apply GhostSim PostgreSQL migrations safely and in order.

Run from the backend directory:

    python -m scripts.migrate

The runner:
- Discovers numbered SQL migrations.
- Applies migrations in filename order.
- Records successful migrations and SHA-256 checksums.
- Runs each migration and its tracking insert atomically.
- Refuses to silently accept a modified applied migration.
- Uses a PostgreSQL advisory lock to prevent concurrent runners.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import sys
from pathlib import Path

import asyncpg

# Make the backend package importable when this file is executed
# directly as well as through `python -m scripts.migrate`.
BACKEND_DIR = Path(__file__).resolve().parents[1]
REPOSITORY_DIR = BACKEND_DIR.parent

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.config import get_settings  # noqa: E402


LOGGER = logging.getLogger("ghostsim.migrations")

MIGRATIONS_DIR = REPOSITORY_DIR / "db" / "migrations"

MIGRATION_NAME_PATTERN = re.compile(
    r"^\d{3}_[a-z0-9_]+\.sql$"
)

# A fixed, application-specific lock pair.
# Other applications should use a different pair.
ADVISORY_LOCK_KEY_1 = 731902441
ADVISORY_LOCK_KEY_2 = 1145131603


class MigrationError(Exception):
    """Raised when a database migration cannot be applied safely."""


def get_database_dsn() -> str:
    """Get the configured PostgreSQL DSN without logging credentials."""
    settings = get_settings()
    dsn = settings.get_database_url()

    # asyncpg expects a PostgreSQL URL, not SQLAlchemy's dialect name.
    if dsn.startswith("postgresql+asyncpg://"):
        dsn = dsn.replace(
            "postgresql+asyncpg://",
            "postgresql://",
            1,
        )

    if not dsn.startswith("postgresql://"):
        raise MigrationError(
            "The configured database URL is not a supported "
            "PostgreSQL DSN."
        )

    return dsn


def discover_migrations() -> list[Path]:
    """Find valid SQL migrations and return them in execution order."""
    if not MIGRATIONS_DIR.is_dir():
        raise MigrationError(
            f"Migration directory does not exist: {MIGRATIONS_DIR}"
        )

    migrations = sorted(
        path
        for path in MIGRATIONS_DIR.iterdir()
        if path.is_file()
        and MIGRATION_NAME_PATTERN.fullmatch(path.name)
    )

    if not migrations:
        raise MigrationError(
            f"No numbered SQL migrations found in {MIGRATIONS_DIR}."
        )

    # Reject duplicate numeric prefixes such as 001_a.sql and 001_b.sql.
    prefixes: dict[str, str] = {}

    for path in migrations:
        prefix = path.name.split("_", maxsplit=1)[0]

        if prefix in prefixes:
            raise MigrationError(
                "Duplicate migration sequence number "
                f"{prefix}: {prefixes[prefix]} and {path.name}"
            )

        prefixes[prefix] = path.name

    return migrations


def read_migration(path: Path) -> tuple[str, str]:
    """Read a migration and return its SQL and SHA-256 checksum."""
    try:
        raw_sql = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise MigrationError(
            f"Could not read migration {path.name}."
        ) from exc

    if not raw_sql.strip():
        raise MigrationError(
            f"Migration {path.name} is empty."
        )

    checksum = hashlib.sha256(
        raw_sql.encode("utf-8")
    ).hexdigest()

    # These files currently manage their own transactions.
    # Remove only the outer transaction statements so the runner
    # can commit the schema changes and tracking row atomically.
    sql = re.sub(
        r"\A\s*BEGIN\s*;\s*",
        "",
        raw_sql,
        count=1,
        flags=re.IGNORECASE,
    )

    sql = re.sub(
        r"\s*COMMIT\s*;\s*\Z",
        "",
        sql,
        count=1,
        flags=re.IGNORECASE,
    )

    if not sql.strip():
        raise MigrationError(
            f"Migration {path.name} has no SQL after "
            "transaction markers were removed."
        )

    return sql, checksum


async def ensure_tracking_table(
    connection: asyncpg.Connection,
) -> None:
    """Create the migration history table if it does not exist."""
    await connection.execute(
        """
        CREATE TABLE IF NOT EXISTS public.ghostsim_schema_migrations (
            migration_name TEXT PRIMARY KEY,
            checksum_sha256 CHAR(64) NOT NULL,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """
    )


async def apply_migrations() -> None:
    """Apply pending migrations in order using real PostgreSQL."""
    migrations = discover_migrations()
    dsn = get_database_dsn()

    LOGGER.info(
        "Found %d migration file(s).",
        len(migrations),
    )

    connection: asyncpg.Connection | None = None
    lock_acquired = False

    try:
        connection = await asyncpg.connect(
            dsn=dsn,
            timeout=15,
            command_timeout=120,
        )

        # Ensure two deployments cannot apply migrations at once.
        await connection.execute(
            "SELECT pg_advisory_lock($1, $2)",
            ADVISORY_LOCK_KEY_1,
            ADVISORY_LOCK_KEY_2,
        )
        lock_acquired = True

        await ensure_tracking_table(connection)

        applied_rows = await connection.fetch(
            """
            SELECT migration_name, checksum_sha256
            FROM public.ghostsim_schema_migrations
            """
        )

        applied = {
            row["migration_name"]: row["checksum_sha256"].strip()
            for row in applied_rows
        }

        applied_count = 0

        for path in migrations:
            sql, checksum = read_migration(path)
            previous_checksum = applied.get(path.name)

            if previous_checksum is not None:
                if previous_checksum != checksum:
                    raise MigrationError(
                        f"Applied migration {path.name} has changed. "
                        "Do not edit an applied migration silently. "
                        "Review the database and create a new "
                        "numbered migration for the correction."
                    )

                LOGGER.info(
                    "Already applied: %s",
                    path.name,
                )
                continue

            LOGGER.info(
                "Applying migration: %s",
                path.name,
            )

            # The SQL and tracking row are committed together.
            # If execution fails, PostgreSQL rolls both back.
            async with connection.transaction():
                await connection.execute(sql)

                await connection.execute(
                    """
                    INSERT INTO public.ghostsim_schema_migrations (
                        migration_name,
                        checksum_sha256
                    )
                    VALUES ($1, $2)
                    """,
                    path.name,
                    checksum,
                )

            applied_count += 1

            LOGGER.info(
                "Successfully applied: %s",
                path.name,
            )

        LOGGER.info(
            "Migration run completed. Newly applied: %d; "
            "discovered: %d.",
            applied_count,
            len(migrations),
        )

    except MigrationError:
        raise

    except (OSError, asyncpg.PostgresError, TimeoutError) as exc:
        # Avoid printing the DSN or credentials in error messages.
        raise MigrationError(
            "Migration execution failed. Check PostgreSQL "
            "availability, database permissions, and the server "
            f"logs. Error type: {type(exc).__name__}."
        ) from exc

    finally:
        if connection is not None:
            if lock_acquired:
                try:
                    await connection.execute(
                        "SELECT pg_advisory_unlock($1, $2)",
                        ADVISORY_LOCK_KEY_1,
                        ADVISORY_LOCK_KEY_2,
                    )
                except asyncpg.PostgresError:
                    LOGGER.warning(
                        "Could not explicitly release the migration "
                        "lock; PostgreSQL releases session locks "
                        "when the connection closes."
                    )

            await connection.close()


def main() -> int:
    """Command-line entry point."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    try:
        asyncio.run(apply_migrations())
        return 0

    except MigrationError as exc:
        LOGGER.error("%s", exc)
        return 1

    except KeyboardInterrupt:
        LOGGER.error("Migration execution interrupted.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
