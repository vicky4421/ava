# Author: Vivek Sawant
# Date: 09-10-2026

import os
import shutil
import sys
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import psycopg
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from psycopg import sql
from rich.console import Console
from rich.panel import Panel

from ava.config.logger import get_logger

logger = get_logger()
console = Console()

# Connection credentials
PG_HOST = os.getenv("PG_HOST", "localhost")
PG_PORT = int(os.getenv("PG_PORT", "5432"))
PG_USER = os.getenv("PG_USER", "postgres")
PG_PASSWORD = os.getenv("PG_PASSWORD", "postgres")
TARGET_DB = os.getenv("PG_DATABASE", "ava_db")

# Base connection to default maintenance database
MAINTENANCE_CONNINFO = (
    f"postgresql://{PG_USER}:{PG_PASSWORD}@{PG_HOST}:{PG_PORT}/postgres"
)
TARGET_DB_CONNINFO = (
    f"postgresql://{PG_USER}:{PG_PASSWORD}@{PG_HOST}:{PG_PORT}/{TARGET_DB}"
)


def verify_postgres_installed() -> None:
    """Check if PostgreSQL system binaries exist on the Linux host."""
    # Check for core server/client utilities
    has_psql = shutil.which("psql") is not None

    if not has_psql:
        console.print(
            Panel(
                "[bold red]PostgreSQL server is not installed on this system.[/bold red]\n\n"
                "AVA requires a local PostgreSQL instance for short-term memory and checkpointing.\n\n"
                "[bold cyan]Install and start it with:[/bold cyan]\n"
                "  1. [white]sudo apt update && sudo apt install -y postgresql postgresql-contrib[/white]\n"
                "  2. [white]sudo service postgresql start[/white]\n"
                "  3. [white]sudo -u postgres psql -c \"ALTER USER postgres PASSWORD 'postgres';\"[/white]",
                title="Missing Dependency: PostgreSQL",
                border_style="red",
            )
        )
        sys.exit(1)


async def ensure_database_exists() -> None:
    """Connect to the default 'postgres' database and create the target DB if missing."""
    try:
        async with await psycopg.AsyncConnection.connect(  # noqa: SIM117
            MAINTENANCE_CONNINFO, autocommit=True
        ) as conn:
            async with conn.cursor() as cur:
                # Check if target database already exists
                await cur.execute(
                    "SELECT 1 FROM pg_database WHERE datname = %s;",
                    (TARGET_DB,),
                )
                exists = await cur.fetchone()

                if not exists:
                    logger.info(
                        f"Database '{TARGET_DB}' not found. Creating it automatically..."
                    )
                    # Safe identifier formatting for SQL execution
                    await cur.execute(
                        sql.SQL("CREATE DATABASE {}").format(sql.Identifier(TARGET_DB))
                    )
                    logger.info(f"Database '{TARGET_DB}' created successfully.")

    except psycopg.OperationalError as e:
        logger.error(
            f"Failed to connect to local PostgreSQL service on {PG_HOST}:{PG_PORT}. "
            "Ensure the PostgreSQL service is active ('sudo service postgresql status')."
        )
        logger.error(f"PostgreSQL connection error: {e}")
        sys.exit(1)


@asynccontextmanager
async def get_checkpointer() -> AsyncGenerator[AsyncPostgresSaver, None]:  # noqa: UP043
    """Ensures database existence and yields a managed AsyncPostgresSaver."""
    await ensure_database_exists()

    async with AsyncPostgresSaver.from_conn_string(TARGET_DB_CONNINFO) as checkpointer:
        await checkpointer.setup()
        yield checkpointer
