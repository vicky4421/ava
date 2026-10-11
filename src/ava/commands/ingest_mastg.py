# Author: Vivek Sawant
# Date: 11-10-2026

import sys
from pathlib import Path

from rich.console import Console

from ava.config.logger import get_logger
from ava.rag.store import ingest_mastg_to_chroma

logger = get_logger()
console = Console()


def handle_ingest_mastg(path: Path, force: bool = False) -> None:
    """Validates the MASTG path and triggers the Chroma indexing pipeline."""

    repo_path = path.resolve()

    if not repo_path.exists():
        console.print(
            f"[bold red]MASTG directory not found:[/bold red] {repo_path}\n"
            "Please verify the clone path or provide [bold cyan]--path <dir>[/bold cyan]."
        )
        sys.exit(1)

    logger.info(f"Starting MASTG ingestion from: {repo_path} (force={force})")
    ingest_mastg_to_chroma(repo_path=repo_path, force=force)
