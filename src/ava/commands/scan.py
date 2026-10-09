import sys
from pathlib import Path

from ava.agent.graph import app
from ava.commands.ui.manifest_view import render_manifest_tables
from ava.commands.ui.secrets_view import render_secrets_table
from ava.config.logger import get_logger

logger = get_logger()


async def run_scan(target: Path):
    """Validates the input APK and streams the agent workflow."""

    apk_path = target.resolve()

    if not apk_path.exists():
        logger.error(msg=f"Target path does not exist: {apk_path}")
        sys.exit(1)

    if apk_path.suffix.lower() != ".apk":
        logger.error(msg="Target file must have a .apk extension.")
        sys.exit(1)

    logger.info(f"Initializing analysis for: {apk_path}")

    try:
        result = await app.ainvoke(
            {
                "target_apk": str(apk_path),
                "messages": [],
                "secret_candidates": [],
                "verified_secrets": [],
                "decompiled_path": "",
                "manifest_analysis": {},
            }
        )
        # render_secrets_table(verified_secrets=result["verified_secrets"])
        # 1. Print Secrets Table (if any)
        if "verified_secrets" in result:
            render_secrets_table(result["verified_secrets"])

        # 2. Print Manifest Table
        if "manifest_analysis" in result:
            render_manifest_tables(result["manifest_analysis"])

    except Exception:
        logger.exception("Error executing agent workflow")
        sys.exit(1)
