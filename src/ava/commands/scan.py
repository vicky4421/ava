import sys
from pathlib import Path

from ava.agent.graph import app
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
        app.invoke({"target_apk": str(apk_path), "messages": []})
    except Exception:
        logger.exception("Error executing agent workflow")
        sys.exit(1)
