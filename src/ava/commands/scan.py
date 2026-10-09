import sys
from pathlib import Path

from langchain_core.runnables import RunnableConfig

from ava.agent.graph import build_app
from ava.agent.state import AgentState
from ava.commands.ui.manifest_view import render_manifest_tables
from ava.commands.ui.secrets_view import render_secrets_table
from ava.commands.utils import get_apk_fingerprint
from ava.config.database import get_checkpointer
from ava.config.logger import get_logger

logger = get_logger()


async def run_scan(target: Path, fresh: bool = False):
    """Validates the input APK and streams the agent workflow."""

    apk_path = target.resolve()

    if not apk_path.exists():
        logger.error(msg=f"Target path does not exist: {apk_path}")
        sys.exit(1)

    if apk_path.suffix.lower() != ".apk":
        logger.error(msg="Target file must have a .apk extension.")
        sys.exit(1)

    thread_id = get_apk_fingerprint(apk_path)
    config: RunnableConfig = {"configurable": {"thread_id": thread_id}}

    logger.info(f"Initializing analysis for: {apk_path}")

    # Automatically bootstraps the DB & setup tables on first run
    async with get_checkpointer() as checkpointer:
        app = build_app(checkpointer=checkpointer)

        existing_state = await app.aget_state(config=config) if not fresh else None

        # Resume if a previous checkpoint exists, otherwise start fresh
        # If fresh is True or no prior checkpoint exists, initialize full state
        inputs: AgentState | None = (
            None
            if existing_state and existing_state.values
            else {
                "target_apk": str(apk_path),
                "messages": [],
                "secret_candidates": [],
                "verified_secrets": [],
                "decompiled_path": "",
                "manifest_analysis": {},
            }
        )

        try:
            result = await app.ainvoke(input=inputs, config=config)

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
