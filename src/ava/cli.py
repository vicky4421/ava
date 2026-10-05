import argparse
import asyncio
import sys
from pathlib import Path

from ava.agent.graph import app
from ava.banner import print_ava_banner
from ava.config.logger import get_logger

logger = get_logger()

# ---------------------------------------------------------------------------------------------------
# func: build_parser
# ---------------------------------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Builds and returns the command line argument parser."""

    parser = argparse.ArgumentParser(
        prog="ava",
        description="AVA - Autonomous Vulnerability Analyzer for Android APKs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Subcommands pattern: allows `ava scan <path>` now, and future commands like `ava rag`, `ava report`
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # --- Command: scan ---
    scan_parser = subparsers.add_parser(
        name="scan", help="Decompile and analyze a target APK"
    )
    scan_parser.add_argument("target", type=Path, help="Path to the target .apk file")

    return parser


# ---------------------------------------------------------------------------------------------------
# func: run_scan
# ---------------------------------------------------------------------------------------------------
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


async def async_main():
    parser = build_parser()
    args = parser.parse_args()
    print_ava_banner(target_apk=str(args.target))

    if args.command == "scan":
        await run_scan(target=args.target)
    else:
        parser.print_help()
        sys.exit(0)


def main():
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        logger.error("Analysis aborted by user.")
        sys.exit(130)


if __name__ == "__main__":
    main()
