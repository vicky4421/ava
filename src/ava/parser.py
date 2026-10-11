import argparse
from pathlib import Path

from ava.rag.parser import DEFAULT_MASTG_PATH


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
    scan_parser.add_argument(
        "--fresh",
        action="store_true",
        default=False,
        help="Ignore cached PostgreSQL checkpoints and force a full re-scan",
    )

    # --- Command: logs ---
    logs_parser = subparsers.add_parser(
        name="logs", help="Inspect or clear application logs."
    )
    logs_parser.add_argument(
        "-n",
        "--lines",
        type=int,
        default=50,
        help="Number of lines to display from the end (default: 50)",
    )

    logs_parser.add_argument(
        "--clear",
        action="store_true",
        help="Clear the current log file",
    )
    logs_parser.add_argument(
        "--path",
        action="store_true",
        help="Print the absolute path to the log file",
    )

    # --- Command: ingest_mastg ---
    ingest_mastg_parser = subparsers.add_parser(
        "ingest-mastg",
        help="Ingest and index OWASP MASTG v2 documentation and rules into Chroma",
    )
    ingest_mastg_parser.add_argument(
        "--path",
        type=Path,
        default=DEFAULT_MASTG_PATH,
        help="Path to cloned mastg repository (default: MASTG_PATH or ~/mastg_docs/mastg)",
    )
    ingest_mastg_parser.add_argument(
        "--force",
        action="store_true",
        default=False,
        help="Overwrite existing Chroma collection if already populated",
    )

    return parser
