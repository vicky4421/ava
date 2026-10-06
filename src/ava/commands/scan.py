import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

from ava.agent.graph import app
from ava.config.logger import get_logger

logger = get_logger()
console = Console()


SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim",
}


def render_secrets_table(verified_secrets: list[dict]):
    if not verified_secrets:
        console.print("[green][✓][/green] No suspicious hardcoded secrets confirmed.")
        return

    table = Table(
        title="Verified Secret Findings",
        show_header=True,
        header_style="bold magenta",
        expand=True,
    )

    table.add_column("Severity", justify="center", width=12)
    table.add_column("Type", width=18)
    table.add_column("Secret Snippet", width=26)
    table.add_column("Location", style="dim", width=32)
    table.add_column("Valid?", justify="center", width=8)
    table.add_column("Risk Summary")

    for finding in verified_secrets:
        sev = finding.get("severity", "INFO")
        sev_styled = f"[{SEVERITY_COLORS.get(sev, 'white')}]{sev}[/]"

        # Mask middle characters if candidate is long
        val = finding.get("candidate", "")
        masked_val = val if len(val) <= 16 else f"{val[:6]}...{val[-4:]}"

        is_valid = finding.get("is_valid_secret", False)
        valid_styled = "[green]Yes[/green]" if is_valid else "[dim]No[/dim]"

        # Format locations: join multiple occurrences with newlines
        locs = finding.get("locations", [])
        loc_display = "\n".join(locs) if locs else "N/A"

        table.add_row(
            sev_styled,
            finding.get("secret_type", "Unknown"),
            masked_val,
            loc_display,
            valid_styled,
            finding.get("risk_summary", ""),
        )

    console.print(table)


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
            }
        )
        render_secrets_table(verified_secrets=result["verified_secrets"])
    except Exception:
        logger.exception("Error executing agent workflow")
        sys.exit(1)
