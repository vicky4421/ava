# Author: Vivek Sawant
# Date: 09-10-2026

from rich.console import Console
from rich.table import Table

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

    table.add_column("Severity", justify="center", width=10)
    table.add_column("Type", width=16)
    table.add_column("Secret Snippet", width=20)
    table.add_column("Entropy", justify="right", width=9)
    table.add_column("Location", style="dim", width=28)
    table.add_column("Valid?", justify="center", width=8)
    table.add_column("Risk Summary")

    for finding in verified_secrets:
        sev = finding.get("severity", "INFO")
        sev_styled = f"[{SEVERITY_COLORS.get(sev, 'white')}]{sev}[/]"

        # Mask middle characters if candidate is long
        val = finding.get("candidate", "")
        masked_val = val if len(val) <= 16 else f"{val[:6]}...{val[-4:]}"

        # Color-code entropy: High entropy indicates true randomness
        entropy_val = finding.get("entropy", 0.0)
        if entropy_val >= 4.0:
            entropy_styled = f"[bold green]{entropy_val:.2f}[/]"
        elif entropy_val >= 3.0:
            entropy_styled = f"[yellow]{entropy_val:.2f}[/]"
        else:
            entropy_styled = f"[dim]{entropy_val:.2f}[/]"

        is_valid = finding.get("is_valid_secret", False)
        valid_styled = "[green]Yes[/green]" if is_valid else "[dim]No[/dim]"

        # Format locations: join multiple occurrences with newlines
        locs = finding.get("locations", [])
        loc_display = "\n".join(locs) if locs else "N/A"

        table.add_row(
            sev_styled,
            finding.get("secret_type", "Unknown"),
            masked_val,
            entropy_styled,
            loc_display,
            valid_styled,
            finding.get("risk_summary", ""),
        )

    console.print(table)
