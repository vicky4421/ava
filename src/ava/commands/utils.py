from rich.console import Console
from rich.panel import Panel
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


def render_manifest_tables(manifest_data: dict) -> None:
    if not manifest_data:
        console.print("[dim]No manifest data available.[/dim]")
        return

    # 1. Hygiene & Config Panel
    pkg = manifest_data.get("package_name", "Unknown")
    target_sdk = manifest_data.get("target_sdk", "N/A")

    debuggable = manifest_data.get("debuggable", False)
    debug_str = (
        "[bold red]ENABLED (Vulnerable)[/]" if debuggable else "[green]Disabled[/]"
    )

    backup = manifest_data.get("allow_backup", True)
    backup_str = "[yellow]True (Default)[/]" if backup else "[green]False[/]"

    summary_text = (
        f"[bold cyan]Package:[/] {pkg}  |  "
        f"[bold cyan]Target SDK:[/] {target_sdk}\n"
        f"[bold cyan]Debuggable:[/] {debug_str}  |  "
        f"[bold cyan]Allow Backup:[/] {backup_str}"
    )
    console.print(Panel(summary_text, title="Manifest Hygiene", border_style="cyan"))

    # 2. All Discovered Components (Sources + Internal Sinks)
    entry_points = manifest_data.get("entry_points", [])
    if not entry_points:
        console.print("[green][✓][/green] No entry points found in manifest.")
        return

    table = Table(
        title="Discovered Components & Attack Surface",
        show_header=True,
        header_style="bold blue",
        expand=True,
    )

    table.add_column("Type", width=12)
    table.add_column("Component Name", ratio=3)
    table.add_column("Exported", justify="center", width=10)
    table.add_column("Permission", width=22)
    table.add_column("Intent Filters", ratio=2)

    type_colors = {
        "activity": "magenta",
        "service": "cyan",
        "receiver": "yellow",
        "provider": "blue",
    }

    # Sort: Exported components first (sources), then unexported (internal sinks)
    sorted_components = sorted(
        entry_points,
        key=lambda x: (not x.get("exported", False), x.get("name", "")),
    )

    for comp in sorted_components:
        ctype = comp.get("component_type", "unknown")
        ctype_styled = f"[{type_colors.get(ctype, 'white')}]{ctype.capitalize()}[/]"

        name = comp.get("name", "")
        # Shorten package namespace for cleaner layout
        if name.startswith(pkg):
            short_name = name[len(pkg) :]
        else:
            short_name = name

        is_exported = comp.get("exported", False)
        if is_exported:
            # High-visibility row for entry points
            comp_name_styled = f"[bold white]{short_name}[/]"
            exported_styled = "[bold red]Yes[/]"
        else:
            # Dimmed row for internal sinks
            comp_name_styled = f"[dim]{short_name}[/]"
            exported_styled = "[dim]No[/]"

        perm = comp.get("permission")
        perm_styled = (
            f"[green]{perm.split('.')[-1]}[/]" if perm else "[dim red]None[/dim red]"
        )

        filters = comp.get("intent_filters", [])
        filters_styled = (
            "\n".join([f.split(".")[-1] for f in filters])
            if filters
            else "[dim]None[/dim]"
        )

        table.add_row(
            ctype_styled,
            comp_name_styled,
            exported_styled,
            perm_styled,
            filters_styled,
        )

    console.print(table)
