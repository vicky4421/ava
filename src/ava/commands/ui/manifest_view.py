# Author: Vivek Sawant
# Date: 09-10-2026

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


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
