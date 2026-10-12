# Author: Vivek Sawant
# Date: 09-10-2026


from rich.console import Console
from rich.panel import Panel

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
        "[bold bright_red]ENABLED (Vulnerable)[/]"
        if debuggable
        else "[green]Disabled[/]"
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

    # 2. Attack Surface & Component Metrics Aggregation
    entry_points = manifest_data.get("entry_points", [])
    permissions = (
        manifest_data.get("permissions") or manifest_data.get("uses_permissions") or []
    )

    total_components = len(entry_points)
    exported_components = [c for c in entry_points if c.get("exported", False)]
    total_exported = len(exported_components)

    # Breakdown by component category : component_type: [no. of total_components, no. of exported_components]
    breakdown = {
        "activity": [0, 0],
        "service": [0, 0],
        "receiver": [0, 0],
        "provider": [0, 0],
    }
    filter_count = 0

    for comp in entry_points:
        c_type = comp.get("component_type", "").lower()
        is_exported = comp.get("exported", False)
        filters = comp.get("intent_filters", [])

        if filters:
            filter_count += len(filters)

        if c_type in breakdown:
            breakdown[c_type][0] += 1  # Total count
            if is_exported:
                breakdown[c_type][1] += 1  # Exported count

    # Formatted component string
    comp_parts = []
    type_meta = {
        "activity": ("magenta", "Activities"),
        "service": ("cyan", "Services"),
        "receiver": ("yellow", "Receivers"),
        "provider": ("bright_blue", "Providers"),  # Changed from standard 'blue'
    }

    comp_parts = []
    for ctype, (tot, exp) in breakdown.items():
        if tot > 0:
            color, label = type_meta.get(ctype, ("white", f"{ctype.capitalize()}s"))
            exp_str = f"[bold bright_red]{exp}[/]" if exp > 0 else "[bold green]0[/]"
            comp_parts.append(f"[{color}]{label}:[/] {tot} ({exp_str} exported)")

    comp_summary_line = (
        "  |  ".join(comp_parts) if comp_parts else "[dim]None discovered[/dim]"
    )

    exported_highlight = (
        f"[bold bright_red]{total_exported} Exported[/]"
        if total_exported > 0
        else "[green]0 Exported[/]"
    )

    # Permission summary formatting
    perm_count = len(permissions)
    if perm_count > 0:
        # Show shortened permission names (last token), top 5 preview
        short_perms = [p.split(".")[-1] for p in permissions[:5]]
        perm_preview = ", ".join(short_perms)
        if perm_count > 5:
            perm_preview += f" [dim](+{perm_count - 5} more)[/dim]"
        perm_line = f"[bold white]{perm_count}[/] total → [dim]{perm_preview}[/dim]"
    else:
        perm_line = "[green]None declared[/green]"

    surface_summary_text = (
        f"[bold cyan]Total Attack Surface:[/] {total_components} Components ({exported_highlight})  |  "
        f"[bold cyan]Intent Filters:[/] {filter_count}\n"
        f"[bold cyan]Components Breakdown:[/] {comp_summary_line}\n"
        f"[bold cyan]Permissions:[/] {perm_line}"
    )

    console.print(
        Panel(
            surface_summary_text,
            title="Attack Surface Summary",
            border_style="yellow" if total_exported > 0 else "green",
        )
    )
