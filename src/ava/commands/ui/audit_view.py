# Author: Vivek Sawant
# Date: 13-10-2026

from rich.console import Console, Group
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from ava.agent.schemas.audit import (
    LeadAuditResult,
    ReachabilityStatus,
    SeverityLevel,
    TriageVerdict,
)

SEVERITY_STYLES = {
    SeverityLevel.CRITICAL: "bold bright_red",
    SeverityLevel.HIGH: "bright_red",
    SeverityLevel.MEDIUM: "yellow",
    SeverityLevel.LOW: "blue",
    SeverityLevel.INFO: "dim cyan",
}

REACHABILITY_STYLES = {
    ReachabilityStatus.DIRECTLY_EXPOSED: "bold bright_red",
    ReachabilityStatus.INTERNALLY_REACHABLE: "yellow",
    ReachabilityStatus.UNREACHABLE: "dim green",
    ReachabilityStatus.INDETERMINATE: "dim",
}

VERDICT_STYLES = {
    TriageVerdict.VULNERABLE: "bold bright_red",
    TriageVerdict.SUSPICIOUS: "bold yellow",
    TriageVerdict.FALSE_POSITIVE: "dim green",
}


def render_audit_summary_table(
    results: list[LeadAuditResult], console: Console
) -> None:
    """Renders an executive summary table across all investigated leads."""

    if not results:
        console.print("[dim yellow]No audit findings to display.[/]")
        return

    table = Table(
        title="Vulnerability Audit Findings",
        show_header=True,
        header_style="bold magenta",
        expand=True,
    )

    table.add_column("Rule ID", style="cyan", width=14, no_wrap=True)
    table.add_column("Target (Class::Method)", style="white")
    table.add_column("CWE", style="dim", width=12)
    table.add_column("Verdict", justify="center", width=14)
    table.add_column("Severity", justify="center", width=10)
    table.add_column("Confidence", justify="right", width=12)

    for res in results:
        v_style = VERDICT_STYLES.get(res.verdict, "white")
        s_style = SEVERITY_STYLES.get(res.severity, "white")
        cwe_display = res.cwe_id.split(":")[0] if res.cwe_id else "N/A"

        table.add_row(
            res.rule_id,
            f"{res.class_name}::{res.method_name}",
            cwe_display,
            Text(res.verdict.value, style=v_style),
            Text(res.severity.value, style=s_style),
            f"{res.confidence * 100:.0f}%",
        )

    console.print(table)


def render_lead_detail_card(result: LeadAuditResult, console: Console) -> None:
    """Renders a comprehensive triage card for an individual finding."""
    border_color = (
        "bright_red"
        if result.verdict == TriageVerdict.VULNERABLE
        else "yellow"
        if result.verdict == TriageVerdict.SUSPICIOUS
        else "green"
    )

    v_style = VERDICT_STYLES.get(result.verdict, "white")
    s_style = SEVERITY_STYLES.get(result.severity, "white")

    # Header section
    card_sections: list[str | Syntax | Panel] = []

    reach_style = REACHABILITY_STYLES.get(result.reachability, "white")

    header_text = (
        f"[bold cyan]Target:[/] {result.class_name}::{result.method_name}\n"
        f"[bold cyan]Verdict:[/] [{v_style}]{result.verdict.value}[/]   |   "
        f"[bold cyan]Severity:[/] [{s_style}]{result.severity.value}[/]   |   "
        f"[bold cyan]Confidence:[/] {result.confidence * 100:.1f}%\n"
        f"[bold cyan]CWE:[/] {result.cwe_id or 'Unassigned'}   |   "
        f"[bold cyan]Reachability:[/] [{reach_style}]{result.reachability.value}[/]"
    )
    card_sections.append(header_text)

    # Bytecode Evidence
    if result.evidence_code and result.evidence_code.strip():
        card_sections.append("\n[bold cyan]Bytecode Evidence:[/]")
        evidence_syntax = Syntax(
            result.evidence_code.strip(),
            "smali",
            theme="monokai",
            line_numbers=False,
            word_wrap=True,
        )
        card_sections.append(evidence_syntax)

    # Taint Data Flow Analysis
    if result.data_flow:
        sanitizer_tag = (
            "[green]Yes[/]"
            if result.data_flow.sanitizer_present
            else "[bright_red]No / None Detected[/]"
        )
        flow_info = (
            f"\n[bold cyan]Taint Analysis:[/] \n"
            f"  • [bold]Source:[/] {result.data_flow.source}\n"
            f"  • [bold]Sink:[/]   {result.data_flow.sink}\n"
            f"  • [bold]Extracted Extra Keys:[/]   {result.data_flow.extracted_extra_keys}\n"
            f"  • [bold]Sanitizer Present:[/] {sanitizer_tag}\n"
            f"  • [bold]Propagation:[/] {result.data_flow.taint_path_summary}"
        )
        card_sections.append(flow_info)

    # Technical Analysis and fix
    card_sections.append(
        f"\n[bold cyan]Technical Analysis:[/]\n{result.analysis.strip()}"
    )

    # Remediation
    card_sections.append(f"\n[bold cyan]Remediation:[/]\n{result.remediation.strip()}")

    # Payload File Artifact (if present)
    if (
        result.payload_file
        and result.payload_file.filename
        and result.payload_file.content
    ):
        card_sections.append(
            f"\n[bold cyan]Payload Artifact: `{result.payload_file.filename}`[/]"
        )
        lexer = (
            "html"
            if result.payload_file.filename.endswith((".html", ".htm"))
            else "xml"
            if result.payload_file.filename.endswith(".xml")
            else "text"
        )
        payload_syntax = Syntax(
            result.payload_file.content.strip(),
            lexer,
            theme="monokai",
            line_numbers=True,
            word_wrap=True,
        )
        card_sections.append(payload_syntax)

    # Verification Commands
    if result.poc_commands:
        card_sections.append("\n[bold cyan]Verification Commands:[/]")
        # Format commands sequentially as executable shell lines
        joined_commands = "\n".join(cmd.strip() for cmd in result.poc_commands)
        cmd_syntax = Syntax(
            joined_commands,
            "bash",
            theme="monokai",
            line_numbers=False,
            word_wrap=True,
        )
        card_sections.append(cmd_syntax)

    # Bundle all sections into a single renderable group
    content_group = Group(*card_sections)

    # Print main card wrapper
    # Print a single clean card
    console.print(
        Panel(
            content_group,
            title=f"Finding: {result.rule_id} ({result.verdict.value})",
            border_style=border_color,
            expand=True,
        )
    )
