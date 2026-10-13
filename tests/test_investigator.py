# Author: Vivek Sawant
# Date: 12-10-2026

# Author: Vivek Sawant
# Date: 12-10-2026

from pathlib import Path

from rich.box import HORIZONTALS
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

from ava.agent.nodes.investigator import _investigate_single_lead
from ava.rag.retriever import HybridMASTGRetriever

console = Console()


def run_test():

    # 2. Target lead from the Deeplink scan
    decompiled_base = (
        Path.home() / "sample_apps" / "bugbazaar" / "BugBazaar_v1.2.1_decompiled"
    )
    target_file = (
        decompiled_base / "smali" / "com" / "BugBazaar" / "ui" / "Deeplink.smali"
    )

    if not target_file.exists():
        console.print(f"[bold red]Target smali file not found:[/] {target_file}")
        return

    sample_lead = {
        "rule_id": "SEC-WEB-001",
        "category": "WebView Security",
        "description": "WebView JavaScript execution enabled.",
        "class_name": "com.BugBazaar.ui.Deeplink",
        "method_name": "setupwebview",
        "file_path": str(target_file),
        "line_number": 48,
        "is_exported": True,  # Deep link handlers are exported entry points
        "code_snippet": "invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V",
    }

    console.print("[bold cyan]Initializing Hybrid RAG Retriever...[/]")
    # Point this to your existing RAG store / vector collection
    retriever = HybridMASTGRetriever()

    console.print("[bold cyan]Initializing Gemini LLM Engine...[/]")
    # llm = ChatGoogleGenerativeAI(
    #     model="gemini-2.5-flash",
    #     temperature=0.0,
    # )

    console.print(
        f"[bold yellow]Running Investigation on:[/] {sample_lead['class_name']}::{sample_lead['method_name']}"
    )

    # 3. Execute the audit node
    result = _investigate_single_lead(
        lead=sample_lead,
        retriever=retriever,
    )

    # 4. Render the structured result
    color_map = {
        "VULNERABLE": "bold bright_red",
        "SUSPICIOUS": "bold yellow",
        "FALSE_POSITIVE": "bold green",
    }
    verdict_style = color_map.get(result.verdict.value, "white")

    report = (
        f"[bold cyan]Rule ID:[/] {result.rule_id}\n"
        f"[bold cyan]Target:[/] {result.class_name}::{result.method_name}\n"
        f"[bold cyan]Verdict:[/] [{verdict_style}]{result.verdict.value}[/]  |  "
        f"[bold cyan]Severity:[/] {result.severity.value}  |  "
        f"[bold cyan]CWE ID:[/] {result.cwe_id}    \n\n"
        f"[bold cyan]Evidence Code:[/] {result.evidence_code}  |  \n\n"
        f"[bold cyan]Confidence:[/] {result.confidence * 100:.1f}%\n\n"
        f"[bold cyan]Analysis:[/] {result.analysis}\n\n"
        f"[bold cyan]Remediation:[/] {result.remediation}\n\n"
    )

    console.print(
        Panel(
            report,
            title="Investigator Audit Result",
            border_style="bold bright_red"
            if result.verdict.value == "VULNERABLE"
            else "cyan",
        )
    )

    if result.poc_exploitation:
        poc_syntax = Markdown(result.poc_exploitation, "bash")
        console.print(
            Panel(
                poc_syntax, title="🎯 Exploitation steps", box=HORIZONTALS, expand=False
            )
        )


if __name__ == "__main__":
    run_test()
