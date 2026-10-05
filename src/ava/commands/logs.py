from rich.console import Console

from ava.config.paths import LOG_FILE

console = Console()


def handle_logs(lines: int = 50, clear: bool = False, show_path: bool = False) -> None:
    """Reads, tails, or clears AVA execution logs."""
    if show_path:
        console.print(str(LOG_FILE))
        return

    if clear:
        if LOG_FILE.exists():
            LOG_FILE.write_text(data="")
            console.print("[bold green][*][/bold green] Log file cleared successfully.")
        else:
            console.print("[yellow][!] No log file found to clear.[/yellow]")
        return

    if not LOG_FILE.exists() or LOG_FILE.stat().st_size == 0:
        console.print("[yellow][!] Log file is empty or does not exist yet.[/yellow]")
        return

    # Print the last N lines
    all_lines = LOG_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
    recent_lines = all_lines[-lines:] if lines > 0 else all_lines

    for line in recent_lines:
        console.print(line, highlight=False)
