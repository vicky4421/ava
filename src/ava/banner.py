import os
import platform

from ava.config.settings import settings

# --- ANSI Color Codes ---
RESET = "\033[0m"
BOLD = "\033[1m"

C_LOGO = "\033[38;5;39m"  # Android electric cyan / bright blue
C_TITLE = "\033[38;5;141m"  # Purple / violet title
C_KEY = "\033[38;5;208m"  # Amber / orange keys
C_VAL = "\033[38;5;255m"  # Bright white values
C_ACC = "\033[38;5;118m"  # Neon cyber green accent
C_DIM = "\033[38;5;241m"  # Subdued gray


def generate_color_palette_bar() -> str:
    """Generates the terminal color swatch bar seen in fetch tools."""
    colors = [237, 196, 46, 226, 201, 51, 231]
    return "".join(f"\033[48;5;{c}m    {RESET}" for c in colors)


def print_ava_banner(target_apk: str = "demo.apk", target_pkg: str = "com.target.app"):
    username = os.getenv("USER", os.getenv("USERNAME", "operator"))
    hostname = platform.node() or "agent-node"

    # Diagnostics to display in the right column
    info_lines = [
        f"{C_TITLE}{BOLD}{username}@{hostname}{RESET}",
        f"{C_DIM}{'─' * 46}{RESET}",
        f"{C_KEY}Agent{RESET}:        {C_VAL}AVA (Autonomous Vulnerability Analyzer){RESET}",
        f"{C_KEY}Version{RESET}:      {C_VAL}0.1.0{RESET}",
        f"{C_KEY}Framework{RESET}:    {C_VAL}LangGraph (AsyncStateGraph){RESET}",
        f"{C_KEY}Persistence{RESET}:  {C_VAL}PostgreSQL Checkpointer{RESET}",
        f"{C_KEY}LLM Engine{RESET}:   {C_VAL}{settings.llm_model}{RESET}",
        f"{C_KEY}Embeddings{RESET}:   {C_VAL}{settings.huggingface_embedding_model_name}(Local CPU){RESET}",
        f"{C_KEY}Router{RESET}:       {C_VAL}Jev (Deterministic System One){RESET}",
        f"{C_KEY}Environment{RESET}:  {C_VAL}{platform.system()} {platform.release()} ({platform.machine()}){RESET}",
        f"{C_KEY}Subprocess{RESET}:   {C_VAL}asyncio.subprocess (injection-safe){RESET}",
        f"{C_KEY}Target APK{RESET}:   {C_ACC}{target_apk}{RESET}",
        f"{C_KEY}Package ID{RESET}:   {C_ACC}{target_pkg}{RESET}",
        f"{C_KEY}Audit State{RESET}:  {C_ACC}● Initializing Analysis Pipelines{RESET}",
        "",
        f"        {generate_color_palette_bar()}",
    ]

    print("\n")
    max_rows = len(info_lines)

    # Print side-by-side: Art on left, diagnostics on right
    for i in range(max_rows):
        right_info = info_lines[i] if i < len(info_lines) else ""
        print(f"{right_info}")

    print("\n")


if __name__ == "__main__":
    print_ava_banner("insecure_bank_v2.apk", "com.payatu.bugbazaar")
