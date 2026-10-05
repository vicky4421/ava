from pathlib import Path


def find_project_root() -> Path:
    """Recursively search upward from this file until pyproject.toml is found."""
    current = Path(__file__).resolve()
    for parent in current.parents:
        if (parent / "pyproject.toml").exists():
            return parent
    return current.parents[2]  # Fallback to the third parent


ROOT_DIR = find_project_root()
LOG_DIR = ROOT_DIR / "logs"
LOG_FILE = LOG_DIR / "ava.log"
