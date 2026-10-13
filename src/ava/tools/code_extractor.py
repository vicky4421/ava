# Author: Vivek Sawant
# Date: 12-10-2026

from pathlib import Path


def extract_method_context(
    file_path: str | Path,
    target_line: int,
    window_padding: int = 60,
    max_total_lines: int = 500,
) -> str | None:
    """
    Extracts Smali method instructions surrounding a specific target line.
    Finds enclosing .method and .end method boundaries, falling back to a
    focused window around target_line if the method exceeds max_total_lines.
    """
    path = Path(file_path)
    if not path.is_file():
        return None

    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return None

    total_file_lines = len(lines)
    if not (1 <= target_line <= total_file_lines):
        return None

    target_idx = target_line - 1

    # 1. Scan backwards to locate the enclosing .method declaration
    start_idx = target_idx
    while start_idx >= 0 and not lines[start_idx].strip().startswith(".method"):
        start_idx -= 1

    # If target line is outside any method block, fall back to line window
    if start_idx < 0:
        start_idx = max(0, target_idx - window_padding)
        end_idx = min(total_file_lines, target_idx + window_padding)
        return "\n".join(lines[start_idx:end_idx])

    # 2. Scan forwards to locate .end method
    end_idx = target_idx
    while end_idx < total_file_lines and not lines[end_idx].strip().startswith(
        ".end method"
    ):
        end_idx += 1

    # Include the .end method line if found
    if end_idx < total_file_lines and lines[end_idx].strip().startswith(".end method"):
        end_idx += 1

    method_slice = lines[start_idx:end_idx]

    # 3. If within budget, return the whole method
    if len(method_slice) <= max_total_lines:
        return "\n".join(method_slice)

    # 4. If massive, slice around the target sink line while keeping method signature
    method_header = [lines[start_idx]]
    registers_line = (
        [lines[start_idx + 1]]
        if start_idx + 1 < total_file_lines and ".registers" in lines[start_idx + 1]
        else []
    )

    window_start = max(start_idx, target_idx - window_padding)
    window_end = min(end_idx, target_idx + window_padding)

    body = (
        method_header
        + registers_line
        + ["    # ... [Earlier instructions trimmed for focus] ..."]
        + lines[window_start:window_end]
        + ["    # ... [Later instructions trimmed for focus] ..."]
        + [".end method"]
    )
    return "\n".join(body)


if __name__ == "__main__":
    pass
