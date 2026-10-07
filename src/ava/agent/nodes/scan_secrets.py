# Author: Vivek Sawant
# Date: 06-10-2026

import math
import re
from collections import Counter
from pathlib import Path
from typing import Any

from ava.agent.state import AgentState
from ava.config.logger import get_logger

logger = get_logger()

# Common high-confidence patterns
PATTERNS = {
    "google_api_key": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "jwt_token": re.compile(
        r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*"
    ),
    "generic_api_key": re.compile(
        r"(?i)(?:api_key|apikey|secret|token)\s*[:=]\s*[\"']([A-Za-z0-9_-]{16,64})[\"']"
    ),
    "private_key_header": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    "firebase_url": re.compile(r"https://[a-z0-9-]+\.firebaseio\.com"),
    "github_personal_token": re.compile(r"gh[pous]_[A-Za-z0-9_]{36,255}"),
    "slack_token": re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,72}"),
    "stripe_api_key": re.compile(r"(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,99}"),
    "basic_auth_url": re.compile(
        r"https?://[a-zA-Z0-9_\-\.]+:[a-zA-Z0-9_\-\.]+@[a-zA-Z0-9_\-\.]+"
    ),
    # 1. Standard bracketed CTF flags: flag{...}, FLAG{...}, ctf{...}, HTB{...}
    "ctf_flag_bracketed": re.compile(
        r"(?i)(?:flag|ctf|[a-z0-9_-]+ctf|htb|pico)\{([^\}\s]{4,100})\}"
    ),
    # 2. Key-value flag assignments: flag = "...", "secret_flag": "..."
    "flag_assignment": re.compile(
        r"(?i)(?:flag|hidden_flag|ctf_flag|secret_key)\s*[:=]\s*[\"']([A-Za-z0-9_\-!@#$%^&*()+=]{6,80})[\"']"
    ),
    # 3. Android XML string tags: <string name="flag">...</string>
    "xml_flag_resource": re.compile(
        r"(?i)<string[^>]*name=[\"'][^\"']*(?:flag|secret|token)[^\"']*[\"'][^>]*>([^<]+)</string>"
    ),
}


def calculate_shannon_entropy(data: str) -> float:
    """Calculates Shannon entropy in O(N) time."""
    if not data:
        return 0.0

    length = len(data)
    counts = Counter(data)

    entropy = -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )
    return round(abs(entropy), 2)


def scan_secrets_node(state: AgentState) -> dict[str, Any]:
    """Scans for potential hardcoded secrets and captures surrounding context."""
    logger.info("Scanning for hardcoded secrets...")

    decompiled_path = state.get("decompiled_path")
    if not decompiled_path:
        logger.critical(msg="decompiled_path not set in state.")
        raise ValueError("decompiled_path not set in state.")

    target_dir = Path(decompiled_path)
    findings_map: dict[str, dict[str, Any]] = {}

    target_extensions = {".xml", ".json", ".smali", ".txt", ".properties"}

    for file_path in target_dir.rglob("*"):
        if not (file_path.is_file() and file_path.suffix in target_extensions):
            continue

        try:
            with file_path.open(mode="r", encoding="utf-8", errors="ignore") as f:
                history: list[tuple[int, str]] = []
                active_captures: list[dict[str, Any]] = []

                for line_num, raw_line in enumerate(f, start=1):
                    line = raw_line.rstrip("\r\n")

                    # 1. Feed this line to any active lookahead contexts from previous lines
                    for cap in active_captures:
                        cap["lines"].append((line_num, line))

                    # 2. Check patterns against the current line
                    for secret_type, pattern in PATTERNS.items():
                        match = pattern.search(line)
                        if not match:
                            continue

                        candidate = (
                            match.group(1) if match.lastindex else match.group(0)
                        )
                        rel_file = str(file_path.relative_to(target_dir))

                        if candidate in findings_map:
                            findings_map[candidate]["occurrences"].append(
                                {"file": rel_file, "line": line_num}
                            )
                            continue

                        # Register new unique candidate
                        findings_map[candidate] = {
                            "type": secret_type,
                            "candidate": candidate,
                            "entropy": calculate_shannon_entropy(candidate),
                            "occurrences": [{"file": rel_file, "line": line_num}],
                            "context_snippet": "",
                        }

                        # Start collecting: preceding 3 lines + current line
                        active_captures.append(
                            {
                                "candidate": candidate,
                                "end_line": line_num + 3,
                                "lines": list(history) + [(line_num, line)],
                            }
                        )

                    # 3. Finalize captures whose lookahead window (+3 lines) has elapsed
                    # (Executed every line, regardless of whether a match occurred)
                    still_active = []
                    for cap in active_captures:
                        if line_num >= cap["end_line"]:
                            snippet = "\n".join(
                                f"{l_no:4d} | {txt}" for l_no, txt in cap["lines"]
                            )
                            findings_map[cap["candidate"]]["context_snippet"] = snippet
                        else:
                            still_active.append(cap)
                    active_captures = still_active

                    # 4. Slide history window (3 lines)
                    history.append((line_num, line))
                    if len(history) > 3:
                        history.pop(0)

                # 5. Flush captures near EOF where file ended before +3 lines
                for cap in active_captures:
                    snippet = "\n".join(
                        f"{l_no:4d} | {txt}" for l_no, txt in cap["lines"]
                    )
                    findings_map[cap["candidate"]]["context_snippet"] = snippet

        except (OSError, UnicodeDecodeError) as e:
            logger.debug(f"Could not read {file_path}: {e}")
            continue

    deduplicated_findings = list(findings_map.values())
    logger.info(
        f"Scan complete. Found {len(deduplicated_findings)} unique candidate secret(s)."
    )

    return {"secret_candidates": deduplicated_findings}
