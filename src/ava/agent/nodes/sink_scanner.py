# Author: Vivek Sawant
# Date: 12-10-2026

import re
from pathlib import Path
from typing import Any

from ava.agent.state import AgentState
from ava.config.logger import get_logger
from ava.static.sink_rules import SMALI_RULES, SinkRule

logger = get_logger()

# Regex to capture the declaring class definition in Smali
CLASS_PATTERN = re.compile(r"^\.class\s+.*?([^\s;]+);")
# Regex to identify the containing method
METHOD_PATTERN = re.compile(r"^\.method\s+.*?\s+([^\s(]+)\(")


def is_in_scope(class_name: str, app_package: str | None) -> bool:
    """
    Determines if a class belongs to first-party application code.
    If app_package is unavailable, defaults to True to avoid dropping leads.
    """
    if not app_package or app_package.lower() == "unknown":
        return True

    # Normalize to lower-case for reliable prefix comparison
    pkg = app_package.strip().lower()
    target = class_name.strip().lower()

    # Exact match or direct subpackage (e.g., com.BugBazaar or com.BugBazaar.*)
    return target == pkg or target.startswith(f"{pkg}.")


def _smali_to_java_class(smali_type) -> str:
    """Converts 'Lcom/package/ui/MainActivity' to 'com.package.ui.MainActivity'."""

    clean = smali_type.strip()
    clean = clean.removeprefix("L")  # removes L i.e. first item in string
    return clean.replace("/", ".")


def scan_smali_file(
    file_path: Path,
    rules: list[SinkRule],
    exported_map: dict[str, bool],
    app_package: str | None = None,
) -> list[dict[str, Any]]:
    """Scans an individual Smali file against active rules."""

    findings = []
    current_class = "Unknown"
    current_method = "Unknown"

    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []

    # Quick check: extract class from top lines first
    for line in content[:15]:
        stripped = line.strip()
        if stripped.startswith(".class"):
            m = CLASS_PATTERN.search(stripped)
            if m:
                current_class = _smali_to_java_class(m.group(1))
                break

    # If the class is outside our application package, bail out immediately
    if app_package and not is_in_scope(current_class, app_package):
        return []

    for line_num, line in enumerate(content, start=1):
        stripped = line.strip()

        # Update class context
        if stripped.startswith(".class"):
            m = CLASS_PATTERN.search(stripped)
            if m:
                current_class = _smali_to_java_class(m.group(1))
            continue

        # Update method context
        if stripped.startswith(".method"):
            m = METHOD_PATTERN.search(stripped)
            if m:
                current_method = m.group(1)
            continue

        if stripped.startswith(".end method"):
            current_method = "Unknown"
            continue

        # Match rules against instruction
        for rule in rules:
            if re.search(rule.pattern, stripped):
                is_exported = exported_map.get(current_class, False)

                findings.append(
                    {
                        "rule_id": rule.rule_id,
                        "category": rule.category.value,
                        "description": rule.description,
                        "class_name": current_class,
                        "method_name": current_method,
                        "file_path": str(file_path),
                        "line_number": line_num,
                        "code_snippet": stripped,
                        "is_exported": is_exported,
                        "is_intrinsic": rule.is_intrinsic,
                        "confidence": rule.confidence,
                    }
                )
    return findings


def scan_sink_node(state: AgentState) -> dict[str, Any]:
    """LangGraph node: scans decompiled Smali files for dangerous sinks."""

    decompiled_path = state.get("decompiled_path")
    manifest = state.get("manifest_analysis") or {}
    app_package = manifest.get("package_name")

    if not decompiled_path:
        logger.error("Missing decompiled_path in state.")
        return {"candidate_leads": []}

    # Build lookup map: class_name -> is_exported
    exported_map = {
        ep.get("name"): ep.get("exported", False)
        for ep in manifest.get("entry_points", [])
        if "name" in ep
    }

    decompiled_dir = Path(decompiled_path)

    # Android apps can have smali, smali_classes2, smali_classes3, etc.
    smali_dirs = sorted(decompiled_dir.glob("smali*"))

    logger.info(f"Initiating sink scan across {len(smali_dirs)} smali roots...")

    all_leads: list[dict[str, Any]] = []

    for s_dir in smali_dirs:
        for smali_file in s_dir.rglob("*.smali"):
            leads = scan_smali_file(
                smali_file,
                SMALI_RULES,
                exported_map,
                app_package=app_package,
            )
            all_leads.extend(leads)

    # Prioritize: Exported components first, then intrinsic vulnerabilities
    all_leads.sort(
        key=lambda x: (not x["is_exported"], not x["is_intrinsic"], x["rule_id"])
    )

    logger.info(
        f"Sink scan completed: {len(all_leads)} leads identified "
        f"({sum(1 for x in all_leads if x['is_exported'])} in exported components)."
    )

    return {"candidate_leads": all_leads}
