# Author: Vivek Sawant
# Date: 14-10-2026

from typing import Any

LIFECYCLE_ENTRY_POINTS = {
    "onCreate",
    "onStart",
    "onResume",
    "onReceive",
    "onNewIntent",
    "doInBackground",
}


def trace_upstream_callers(
    dx: Any,
    target_class_smali: str,
    target_method: str,
    exported_components: set[str],
    max_depth: int = 3,
    _visited: set[tuple[str, str]] | None = None,
    _depth: int = 0,
) -> list[dict[str, Any]]:
    """Discovers upstream caller methods for a target sink method using Androguard xrefs.

    target_class_smali format: 'Lcom/BugBazaar/ui/Deeplink;'
    """

    if _visited is None:
        _visited = set()

    callers = []

    # Format class descriptor for Dalvik (Lcom/path/Class;)
    formatted_class = target_class_smali.strip()
    if not formatted_class.startswith("L"):
        formatted_class = f"L{formatted_class.replace('.', '/')};"

    key = (formatted_class, target_method)

    if key in _visited or _depth >= max_depth:
        return []
    _visited.add(key)

    matched_methods = dx.find_methods(
        classname=formatted_class,
        methodname=target_method,
    )

    for method_analysis in matched_methods:
        for xref_class, xref_method, offset in method_analysis.get_xref_from():
            caller_name = getattr(
                xref_method,
                "name",
                str(
                    xref_method.get_method().get_name()
                    if hasattr(xref_method, "get_method")
                    else xref_method
                ),
            )

            caller_class = getattr(
                xref_class,
                "name",
                str(
                    xref_class.get_vm_class().get_name()
                    if hasattr(xref_class, "get_vm_class")
                    else xref_class
                ),
            )

            # Normalize smali class name (Lcom/x/Y;) to dotted (com.x.Y) for comparison
            normalized_class = caller_class.strip("L;").replace("/", ".")

            is_entry = (
                caller_name in LIFECYCLE_ENTRY_POINTS
                and normalized_class in exported_components
            )

            # Extract Smali instructions from the caller method
            instructions: list[str] = []
            encoded_method = (
                xref_method.get_method() if hasattr(xref_method, "get_method") else None
            )

            if encoded_method and hasattr(encoded_method, "get_instructions"):
                for ins in encoded_method.get_instructions():
                    try:
                        instructions.append(f"    {ins.get_name()} {ins.get_output()}")
                    except Exception:  # noqa: BLE001
                        instructions.append(f"    {ins.get_name()}")

            callers.append(
                {
                    "class_name": caller_class,
                    "method_name": caller_name,
                    "is_lifecycle_entry": is_entry,
                    "instructions": "\n".join(instructions),
                }
            )

            # Recurse upward unless this caller is already a lifecycle entry point
            if not is_entry:
                callers.extend(
                    trace_upstream_callers(
                        dx,
                        caller_class,
                        caller_name,
                        exported_components,
                        max_depth,
                        _visited,
                        _depth=_depth + 1,
                    )
                )

    # Sort so lifecycle entry points appear first
    return sorted(callers, key=lambda c: 0 if c["is_lifecycle_entry"] else 1)
