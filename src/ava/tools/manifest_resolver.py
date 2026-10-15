# Author: Vivek Sawant
# Date: 14-10-2026


def resolve_component_from_manifest(manifest_data: dict, target_class: str) -> dict:
    """Resolves metadata for a target class using the exact ManifestAnalysisResult dictionary from state."""

    package_name = manifest_data.get("package_name", "")
    entry_points = manifest_data.get("entry_points", [])

    clean_target = target_class.replace("/", ".").strip("L; ")

    for entry in entry_points:
        entry_name = entry.get("name", "")
        if clean_target in entry_name or entry_name in clean_target:
            rel_path = entry_name.removeprefix(package_name)

            if not rel_path.startswith("."):
                rel_path = f".{rel_path}"

            intent_filters = entry.get("intent_filters", [])
            action = intent_filters[0] if intent_filters else None

            return {
                "package_name": package_name,
                "component_path": f"{package_name}/{rel_path}",
                "component_type": entry.get("component_type", "activity"),
                "exported": entry.get("exported", False),
                "action": action,
                "permission": entry.get("permission"),
            }

    # Fallback if class name was not explicitly declared in manifest entry points
    short_class = clean_target.split(".")[-1]
    return {
        "package_name": package_name,
        "component_path": f"{package_name}/{short_class}",
        "component_type": "activity",
        "exported": False,
        "action": None,
        "permission": None,
    }
