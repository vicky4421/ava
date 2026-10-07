# Author: Vivek Sawant
# Date: 07-10-2026

from pathlib import Path
from typing import Any

import defusedxml.ElementTree as ET  # type: ignore

from ava.agent.schemas.manifest import ComponentEntryPoint, ManifestAnalysisResult
from ava.agent.state import AgentState
from ava.config.logger import get_logger

logger = get_logger()

# Standard Android XML Namespace
ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


def analyze_manifest_node(state: AgentState) -> dict[str, Any]:
    """Parse AndroidManifest.xml for basic hygiene flags and component entry points."""

    decompiled_path = state.get("decompiled_path", "")

    if not decompiled_path:
        logger.error("Decompiled path is missing from state.")
        return {"manifest_analysis": {}}

    decompiled_dir = Path(decompiled_path)

    manifest_path = decompiled_dir / "AndroidManifest.xml"

    logger.info("Parsing AndroidManifest.xml for components and flags...")

    try:
        tree = ET.parse(str(manifest_path))
        root = tree.getroot()
    except (ET.ParseError, OSError) as e:
        logger.error(f"Failed to parse AndroidManifest.xml: {e}")
        return {"manifest_analysis": {}}

    if root is None:
        logger.error("AndroidManifest.xml has no root element.")
        return {"manifest_analysis": {}}

    package_name = root.attrib.get("package", "Unknown")

    # 1. Parse SDK versions
    uses_sdk = root.find("uses-sdk")
    target_sdk = None
    if uses_sdk is not None:
        target_sdk_str = uses_sdk.attrib.get(f"{ANDROID_NS}targetSdkVersion")
        if target_sdk_str and target_sdk_str.isdigit():
            target_sdk = int(target_sdk_str)

    # 2. Parse Application Level Flags
    app_elem = root.find("application")
    debuggable = False
    allow_backup = True  # Default is True in Android if omitted

    if app_elem is not None:
        debuggable = (
            app_elem.attrib.get(f"{ANDROID_NS}debuggable", "false").lower() == "true"
        )
        allow_backup = (
            app_elem.attrib.get(f"{ANDROID_NS}allowBackup", "true").lower() == "true"
        )

    # 3. Parse Component Entry Points
    component_tags = {
        "activity": "activity",
        "receiver": "receiver",
        "service": "service",
        "provider": "provider",
    }

    discovered_entry_points: list[ComponentEntryPoint] = []

    if app_elem is not None:
        for tag, component_type in component_tags.items():
            for elem in app_elem.findall(tag):
                name = elem.attrib.get(f"{ANDROID_NS}name", "unknown")
                permission = elem.attrib.get(f"{ANDROID_NS}permission")

                # Extract intent filter action names
                actions = []

                for intent_filter in elem.findall("intent-filter"):
                    for action in intent_filter.findall("action"):
                        action_name = action.attrib.get(f"{ANDROID_NS}name")
                        if action_name:
                            actions.append(action_name)

                # Exported logic:
                # If explicit android:exported is set, use it.
                # If omitted, defaults to True if intent-filters exist, otherwise False.
                exported_attr = elem.attrib.get(f"{ANDROID_NS}exported")
                if exported_attr is not None:
                    is_exported = exported_attr.lower() == "true"
                else:
                    is_exported = len(actions) > 0

                discovered_entry_points.append(
                    ComponentEntryPoint(
                        name=name,
                        component_type=component_type,
                        exported=is_exported,
                        permission=permission,
                        intent_filters=actions,
                    )
                )

    exported_count = sum(1 for c in discovered_entry_points if c.exported)

    logger.info(
        f"Manifest parsed: {len(discovered_entry_points)} components found ({exported_count} exported)."
    )

    manifest_result = ManifestAnalysisResult(
        package_name=package_name,
        target_sdk=target_sdk,
        debuggable=debuggable,
        allow_backup=allow_backup,
        entry_points=discovered_entry_points,
    )

    return {"manifest_analysis": manifest_result.model_dump()}


def get_exported_entry_points(state: AgentState) -> list[dict[str, Any]]:
    """Retrieve all directly accessible external components (Ingress points)."""
    manifest = state.get("manifest_analysis") or {}
    entry_points = manifest.get("entry_points", [])
    return [comp for comp in entry_points if comp.get("exported", False)]


def get_internal_entry_points(state: AgentState) -> list[dict[str, Any]]:
    """Retrieve internal unexported components (Potential targets for Intent Redirection / Sinks)."""
    manifest = state.get("manifest_analysis") or {}
    entry_points = manifest.get("entry_points", [])
    return [comp for comp in entry_points if not comp.get("exported", False)]
