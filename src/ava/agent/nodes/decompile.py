from pathlib import Path

from ava.agent.state import AgentState
from ava.resources.tools import decompile_apk

# ---------------------------------------------------------------------------------------------------
# define nodes
# ---------------------------------------------------------------------------------------------------


def decompile_node(state: AgentState) -> dict[str, str]:
    target_apk = state.get("target_apk")

    if not target_apk:
        raise ValueError("Missing 'target_apk' in AgentState.")

    apk = Path(target_apk).resolve()
    decompiled_path = apk.parent / f"{apk.stem}_decompiled"
    decompile_apk(apk_path=str(apk))

    return {"decompiled_path": str(decompiled_path)}
