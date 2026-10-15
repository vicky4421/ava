from pathlib import Path

from androguard.misc import AnalyzeAPK
from androguard.util import set_log
from loguru import logger as loguru_logger

from ava.agent.state import AgentState
from ava.config.logger import get_logger
from ava.resources.runtime import set_analysis_context
from ava.resources.tools import decompile_apk

logger = get_logger()

# Silence all Androguard internal loggers
set_log("ERROR")
loguru_logger.disable("androguard")


def decompile_node(state: AgentState) -> dict[str, str]:
    target_apk = state.get("target_apk")

    if not target_apk:
        raise ValueError("Missing 'target_apk' in AgentState.")

    apk = Path(target_apk).resolve()

    decompiled_path = apk.parent / f"{apk.stem}_decompiled"

    # 1. Unpack resources & smali to disk via apktool if not already decompiled
    if not decompiled_path.exists():
        logger.info(f"Decompiling APK resources and bytecode to {decompiled_path}...")
        decompile_apk(apk_path=str(apk))
    else:
        logger.info(f"Using existing decompiled directory: {decompiled_path}")

    # 2. Run Androguard analysis for Xref / Call Graph mapping
    logger.info("Initializing Androguard cross-reference tables...")
    _, _, dx = AnalyzeAPK(str(apk))

    # Cache dx in memory using the resolved path as the key
    set_analysis_context(key=str(apk), dx=dx)

    return {"decompiled_path": str(decompiled_path)}
