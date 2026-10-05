from typing import NotRequired

from langgraph.graph import MessagesState


class AgentState(MessagesState):
    target_apk: NotRequired[str | None]
    decompiled_path: NotRequired[str | None]
