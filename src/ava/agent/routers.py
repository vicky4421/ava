# Author: Vivek Sawant
# Date: 07-10-2026

from ava.agent.nodes.constants import RouteVerdicts
from ava.agent.state import AgentState


def should_triage_secrets(state: AgentState) -> RouteVerdicts:
    """Route to LLM triage if regex candidates exist; otherwise bypass to manifest analysis."""
    candidates = state.get("secret_candidates", [])
    if candidates:
        return RouteVerdicts.TRIAGE
    else:
        return RouteVerdicts.SKIP_TRIAGE
