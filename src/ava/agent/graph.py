from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import END, START, StateGraph

from ava.agent.nodes.analyze_manifest import analyze_manifest_node
from ava.agent.nodes.constants import Node, RouteVerdicts
from ava.agent.nodes.decompile import decompile_node
from ava.agent.nodes.scan_secrets import scan_secrets_node
from ava.agent.nodes.triage_secrets import triage_secret_node
from ava.agent.routers import should_triage_secrets
from ava.agent.state import AgentState


def build_app(checkpointer: BaseCheckpointSaver | None = None):
    # ---------------------------------------------------------------------------------------------------
    # define graph
    # ---------------------------------------------------------------------------------------------------
    graph = StateGraph(state_schema=AgentState)

    # ---------------------------------------------------------------------------------------------------
    # add nodes to graph
    # ---------------------------------------------------------------------------------------------------
    graph.add_node(Node.DECOMPILE, decompile_node)
    graph.add_node(Node.SCAN_SECRETS, scan_secrets_node)
    graph.add_node(Node.TRIAGE_SECRETS, triage_secret_node)
    graph.add_node(Node.ANALYZE_MANIFEST, analyze_manifest_node)

    # ---------------------------------------------------------------------------------------------------
    # add edges to graph
    # ---------------------------------------------------------------------------------------------------
    graph.add_edge(START, Node.DECOMPILE)
    graph.add_edge(Node.DECOMPILE, Node.SCAN_SECRETS)
    graph.add_conditional_edges(
        source=Node.SCAN_SECRETS,
        path=should_triage_secrets,
        path_map={
            RouteVerdicts.TRIAGE: Node.TRIAGE_SECRETS,
            RouteVerdicts.SKIP_TRIAGE: Node.ANALYZE_MANIFEST,
        },
    )
    graph.add_edge(Node.TRIAGE_SECRETS, Node.ANALYZE_MANIFEST)
    graph.add_edge(Node.ANALYZE_MANIFEST, END)

    return graph.compile(checkpointer=checkpointer)


# app for visualization, inspecting topology, and testing
app = build_app()
