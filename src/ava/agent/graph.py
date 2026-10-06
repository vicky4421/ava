from langgraph.graph import END, START, StateGraph

from ava.agent.nodes.constants import Node
from ava.agent.nodes.decompile import decompile_node
from ava.agent.nodes.scan_secrets import scan_secrets_node
from ava.agent.nodes.triage_secret import triage_secret_node
from ava.agent.state import AgentState

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

# ---------------------------------------------------------------------------------------------------
# add edges to graph
# ---------------------------------------------------------------------------------------------------
graph.add_edge(START, Node.DECOMPILE)
graph.add_edge(Node.DECOMPILE, Node.SCAN_SECRETS)
graph.add_edge(Node.SCAN_SECRETS, Node.TRIAGE_SECRETS)
graph.add_edge(Node.TRIAGE_SECRETS, END)


# ---------------------------------------------------------------------------------------------------
# compile graph
# ---------------------------------------------------------------------------------------------------
app = graph.compile()
