"""
SENTINEL AI — LangGraph Investigation Workflow.

Defines the multi-agent investigation workflow graph per Section 6.2.
Guarantees execution safety, validation stops, and honest evidence synthesis.
"""

from __future__ import annotations

from typing import Literal

from backend.app.agents.nodes.analysis_node import analyze_events_node
from backend.app.agents.nodes.clarification_node import clarify_query_node
from backend.app.agents.nodes.executor_node import execute_query_node
from backend.app.agents.nodes.intent_node import plan_intent_node
from backend.app.agents.nodes.synthesis_node import synthesize_response_node
from backend.app.agents.nodes.validator_node import validate_query_node
from backend.app.agents.state import InvestigationState
from langgraph.graph import END, START, StateGraph


def routing_decision(state: InvestigationState) -> Literal["execute_query", "clarify_query"]:
    """
    Conditional routing function after query validation.
    Halts execution if validation fails or errors exist.
    """
    val = state.get("validation_result")
    errors = state.get("errors", [])

    if val is not None and val.is_valid and not errors:
        return "execute_query"
    return "clarify_query"


def build_investigation_graph() -> StateGraph:
    """Build and assemble the LangGraph investigation workflow."""
    workflow = StateGraph(InvestigationState)

    # Register workflow nodes
    workflow.add_node("plan_intent", plan_intent_node)
    workflow.add_node("validate_query", validate_query_node)
    workflow.add_node("clarify_query", clarify_query_node)
    workflow.add_node("execute_query", execute_query_node)
    workflow.add_node("analyze_events", analyze_events_node)
    workflow.add_node("synthesize_response", synthesize_response_node)

    # Establish linear and conditional edges
    workflow.add_edge(START, "plan_intent")
    workflow.add_edge("plan_intent", "validate_query")
    workflow.add_conditional_edges(
        "validate_query",
        routing_decision,
        {
            "execute_query": "execute_query",
            "clarify_query": "clarify_query",
        },
    )
    workflow.add_edge("execute_query", "analyze_events")
    workflow.add_edge("analyze_events", "synthesize_response")
    workflow.add_edge("synthesize_response", END)
    workflow.add_edge("clarify_query", END)

    return workflow


# Compiled singleton instance
investigation_workflow = build_investigation_graph().compile()
