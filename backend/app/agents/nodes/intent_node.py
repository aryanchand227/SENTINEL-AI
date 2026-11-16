"""
SENTINEL AI — Intent & Query Planning Node.

Extracts intent, extracts entities, and generates SentinelQuerySpec.
"""

from __future__ import annotations

from typing import Any, Literal, cast

from backend.app.agents.state import (
    ExtractedEntity,
    InvestigationIntent,
    InvestigationState,
)
from backend.app.nlp.intent_planner import IntentPlanner, InvestigationContext


async def plan_intent_node(state: InvestigationState) -> dict[str, Any]:
    """Extract intent and plan SQS query from natural language input."""
    user_query = state.get("user_query", "")
    resolved_context = state.get("resolved_context")
    provider_name = state.get("provider_name", "synthetic")

    # Map state context to IntentPlanner context
    planner_ctx: InvestigationContext | None = None
    if resolved_context:
        planner_ctx = InvestigationContext(
            prior_time_range=resolved_context.prior_time_range,
            target_accounts=resolved_context.target_accounts,
            target_ips=resolved_context.target_ips,
            target_hosts=resolved_context.target_hosts,
            prior_evidence_ids=resolved_context.prior_evidence_ids,
        )

    planner = IntentPlanner()
    sqs, intent_summary = planner.plan_query(user_query, planner_ctx)
    # Ensure provider is correctly set
    if provider_name in ("synthetic", "elasticsearch", "wazuh"):
        sqs.provider = cast(Literal["synthetic", "elasticsearch", "wazuh"], provider_name)

    # Extract entities
    entities: list[ExtractedEntity] = []
    for f in sqs.filters:
        if f.field == "user.name" and f.value:
            if isinstance(f.value, list):
                for val in f.value:
                    entities.append(
                        ExtractedEntity(entity_type="user", value=str(val), role="subject")
                    )
            else:
                entities.append(
                    ExtractedEntity(entity_type="user", value=str(f.value), role="subject")
                )
        elif f.field == "source.ip" and f.value:
            entities.append(ExtractedEntity(entity_type="ip", value=str(f.value), role="source"))
        elif f.field == "host.name" and f.value:
            entities.append(ExtractedEntity(entity_type="host", value=str(f.value), role="target"))

    intent = InvestigationIntent(
        intent_type="search",
        description=intent_summary,
        confidence=1.0,
    )

    return {
        "intent": intent,
        "entities": entities,
        "query_plan": sqs,
        "warnings": list(state.get("warnings", [])),
        "errors": list(state.get("errors", [])),
    }
