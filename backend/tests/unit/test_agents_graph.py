"""
Unit tests for LangGraph Multi-Agent Investigation Workflow.
"""

from __future__ import annotations

import pytest

from backend.app.agents.graph import investigation_workflow
from backend.app.agents.state import InvestigationState, ResolvedInvestigationContext


@pytest.mark.asyncio
async def test_workflow_valid_query_execution() -> None:
    state: InvestigationState = {
        "request_id": "test-req-1",
        "user_id": "user-123",
        "conversation_id": "conv-123",
        "investigation_id": "inv-123",
        "provider_name": "synthetic",
        "user_query": "Find accounts with failed logins in the last 24 hours.",
    }

    result = await investigation_workflow.ainvoke(state)

    assert result.get("intent") is not None
    assert result.get("query_plan") is not None
    assert result.get("validation_result") is not None
    assert result["validation_result"].is_valid

    # Check execution
    events = result.get("events", [])
    assert len(events) > 0
    assert len(result.get("evidence_ids", [])) == len(events)

    # Check analysis
    assert result.get("risk_assessment") is not None
    assert len(result.get("attack_candidates", [])) > 0

    # Check synthesis
    final_resp = result.get("final_response", "")
    assert "Investigation Summary" in final_resp
    assert "SYNTHETIC DATA DISCLOSURE" in final_resp
    assert "MITRE ATT&CK Mappings" in final_resp


@pytest.mark.asyncio
async def test_workflow_multi_turn_follow_up() -> None:
    # First turn sets context with suspect account jsmith
    state: InvestigationState = {
        "request_id": "test-req-2",
        "user_id": "user-123",
        "conversation_id": "conv-123",
        "investigation_id": "inv-123",
        "provider_name": "synthetic",
        "user_query": "Did any of those accounts log in successfully afterwards?",
        "resolved_context": ResolvedInvestigationContext(
            target_accounts=["jsmith"],
        ),
    }

    result = await investigation_workflow.ainvoke(state)

    assert result["validation_result"].is_valid
    events = result.get("events", [])
    # In synthetic scenario 2, jsmith has 1 successful login
    assert any(
        e.user
        and e.user.name == "jsmith"
        and e.event.outcome
        and e.event.outcome.value == "success"
        for e in events
    )

    # Check correlations
    corrs = result.get("correlations", [])
    assert any(c.rule_id == "CORR_001_AUTH_BRUTE_FORCE_SUCCESS" for c in corrs)
    assert any(f.finding_type == "post_failure_success" for f in result.get("findings", []))


@pytest.mark.asyncio
async def test_workflow_invalid_query_clarification() -> None:
    # Query with unapproved field
    state: InvestigationState = {
        "request_id": "test-req-3",
        "user_id": "user-123",
        "conversation_id": "conv-123",
        "investigation_id": "inv-123",
        "provider_name": "synthetic",
        "user_query": "malware",
        "errors": ["Validation error (unapproved_field): Field 'secret_pass' is not permitted"],
    }

    result = await investigation_workflow.ainvoke(state)

    # Execution skipped, routed to clarify_query
    assert not result.get("events")
    final_resp = result.get("final_response", "")
    assert "Query Validation Failed / Clarification Required" in final_resp
    assert "Field 'secret_pass' is not permitted" in final_resp
