"""
Integration test running the evaluation questions benchmark against SENTINEL AI.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend.app.agents.graph import investigation_workflow
from backend.app.agents.state import InvestigationState, ResolvedInvestigationContext


@pytest.mark.asyncio
async def test_evaluation_benchmark_all_scenarios() -> None:
    eval_file = Path("evaluation/questions.json")
    assert eval_file.exists(), "evaluation/questions.json missing"

    with open(eval_file, encoding="utf-8") as f:
        questions = json.load(f)

    assert len(questions) == 10, "Expected 10 evaluation questions for Appendix B scenarios"

    for q in questions:
        state: InvestigationState = {
            "request_id": f"eval-req-{q['id']}",
            "user_id": "eval-analyst",
            "conversation_id": f"eval-conv-{q['id']}",
            "investigation_id": f"eval-inv-{q['id']}",
            "provider_name": "synthetic",
            "user_query": q["question"],
        }
        if q["id"] == "eval-02":
            state["resolved_context"] = ResolvedInvestigationContext(target_accounts=["jsmith"])

        res = await investigation_workflow.ainvoke(state)
        assert res.get("validation_result") is not None
        assert res["validation_result"].is_valid, f"Validation failed for question {q['id']}"

        events = res.get("events", [])
        assert len(events) >= q["expected_min_hits"], (
            f"Question {q['id']} ({q['scenario_name']}) expected at least "
            f"{q['expected_min_hits']} events, got {len(events)}"
        )
