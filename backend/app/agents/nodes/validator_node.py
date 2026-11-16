"""
SENTINEL AI — Query Validation Node.

Validates SentinelQuerySpec against safety boundaries and field registries.
"""

from __future__ import annotations

from typing import Any

from backend.app.agents.state import InvestigationState
from backend.app.query.validator import QueryValidator


async def validate_query_node(state: InvestigationState) -> dict[str, Any]:
    """Validate query plan using QueryValidator."""
    query_plan = state.get("query_plan")
    errors = list(state.get("errors", []))
    warnings = list(state.get("warnings", []))

    if query_plan is None:
        return {
            "validation_result": None,
            "errors": errors + ["No query plan was generated to validate."],
        }

    validator = QueryValidator()
    validation_result = validator.validate(query_plan)

    if not validation_result.is_valid:
        for err in validation_result.errors:
            errors.append(f"Validation error ({err.field or 'general'}): {err.message}")

    for warn in validation_result.warnings:
        warnings.append(warn)

    return {
        "validation_result": validation_result,
        "errors": errors,
        "warnings": warnings,
    }
