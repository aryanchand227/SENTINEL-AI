"""
SENTINEL AI — Query Execution Node.

Compiles validated SQS and executes query against active SIEM provider.
"""

from __future__ import annotations

from typing import Any

from backend.app.agents.state import InvestigationState
from backend.app.query.compiler import QueryCompiler
from backend.app.siem.registry import get_provider_registry


async def execute_query_node(state: InvestigationState) -> dict[str, Any]:
    """Execute compiled query using registered provider."""
    query_plan = state.get("query_plan")
    errors = list(state.get("errors", []))
    warnings = list(state.get("warnings", []))

    if query_plan is None:
        return {
            "events": [],
            "evidence_ids": [],
            "errors": errors + ["Cannot execute without query plan."],
        }

    # Compile SQS to SearchRequest
    search_request = QueryCompiler.compile_to_search_request(query_plan)

    provider_name = state.get("provider_name", "synthetic")
    registry = get_provider_registry()

    try:
        provider = registry.get_provider(provider_name)
        search_result = await provider.search(search_request)

        events = search_result.events
        evidence_ids = [e.event.id for e in events]

        for warn in search_result.metadata.warnings:
            warnings.append(warn)

        compiled_metadata = {
            "page_size": search_request.page_size,
            "sort_field": search_request.sort_field,
            "sort_order": search_request.sort_order,
            "filter_count": len(search_request.filters),
            "aggregation_count": len(search_request.aggregations),
        }

        provider_metadata = {
            "total_hits": search_result.metadata.total_hits,
            "returned_count": search_result.metadata.returned_count,
            "took_ms": search_result.metadata.took_ms,
            "provider": search_result.metadata.provider,
            "is_partial": search_result.metadata.is_partial,
        }

        return {
            "events": events,
            "evidence_ids": evidence_ids,
            "compiled_query_metadata": compiled_metadata,
            "provider_results_metadata": provider_metadata,
            "warnings": warnings,
            "errors": errors,
        }
    except Exception as e:
        errors.append(f"Provider execution error ({provider_name}): {e}")
        return {
            "events": [],
            "evidence_ids": [],
            "warnings": warnings,
            "errors": errors,
        }
