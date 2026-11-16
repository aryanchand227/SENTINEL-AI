"""
SENTINEL AI — Query Compiler.

Deterministically compiles a validated SentinelQuerySpec (SQS) into a
SearchRequest suitable for execution by the target SIEM provider.
"""

from __future__ import annotations

from typing import Any

from backend.app.query.sqs import SentinelQuerySpec
from backend.app.siem.provider_interface import SearchRequest


class QueryCompiler:
    """Compiles validated SQS to provider-ready SearchRequest."""

    @staticmethod
    def compile_to_search_request(spec: SentinelQuerySpec) -> SearchRequest:
        """Transform SQS to ProviderInterface SearchRequest."""
        # Compile filters
        compiled_filters: list[dict[str, Any]] = []
        for f in spec.filters:
            compiled_filters.append({
                "field": f.field,
                "operator": f.operator.value,
                "value": f.value,
            })

        # Compile aggregations
        compiled_aggs: list[dict[str, Any]] = []
        for agg in spec.aggregations:
            agg_dict: dict[str, Any] = {
                "type": agg.type.value,
                "field": agg.field,
                "name": f"{agg.type.value}_{agg.field}",
            }
            if agg.size is not None:
                agg_dict["size"] = agg.size
            if agg.interval is not None:
                agg_dict["interval"] = agg.interval
            compiled_aggs.append(agg_dict)

        return SearchRequest(
            filters=compiled_filters,
            time_start=spec.time_range.start,
            time_end=spec.time_range.end,
            sort_field=spec.sort_field,
            sort_order=spec.sort_order,
            page_size=spec.page_size,
            cursor=spec.cursor,
            aggregations=compiled_aggs,
            requested_fields=spec.requested_fields,
        )
