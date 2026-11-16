"""
SENTINEL AI — Elasticsearch Query DSL Compiler.

Deterministically compiles validated SearchRequest into read-only
Elasticsearch 8.x Query DSL. Rejects write/script constructs.
"""

from __future__ import annotations

from typing import Any

from backend.app.query.field_registry import FieldDataType, get_field_definition
from backend.app.siem.provider_interface import SearchRequest


class ElasticsearchDslCompiler:
    """Compiles SearchRequest into Elasticsearch 8.x Query DSL."""

    @classmethod
    def compile(cls, request: SearchRequest) -> dict[str, Any]:
        filters: list[dict[str, Any]] = []

        # Time range filter
        if request.time_start or request.time_end:
            time_range_filter: dict[str, Any] = {}
            if request.time_start:
                time_range_filter["gte"] = request.time_start.isoformat()
            if request.time_end:
                time_range_filter["lte"] = request.time_end.isoformat()
            filters.append({"range": {"@timestamp": time_range_filter}})

        # Field filters
        for f in request.filters:
            field = f.get("field", "")
            operator = f.get("operator", "eq")
            value = f.get("value")

            field_def = get_field_definition(field)
            is_text = field_def is not None and field_def.data_type == FieldDataType.TEXT

            if operator == "eq":
                filters.append({"term": {field: value}})
            elif operator == "in":
                filters.append({"terms": {field: value}})
            elif operator == "contains":
                if is_text:
                    filters.append({"match": {field: value}})
                else:
                    filters.append({"wildcard": {field: f"*{value}*"}})
            elif operator in ("gte", "lte", "gt", "lt"):
                filters.append({"range": {field: {operator: value}}})
            elif operator == "exists":
                filters.append({"exists": {"field": field}})

        query: dict[str, Any] = {"bool": {"filter": filters}} if filters else {"match_all": {}}

        # Sorting
        sort: list[dict[str, Any]] = []
        if request.sort_field:
            sort.append({request.sort_field: {"order": request.sort_order}})

        # Build final DSL body
        body: dict[str, Any] = {
            "query": query,
            "sort": sort,
            "size": min(request.page_size, 500),
        }

        # Source filtering (requested fields)
        if request.requested_fields:
            body["_source"] = request.requested_fields

        # Aggregations
        if request.aggregations:
            aggs_dict: dict[str, Any] = {}
            for agg in request.aggregations:
                agg_type = agg.get("type", "terms")
                agg_field = agg.get("field", "")
                agg_name = agg.get("name", f"{agg_type}_{agg_field}")

                if agg_type == "terms":
                    size = min(agg.get("size", 10), 100)
                    aggs_dict[agg_name] = {"terms": {"field": agg_field, "size": size}}
                elif agg_type == "date_histogram":
                    interval = agg.get("interval", "1h")
                    aggs_dict[agg_name] = {
                        "date_histogram": {
                            "field": agg_field,
                            "fixed_interval": interval,
                        }
                    }
                elif agg_type == "value_count":
                    aggs_dict[agg_name] = {"value_count": {"field": agg_field}}

            body["aggs"] = aggs_dict

        return body
