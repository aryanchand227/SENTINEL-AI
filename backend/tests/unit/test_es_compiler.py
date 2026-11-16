"""
Unit tests for Elasticsearch Query DSL Compiler.
"""

from __future__ import annotations

from datetime import UTC, datetime

from backend.app.siem.elasticsearch.compiler import ElasticsearchDslCompiler
from backend.app.siem.provider_interface import SearchRequest


def test_compiler_empty_request() -> None:
    req = SearchRequest()
    dsl = ElasticsearchDslCompiler.compile(req)
    assert dsl["query"] == {"match_all": {}}
    assert dsl["size"] == 100
    assert dsl["sort"] == [{"@timestamp": {"order": "desc"}}]
    assert "aggs" not in dsl


def test_compiler_time_range() -> None:
    t_start = datetime(2025, 1, 15, 10, 0, 0, tzinfo=UTC)
    t_end = datetime(2025, 1, 15, 12, 0, 0, tzinfo=UTC)
    req = SearchRequest(time_start=t_start, time_end=t_end)

    dsl = ElasticsearchDslCompiler.compile(req)
    filters = dsl["query"]["bool"]["filter"]
    assert len(filters) == 1
    assert filters[0] == {
        "range": {
            "@timestamp": {
                "gte": t_start.isoformat(),
                "lte": t_end.isoformat(),
            }
        }
    }


def test_compiler_field_filters() -> None:
    req = SearchRequest(
        filters=[
            {"field": "user.name", "operator": "eq", "value": "jdoe"},
            {"field": "event.outcome", "operator": "in", "value": ["failure", "unknown"]},
            {"field": "event.severity", "operator": "gte", "value": 75},
            {"field": "message", "operator": "contains", "value": "powershell"},
            {"field": "source.ip", "operator": "exists"},
        ]
    )
    dsl = ElasticsearchDslCompiler.compile(req)
    filters = dsl["query"]["bool"]["filter"]
    assert {"term": {"user.name": "jdoe"}} in filters
    assert {"terms": {"event.outcome": ["failure", "unknown"]}} in filters
    assert {"range": {"event.severity": {"gte": 75}}} in filters
    assert {"match": {"message": "powershell"}} in filters
    assert {"exists": {"field": "source.ip"}} in filters


def test_compiler_wildcard_for_non_text_contains() -> None:
    req = SearchRequest(
        filters=[
            {"field": "user.name", "operator": "contains", "value": "admin"},
        ]
    )
    dsl = ElasticsearchDslCompiler.compile(req)
    filters = dsl["query"]["bool"]["filter"]
    assert {"wildcard": {"user.name": "*admin*"}} in filters


def test_compiler_aggregations_and_source() -> None:
    req = SearchRequest(
        requested_fields=["@timestamp", "user.name", "event.outcome"],
        aggregations=[
            {"type": "terms", "field": "user.name", "size": 15, "name": "top_users"},
            {"type": "date_histogram", "field": "@timestamp", "interval": "30m"},
            {"type": "value_count", "field": "event.id", "name": "total_events"},
        ],
    )
    dsl = ElasticsearchDslCompiler.compile(req)
    assert dsl["_source"] == ["@timestamp", "user.name", "event.outcome"]
    aggs = dsl["aggs"]
    assert aggs["top_users"] == {"terms": {"field": "user.name", "size": 15}}
    assert aggs["date_histogram_@timestamp"] == {
        "date_histogram": {"field": "@timestamp", "fixed_interval": "30m"}
    }
    assert aggs["total_events"] == {"value_count": {"field": "event.id"}}
