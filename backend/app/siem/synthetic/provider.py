"""
SENTINEL AI — Synthetic provider.

Implements the ProviderInterface contract using deterministic
generated events. Supports filtering, sorting, pagination, and aggregations.
"""

from __future__ import annotations

import time
from collections import Counter
from datetime import UTC, datetime
from typing import Any

from backend.app.domain.events import SecurityEvent
from backend.app.siem.provider_interface import (
    AggregationBucket,
    AggregationResult,
    ProviderHealthResult,
    ProviderInterface,
    ProviderSearchResult,
    ProviderStatus,
    SearchRequest,
    SearchResultMetadata,
)
from backend.app.siem.synthetic.generator import SyntheticEventGenerator


def _get_nested_value(event: SecurityEvent, field: str) -> Any:
    """Extract a nested field value from a SecurityEvent using dot notation."""
    if field == "@timestamp":
        return event.timestamp

    parts = field.split(".")
    obj: Any = event

    for part in parts:
        if obj is None:
            return None
        if isinstance(obj, dict):
            obj = obj.get(part)
        elif hasattr(obj, part):
            obj = getattr(obj, part)
        else:
            return None

    return obj


def _match_filter(event: SecurityEvent, filt: dict[str, Any]) -> bool:
    """Evaluate a single filter against an event."""
    field = filt.get("field", "")
    operator = filt.get("operator", "eq")
    value = filt.get("value")

    actual = _get_nested_value(event, field)

    if operator == "eq":
        return bool(actual == value)
    elif operator == "in":
        if isinstance(value, list):
            return bool(actual in value)
        return bool(actual == value)
    elif operator == "contains":
        if actual is None:
            return False
        return str(value).lower() in str(actual).lower()
    elif operator == "gte":
        if actual is None or value is None:
            return False
        return bool(actual >= value)
    elif operator == "lte":
        if actual is None or value is None:
            return False
        return bool(actual <= value)
    elif operator == "gt":
        if actual is None or value is None:
            return False
        return bool(actual > value)
    elif operator == "lt":
        if actual is None or value is None:
            return False
        return bool(actual < value)
    elif operator == "exists":
        return actual is not None
    else:
        return False


class SyntheticProvider(ProviderInterface):
    """
    In-memory synthetic SIEM provider.

    Uses deterministic generated events, supports time/field filters,
    sorting, pagination, and term aggregations.
    """

    def __init__(self, seed: int = 42, base_time: datetime | None = None) -> None:
        self._generator = SyntheticEventGenerator(seed=seed, base_time=base_time)
        self._events: list[SecurityEvent] | None = None

    def _ensure_events(self) -> list[SecurityEvent]:
        if self._events is None:
            self._events = self._generator.generate_all()
        return self._events

    @property
    def name(self) -> str:
        return "synthetic"

    async def health_check(self) -> ProviderHealthResult:
        events = self._ensure_events()
        return ProviderHealthResult(
            provider=self.name,
            status=ProviderStatus.HEALTHY,
            version="1.0.0",
            message=f"Synthetic provider healthy. {len(events)} events loaded.",
            checked_at=datetime.now(UTC),
        )

    async def search(self, request: SearchRequest) -> ProviderSearchResult:
        start_time = time.monotonic()
        all_events = self._ensure_events()
        matched: list[SecurityEvent] = []

        for event in all_events:
            # Time filter
            if request.time_start and event.timestamp < request.time_start:
                continue
            if request.time_end and event.timestamp > request.time_end:
                continue

            # Field filters
            if request.filters:
                if not all(_match_filter(event, f) for f in request.filters):
                    continue

            matched.append(event)

        # Sorting
        sort_field = request.sort_field or "@timestamp"
        reverse = request.sort_order == "desc"
        matched.sort(
            key=lambda e: _get_nested_value(e, sort_field) or "",
            reverse=reverse,
        )

        total_hits = len(matched)

        # Pagination via cursor (offset-based for synthetic)
        offset = int(request.cursor) if request.cursor else 0
        page_size = min(request.page_size, 500)
        page = matched[offset : offset + page_size]

        next_cursor = None
        if offset + page_size < total_hits:
            next_cursor = str(offset + page_size)

        # Aggregations
        agg_results: list[AggregationResult] = []
        for agg in request.aggregations:
            agg_type = agg.get("type", "terms")
            agg_field = agg.get("field", "")
            agg_size = agg.get("size", 10)
            agg_name = agg.get("name", agg_field)

            if agg_type == "terms":
                counter: Counter[str] = Counter()
                for event in matched:
                    val = _get_nested_value(event, agg_field)
                    if val is not None:
                        counter[str(val)] += 1
                buckets = [
                    AggregationBucket(key=k, doc_count=c)
                    for k, c in counter.most_common(agg_size)
                ]
                agg_results.append(AggregationResult(name=agg_name, buckets=buckets))

            elif agg_type == "value_count":
                count = sum(1 for e in matched if _get_nested_value(e, agg_field) is not None)
                agg_results.append(AggregationResult(
                    name=agg_name,
                    buckets=[AggregationBucket(key="_count", doc_count=count)],
                ))

            elif agg_type == "date_histogram":
                # Simple hourly bucketing for synthetic
                from collections import defaultdict
                buckets_dict: dict[str, int] = defaultdict(int)
                for event in matched:
                    ts = event.timestamp
                    hour_key = ts.strftime("%Y-%m-%dT%H:00:00Z")
                    buckets_dict[hour_key] += 1
                sorted_keys = sorted(buckets_dict.keys())
                buckets = [
                    AggregationBucket(key=k, doc_count=buckets_dict[k])
                    for k in sorted_keys
                ]
                agg_results.append(AggregationResult(name=agg_name, buckets=buckets))

        elapsed_ms = int((time.monotonic() - start_time) * 1000)

        return ProviderSearchResult(
            events=page,
            metadata=SearchResultMetadata(
                total_hits=total_hits,
                returned_count=len(page),
                took_ms=elapsed_ms,
                next_cursor=next_cursor,
                provider=self.name,
            ),
            aggregations=agg_results,
        )

    async def get_field_mappings(self) -> dict[str, str]:
        """Return the field mappings supported by the synthetic provider."""
        return {
            "@timestamp": "date",
            "event.id": "keyword",
            "event.kind": "keyword",
            "event.category": "keyword",
            "event.type": "keyword",
            "event.action": "keyword",
            "event.outcome": "keyword",
            "event.severity": "integer",
            "message": "text",
            "source.ip": "ip",
            "source.port": "integer",
            "destination.ip": "ip",
            "destination.port": "integer",
            "user.name": "keyword",
            "user.id": "keyword",
            "host.name": "keyword",
            "host.id": "keyword",
            "host.os.name": "keyword",
            "process.name": "keyword",
            "process.command_line": "text",
            "process.pid": "integer",
            "file.path": "keyword",
            "file.hash.sha256": "keyword",
            "rule.id": "keyword",
            "rule.name": "keyword",
            "agent.id": "keyword",
            "agent.name": "keyword",
            "network.protocol": "keyword",
            "observer.name": "keyword",
            "sentinel.source.provider": "keyword",
            "sentinel.data_mode": "keyword",
        }
