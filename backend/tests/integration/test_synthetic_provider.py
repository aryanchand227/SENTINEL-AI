"""
Integration tests for synthetic provider — filtering, aggregation, pagination.
"""

from datetime import UTC, datetime, timedelta

import pytest

from backend.app.domain.events import EventCategory, EventOutcome
from backend.app.siem.provider_interface import SearchRequest
from backend.app.siem.synthetic.provider import SyntheticProvider


@pytest.fixture
def provider() -> SyntheticProvider:
    return SyntheticProvider(seed=42)


class TestSyntheticProviderHealth:
    @pytest.mark.asyncio
    async def test_health_check(self, provider: SyntheticProvider) -> None:
        result = await provider.health_check()
        assert result.provider == "synthetic"
        assert result.status.value == "healthy"
        assert "events loaded" in (result.message or "")


class TestSyntheticProviderSearch:
    @pytest.mark.asyncio
    async def test_search_all_events(self, provider: SyntheticProvider) -> None:
        """Search without filters returns all events."""
        result = await provider.search(SearchRequest(page_size=200))
        assert result.metadata.total_hits == 94
        assert result.metadata.provider == "synthetic"

    @pytest.mark.asyncio
    async def test_filter_by_category(self, provider: SyntheticProvider) -> None:
        """Filter by event.category == authentication."""
        result = await provider.search(
            SearchRequest(
                filters=[{"field": "event.category", "operator": "eq", "value": "authentication"}],
                page_size=200,
            )
        )
        assert result.metadata.total_hits > 0
        for e in result.events:
            assert e.event.category == EventCategory.AUTHENTICATION

    @pytest.mark.asyncio
    async def test_filter_by_outcome(self, provider: SyntheticProvider) -> None:
        """Filter by event.outcome == failure."""
        result = await provider.search(
            SearchRequest(
                filters=[{"field": "event.outcome", "operator": "eq", "value": "failure"}],
                page_size=200,
            )
        )
        assert result.metadata.total_hits > 0
        for e in result.events:
            assert e.event.outcome == EventOutcome.FAILURE

    @pytest.mark.asyncio
    async def test_filter_by_source_ip(self, provider: SyntheticProvider) -> None:
        """Filter by source.ip."""
        result = await provider.search(
            SearchRequest(
                filters=[{"field": "source.ip", "operator": "eq", "value": "192.168.1.100"}],
                page_size=200,
            )
        )
        assert result.metadata.total_hits == 20  # SSH brute force scenario 1
        for e in result.events:
            assert e.source is not None
            assert e.source.ip == "192.168.1.100"

    @pytest.mark.asyncio
    async def test_filter_by_severity_gte(self, provider: SyntheticProvider) -> None:
        """Filter by event.severity >= 75 (HIGH+)."""
        result = await provider.search(
            SearchRequest(
                filters=[{"field": "event.severity", "operator": "gte", "value": 75}],
                page_size=200,
            )
        )
        assert result.metadata.total_hits > 0
        for e in result.events:
            assert e.event.severity >= 75

    @pytest.mark.asyncio
    async def test_time_range_filter(self, provider: SyntheticProvider) -> None:
        """Filter by time range."""
        base = datetime(2026, 11, 16, 0, 0, 0, tzinfo=UTC)
        result = await provider.search(
            SearchRequest(
                time_start=base - timedelta(hours=6),
                time_end=base,
                page_size=200,
            )
        )
        assert result.metadata.total_hits > 0
        for e in result.events:
            assert e.timestamp >= base - timedelta(hours=6)
            assert e.timestamp <= base

    @pytest.mark.asyncio
    async def test_combined_filters(self, provider: SyntheticProvider) -> None:
        """Multiple filters applied together (AND)."""
        result = await provider.search(
            SearchRequest(
                filters=[
                    {"field": "event.category", "operator": "eq", "value": "authentication"},
                    {"field": "event.outcome", "operator": "eq", "value": "failure"},
                    {"field": "source.ip", "operator": "eq", "value": "10.0.0.55"},
                ],
                page_size=200,
            )
        )
        assert result.metadata.total_hits == 15  # Scenario 2 failures only

    @pytest.mark.asyncio
    async def test_pagination(self, provider: SyntheticProvider) -> None:
        """Pagination works with cursor."""
        # Get first page
        r1 = await provider.search(SearchRequest(page_size=10))
        assert r1.metadata.returned_count == 10
        assert r1.metadata.next_cursor is not None

        # Get second page
        r2 = await provider.search(SearchRequest(page_size=10, cursor=r1.metadata.next_cursor))
        assert r2.metadata.returned_count == 10

        # Events should not overlap
        ids1 = {e.event.id for e in r1.events}
        ids2 = {e.event.id for e in r2.events}
        assert ids1.isdisjoint(ids2)

    @pytest.mark.asyncio
    async def test_sort_ascending(self, provider: SyntheticProvider) -> None:
        """Events sorted by timestamp ascending."""
        result = await provider.search(
            SearchRequest(
                sort_field="@timestamp",
                sort_order="asc",
                page_size=200,
            )
        )
        timestamps = [e.timestamp for e in result.events]
        assert timestamps == sorted(timestamps)

    @pytest.mark.asyncio
    async def test_terms_aggregation(self, provider: SyntheticProvider) -> None:
        """Terms aggregation on event.category."""
        result = await provider.search(
            SearchRequest(
                aggregations=[{"type": "terms", "field": "event.category", "name": "by_category"}],
                page_size=200,
            )
        )
        assert len(result.aggregations) == 1
        agg = result.aggregations[0]
        assert agg.name == "by_category"
        assert len(agg.buckets) > 0
        total_from_agg = sum(b.doc_count for b in agg.buckets)
        assert total_from_agg == result.metadata.total_hits

    @pytest.mark.asyncio
    async def test_terms_aggregation_source_ip(self, provider: SyntheticProvider) -> None:
        """Terms aggregation on source.ip — top IPs."""
        result = await provider.search(
            SearchRequest(
                aggregations=[
                    {"type": "terms", "field": "source.ip", "name": "top_ips", "size": 5}
                ],
                page_size=200,
            )
        )
        assert len(result.aggregations) == 1
        agg = result.aggregations[0]
        assert agg.name == "top_ips"
        assert len(agg.buckets) <= 5
        # Most common IP should be the SSH brute force IP
        assert agg.buckets[0].key in ["192.168.1.100", "203.0.113.42"]

    @pytest.mark.asyncio
    async def test_value_count_aggregation(self, provider: SyntheticProvider) -> None:
        """Value count aggregation."""
        result = await provider.search(
            SearchRequest(
                aggregations=[{"type": "value_count", "field": "user.name", "name": "user_count"}],
                page_size=200,
            )
        )
        assert len(result.aggregations) == 1
        assert result.aggregations[0].buckets[0].doc_count > 0

    @pytest.mark.asyncio
    async def test_date_histogram_aggregation(self, provider: SyntheticProvider) -> None:
        """Date histogram aggregation."""
        result = await provider.search(
            SearchRequest(
                aggregations=[
                    {"type": "date_histogram", "field": "@timestamp", "name": "timeline"}
                ],
                page_size=200,
            )
        )
        assert len(result.aggregations) == 1
        agg = result.aggregations[0]
        assert agg.name == "timeline"
        assert len(agg.buckets) > 0

    @pytest.mark.asyncio
    async def test_empty_result_not_error(self, provider: SyntheticProvider) -> None:
        """No matching events returns empty result, not an error."""
        result = await provider.search(
            SearchRequest(
                filters=[{"field": "source.ip", "operator": "eq", "value": "1.2.3.4"}],
            )
        )
        assert result.metadata.total_hits == 0
        assert len(result.events) == 0

    @pytest.mark.asyncio
    async def test_contains_filter(self, provider: SyntheticProvider) -> None:
        """Contains filter on message field."""
        result = await provider.search(
            SearchRequest(
                filters=[{"field": "message", "operator": "contains", "value": "malware"}],
                page_size=200,
            )
        )
        assert result.metadata.total_hits >= 1
        for e in result.events:
            assert "malware" in (e.message or "").lower()

    @pytest.mark.asyncio
    async def test_field_mappings(self, provider: SyntheticProvider) -> None:
        """get_field_mappings returns ECS-compatible fields."""
        mappings = await provider.get_field_mappings()
        assert "@timestamp" in mappings
        assert "event.id" in mappings
        assert "source.ip" in mappings
        assert mappings["source.ip"] == "ip"
        assert mappings["event.severity"] == "integer"
