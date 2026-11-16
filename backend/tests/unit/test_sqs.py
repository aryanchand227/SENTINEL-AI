"""
Unit tests for Sentinel Query Specification (SQS) models.
"""

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from backend.app.query.sqs import (
    AggregationType,
    FilterOperator,
    QueryAggregation,
    QueryFilter,
    SentinelQuerySpec,
    TimeRange,
)


class TestTimeRange:
    def test_valid_time_range(self) -> None:
        start = datetime(2026, 1, 1, tzinfo=UTC)
        end = start + timedelta(hours=24)
        tr = TimeRange(start=start, end=end)
        assert tr.start == start
        assert tr.end == end

    def test_invalid_start_after_end(self) -> None:
        start = datetime(2026, 1, 2, tzinfo=UTC)
        end = datetime(2026, 1, 1, tzinfo=UTC)
        with pytest.raises(ValidationError, match="must be before end"):
            TimeRange(start=start, end=end)

    def test_extra_fields_forbidden(self) -> None:
        start = datetime(2026, 1, 1, tzinfo=UTC)
        end = datetime(2026, 1, 2, tzinfo=UTC)
        with pytest.raises(ValidationError):
            TimeRange(start=start, end=end, extra="disallowed")  # type: ignore[call-arg]


class TestQueryFilter:
    def test_valid_eq_filter(self) -> None:
        qf = QueryFilter(field="event.category", operator=FilterOperator.EQ, value="authentication")
        assert qf.field == "event.category"
        assert qf.operator == FilterOperator.EQ
        assert qf.value == "authentication"

    def test_in_operator_requires_list(self) -> None:
        with pytest.raises(ValidationError, match="must have a list value"):
            QueryFilter(field="source.ip", operator=FilterOperator.IN, value="1.2.3.4")

    def test_exists_operator_does_not_need_value(self) -> None:
        qf = QueryFilter(field="file.hash.sha256", operator=FilterOperator.EXISTS)
        assert qf.operator == FilterOperator.EXISTS
        assert qf.value is None

    def test_non_exists_requires_value(self) -> None:
        with pytest.raises(ValidationError, match="requires a non-null value"):
            QueryFilter(field="host.name", operator=FilterOperator.EQ, value=None)


class TestSentinelQuerySpec:
    def test_valid_spec_creation(self) -> None:
        now = datetime.now(UTC)
        spec = SentinelQuerySpec(
            time_range=TimeRange(start=now - timedelta(hours=1), end=now),
            filters=[
                QueryFilter(
                    field="event.category",
                    operator=FilterOperator.EQ,
                    value="authentication",
                ),
                QueryFilter(field="event.outcome", operator=FilterOperator.EQ, value="failure"),
            ],
            aggregations=[
                QueryAggregation(type=AggregationType.TERMS, field="source.ip", size=10),
            ],
            intent="Find failed logins in last hour",
        )
        assert spec.provider == "synthetic"
        assert len(spec.filters) == 2
        assert len(spec.aggregations) == 1
        assert spec.page_size == 100

    def test_extra_fields_forbidden(self) -> None:
        now = datetime.now(UTC)
        with pytest.raises(ValidationError):
            SentinelQuerySpec(
                time_range=TimeRange(start=now - timedelta(hours=1), end=now),
                intent="test",
                unauthorized_script="System.exit(0)",  # type: ignore[call-arg]
            )
