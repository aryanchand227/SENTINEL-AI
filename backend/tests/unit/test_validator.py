"""
Unit tests for QueryValidator, FieldRegistry, and QueryCompiler.
"""

from datetime import UTC, datetime, timedelta

from backend.app.query.compiler import QueryCompiler
from backend.app.query.field_registry import (
    get_field_definition,
    is_field_approved,
    is_operator_allowed,
)
from backend.app.query.sqs import (
    AggregationType,
    FilterOperator,
    QueryAggregation,
    QueryFilter,
    SentinelQuerySpec,
    TimeRange,
)
from backend.app.query.validator import QueryValidator


class TestFieldRegistry:
    def test_approved_fields_exist(self) -> None:
        assert is_field_approved("@timestamp")
        assert is_field_approved("source.ip")
        assert is_field_approved("event.category")
        assert is_field_approved("user.name")
        assert not is_field_approved("malicious_unapproved_field")

    def test_field_definitions(self) -> None:
        fdef = get_field_definition("event.severity")
        assert fdef is not None
        assert fdef.data_type.value == "integer"
        assert fdef.aggregatable is True

    def test_operator_compatibility(self) -> None:
        # source.ip supports eq, in, exists
        assert is_operator_allowed("source.ip", FilterOperator.EQ)
        assert is_operator_allowed("source.ip", FilterOperator.IN)
        assert not is_operator_allowed("source.ip", FilterOperator.GTE)

        # event.severity supports range operators
        assert is_operator_allowed("event.severity", FilterOperator.GTE)
        assert is_operator_allowed("event.severity", FilterOperator.LT)

        # message only supports contains / exists
        assert is_operator_allowed("message", FilterOperator.CONTAINS)
        assert not is_operator_allowed("message", FilterOperator.EQ)


class TestQueryValidator:
    def setup_method(self) -> None:
        self.validator = QueryValidator()
        self.base_time = datetime(2026, 11, 16, 0, 0, 0, tzinfo=UTC)

    def test_valid_query_passes(self) -> None:
        spec = SentinelQuerySpec(
            time_range=TimeRange(
                start=self.base_time - timedelta(hours=24),
                end=self.base_time,
            ),
            filters=[
                QueryFilter(
                    field="event.category",
                    operator=FilterOperator.EQ,
                    value="authentication",
                ),
                QueryFilter(field="source.ip", operator=FilterOperator.EQ, value="192.168.1.100"),
            ],
            aggregations=[
                QueryAggregation(type=AggregationType.TERMS, field="user.name", size=10),
            ],
            intent="Find failed logins from specific IP",
        )
        res = self.validator.validate(spec)
        assert res.is_valid is True
        assert len(res.errors) == 0
        assert res.sanitized_spec is not None

    def test_reject_unapproved_field(self) -> None:
        spec = SentinelQuerySpec(
            time_range=TimeRange(
                start=self.base_time - timedelta(hours=1),
                end=self.base_time,
            ),
            filters=[
                QueryFilter(field="shadow_admin_flag", operator=FilterOperator.EQ, value="true"),
            ],
            intent="Try unapproved field",
        )
        res = self.validator.validate(spec)
        assert res.is_valid is False
        assert any(e.error_code == "UNAPPROVED_FIELD" for e in res.errors)

    def test_reject_incompatible_operator(self) -> None:
        spec = SentinelQuerySpec(
            time_range=TimeRange(
                start=self.base_time - timedelta(hours=1),
                end=self.base_time,
            ),
            filters=[
                # GTE is not allowed on IP fields
                QueryFilter(field="source.ip", operator=FilterOperator.GTE, value="192.168.1.1"),
            ],
            intent="Try invalid operator",
        )
        res = self.validator.validate(spec)
        assert res.is_valid is False
        assert any(e.error_code == "INCOMPATIBLE_OPERATOR" for e in res.errors)

    def test_reject_excessive_time_window(self) -> None:
        spec = SentinelQuerySpec(
            time_range=TimeRange(
                start=self.base_time - timedelta(days=30),  # 720 hours > 168 hours max
                end=self.base_time,
            ),
            intent="Search last 30 days",
        )
        res = self.validator.validate(spec)
        assert res.is_valid is False
        assert any(e.error_code == "TIME_WINDOW_EXCEEDED" for e in res.errors)

    def test_reject_excessive_page_size(self) -> None:
        spec = SentinelQuerySpec(
            time_range=TimeRange(
                start=self.base_time - timedelta(hours=1),
                end=self.base_time,
            ),
            page_size=10000,  # Max is 500
            intent="Dump all data",
        )
        res = self.validator.validate(spec)
        assert res.is_valid is False
        assert any(e.error_code == "PAGE_SIZE_EXCEEDED" for e in res.errors)

    def test_reject_unapproved_sort_field(self) -> None:
        spec = SentinelQuerySpec(
            time_range=TimeRange(
                start=self.base_time - timedelta(hours=1),
                end=self.base_time,
            ),
            sort_field="arbitrary_column",
            intent="Sort by unknown column",
        )
        res = self.validator.validate(spec)
        assert res.is_valid is False
        assert any(e.error_code == "UNAPPROVED_SORT_FIELD" for e in res.errors)

    def test_reject_non_aggregatable_field(self) -> None:
        spec = SentinelQuerySpec(
            time_range=TimeRange(
                start=self.base_time - timedelta(hours=1),
                end=self.base_time,
            ),
            aggregations=[
                QueryAggregation(type=AggregationType.TERMS, field="message", size=10),
            ],
            intent="Aggregate on full message text",
        )
        res = self.validator.validate(spec)
        assert res.is_valid is False
        assert any(e.error_code == "NON_AGGREGATABLE_FIELD" for e in res.errors)


class TestQueryCompiler:
    def test_compile_to_search_request(self) -> None:
        now = datetime.now(UTC)
        spec = SentinelQuerySpec(
            time_range=TimeRange(start=now - timedelta(hours=2), end=now),
            filters=[
                QueryFilter(
                    field="event.category",
                    operator=FilterOperator.EQ,
                    value="authentication",
                ),
                QueryFilter(field="event.outcome", operator=FilterOperator.EQ, value="failure"),
            ],
            aggregations=[
                QueryAggregation(type=AggregationType.TERMS, field="source.ip", size=5),
            ],
            sort_field="@timestamp",
            sort_order="asc",
            page_size=50,
            intent="Find failed authentication",
        )
        req = QueryCompiler.compile_to_search_request(spec)
        assert req.time_start == spec.time_range.start
        assert req.time_end == spec.time_range.end
        assert len(req.filters) == 2
        assert req.filters[0]["field"] == "event.category"
        assert req.filters[0]["operator"] == "eq"
        assert req.filters[0]["value"] == "authentication"
        assert len(req.aggregations) == 1
        assert req.aggregations[0]["type"] == "terms"
        assert req.aggregations[0]["field"] == "source.ip"
        assert req.aggregations[0]["size"] == 5
        assert req.sort_order == "asc"
        assert req.page_size == 50
