"""
SENTINEL AI — Intent Planner & Multi-Turn Context Resolver.

Extracts structured intent, entities, time ranges, and produces
validated Sentinel Query Specifications (SQS).
Implements multi-turn context merge rules per Section 9.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from pydantic import BaseModel, ConfigDict, Field

from backend.app.query.sqs import (
    AggregationType,
    FilterOperator,
    QueryAggregation,
    QueryFilter,
    SentinelQuerySpec,
    TimeRange,
)


class InvestigationContext(BaseModel):
    """Preserved multi-turn investigation context."""

    model_config = ConfigDict(extra="forbid")

    prior_time_range: TimeRange | None = None
    target_accounts: list[str] = Field(default_factory=list)
    target_ips: list[str] = Field(default_factory=list)
    target_hosts: list[str] = Field(default_factory=list)
    prior_evidence_ids: list[str] = Field(default_factory=list)
    prior_spec: SentinelQuerySpec | None = None


class IntentPlanner:
    """
    Interprets natural language analyst inquiries into typed SQS.
    Resolves multi-turn references against prior investigation context.
    """

    def __init__(self, base_time: datetime | None = None) -> None:
        self._base_time = base_time or datetime(2026, 11, 16, 0, 0, 0, tzinfo=UTC)

    def plan_query(
        self,
        prompt: str,
        context: InvestigationContext | None = None,
    ) -> tuple[SentinelQuerySpec, str]:
        """
        Parse natural language prompt and return (SentinelQuerySpec, intent_summary).
        """
        lower = prompt.lower().strip()

        # Detect Time Window
        time_range = self._extract_time_range(lower, context)

        # Multi-turn follow-up: "Did any of those accounts log in successfully afterwards?"
        if ("those accounts" in lower or "any of them" in lower) and "success" in lower:
            accounts = context.target_accounts if context else []
            filters: list[QueryFilter] = [
                QueryFilter(
                    field="event.category", operator=FilterOperator.EQ, value="authentication"
                ),
                QueryFilter(field="event.outcome", operator=FilterOperator.EQ, value="success"),
            ]
            if accounts:
                if len(accounts) == 1:
                    filters.append(
                        QueryFilter(
                            field="user.name", operator=FilterOperator.EQ, value=accounts[0]
                        )
                    )
                else:
                    filters.append(
                        QueryFilter(field="user.name", operator=FilterOperator.IN, value=accounts)
                    )

            spec = SentinelQuerySpec(
                provider="synthetic",
                time_range=time_range,
                filters=filters,
                sort_field="@timestamp",
                sort_order="asc",
                page_size=100,
                intent="Follow-up: Check successful logins for suspect accounts",
            )
            return spec, "Checking for successful logins among targeted accounts"

        # Check for SSH brute force or failed logins
        if "failed" in lower and ("login" in lower or "ssh" in lower or "account" in lower):
            filters = [
                QueryFilter(
                    field="event.category", operator=FilterOperator.EQ, value="authentication"
                ),
                QueryFilter(field="event.outcome", operator=FilterOperator.EQ, value="failure"),
            ]
            aggs: list[QueryAggregation] = [
                QueryAggregation(type=AggregationType.TERMS, field="user.name", size=10),
                QueryAggregation(type=AggregationType.TERMS, field="source.ip", size=5),
            ]

            spec = SentinelQuerySpec(
                provider="synthetic",
                time_range=time_range,
                filters=filters,
                aggregations=aggs,
                sort_field="@timestamp",
                sort_order="desc",
                page_size=100,
                intent="Search authentication failures and aggregate by account and source IP",
            )
            return spec, "Identifying failed authentication attempts and affected accounts"

        # Top IPs / source IP aggregation
        if "source ip" in lower or "top ip" in lower:
            spec = SentinelQuerySpec(
                provider="synthetic",
                time_range=time_range,
                filters=context.prior_spec.filters if context and context.prior_spec else [],
                aggregations=[
                    QueryAggregation(type=AggregationType.TERMS, field="source.ip", size=10),
                ],
                sort_field="@timestamp",
                sort_order="desc",
                page_size=50,
                intent="Aggregate top source IPs for investigation scope",
            )
            return spec, "Aggregating top source IPs"

        # Malware investigation
        if "malware" in lower or "trojan" in lower:
            spec = SentinelQuerySpec(
                provider="synthetic",
                time_range=time_range,
                filters=[
                    QueryFilter(
                        field="event.category", operator=FilterOperator.EQ, value="malware"
                    ),
                ],
                sort_field="@timestamp",
                sort_order="desc",
                page_size=50,
                intent="Retrieve malware detection alerts",
            )
            return spec, "Searching for malware detection alerts"

        # Suspicious PowerShell execution
        if "powershell" in lower or "process" in lower:
            spec = SentinelQuerySpec(
                provider="synthetic",
                time_range=time_range,
                filters=[
                    QueryFilter(
                        field="event.category", operator=FilterOperator.EQ, value="process"
                    ),
                ],
                sort_field="@timestamp",
                sort_order="desc",
                page_size=50,
                intent="Retrieve suspicious process and PowerShell activity",
            )
            return spec, "Searching for process creation and PowerShell activity"

        # Generic default query: all security alerts / events in time window
        spec = SentinelQuerySpec(
            provider="synthetic",
            time_range=time_range,
            filters=[],
            aggregations=[
                QueryAggregation(type=AggregationType.TERMS, field="event.category", size=10),
            ],
            sort_field="@timestamp",
            sort_order="desc",
            page_size=100,
            intent=f"General investigation query for: {prompt[:60]}",
        )
        return spec, "General event retrieval"

    def _extract_time_range(self, text: str, context: InvestigationContext | None) -> TimeRange:
        """Parse time expression from prompt or fall back to context / default 24h."""
        now = self._base_time

        # Check explicit hours
        hours_match = re.search(r"last\s+(\d+)\s+hour", text)
        if hours_match:
            hours = int(hours_match.group(1))
            return TimeRange(start=now - timedelta(hours=hours), end=now)

        # Check explicit days
        days_match = re.search(r"last\s+(\d+)\s+day", text)
        if days_match:
            days = int(days_match.group(1))
            return TimeRange(start=now - timedelta(days=days), end=now)

        # "Today"
        if "today" in text:
            start_of_day = now.replace(hour=0, minute=0, second=0, microsecond=0)
            return TimeRange(start=start_of_day, end=now)

        # Context inheritance (Section 9: unmentioned constraints remain unchanged)
        if context and context.prior_time_range:
            return context.prior_time_range

        # Product default: 24 hours
        return TimeRange(start=now - timedelta(hours=24), end=now)
