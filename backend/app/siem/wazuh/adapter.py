"""
SENTINEL AI — Wazuh Manager API Provider Adapter.

Implements the ProviderInterface for Wazuh endpoint security manager.
Handles JWT token authentication against /security/user/authenticate.
Normalizes Wazuh alerts into canonical SecurityEvent models.
"""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime
from typing import Any

import httpx

from backend.app.core.config import Settings, get_settings
from backend.app.domain.events import (
    AgentFields,
    DataMode,
    DestinationFields,
    EventCategory,
    EventFields,
    EventKind,
    EventOutcome,
    HostFields,
    RuleFields,
    SecurityEvent,
    SentinelMetadata,
    SentinelSource,
    SourceFields,
    UserFields,
)
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

logger = logging.getLogger(__name__)


def _map_wazuh_level_to_severity(level: int) -> int:
    """
    Map Wazuh alert level (1-16) to canonical ECS severity scale (0-100).
    Levels 1-3: Low (25)
    Levels 4-7: Medium (50)
    Levels 8-11: High (75)
    Levels 12-16: Critical (100)
    """
    if level >= 12:
        return 100
    elif level >= 8:
        return 75
    elif level >= 4:
        return 50
    return 25


def _normalize_wazuh_alert(alert: dict[str, Any]) -> SecurityEvent:
    """Normalize a Wazuh alert dictionary into a canonical SecurityEvent."""
    alert_id = str(alert.get("id") or alert.get("_id") or "wazuh-alert")
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    data = alert.get("data", {})

    # Timestamp
    ts_str = alert.get("timestamp")
    if ts_str:
        try:
            timestamp = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            timestamp = datetime.now(UTC)
    else:
        timestamp = datetime.now(UTC)

    # Determine category from rule groups
    groups = rule.get("groups", [])
    category = EventCategory.AUTHENTICATION
    if "pci_dss_11.5" in groups or "syscheck" in groups:
        category = EventCategory.FILE
    elif "web" in groups:
        category = EventCategory.WEB
    elif "rootcheck" in groups or "ossec" in groups:
        category = EventCategory.HOST
    elif "malware" in groups or "virus" in groups:
        category = EventCategory.MALWARE

    # Event fields
    level = int(rule.get("level", 3))
    severity = _map_wazuh_level_to_severity(level)

    ev_fields = EventFields(
        id=f"wazuh-{alert_id}",
        kind=EventKind.ALERT,
        category=category,
        action=rule.get("description", "wazuh_alert"),
        outcome=EventOutcome.SUCCESS if severity < 50 else EventOutcome.FAILURE,
        severity=severity,
        created=timestamp,
    )

    # Network / Source / Destination
    src_ip = data.get("srcip") or data.get("src_ip")
    src_port = data.get("srcport") or data.get("src_port")
    dst_ip = data.get("dstip") or data.get("dst_ip")
    dst_port = data.get("dstport") or data.get("dst_port")

    source_fields = (
        SourceFields(
            ip=src_ip,
            port=int(src_port) if src_port else None,
        )
        if src_ip
        else None
    )

    dest_fields = (
        DestinationFields(
            ip=dst_ip,
            port=int(dst_port) if dst_port else None,
        )
        if dst_ip
        else None
    )

    # User
    username = data.get("srcuser") or data.get("dstuser") or data.get("user")
    user_fields = UserFields(name=username) if username else None

    # Host
    host_fields = (
        HostFields(
            name=agent.get("name"),
            id=agent.get("id"),
        )
        if agent.get("name") or agent.get("id")
        else None
    )

    # Rule
    rule_fields = RuleFields(
        id=str(rule.get("id", "")),
        name=rule.get("description"),
    )

    # Agent
    agent_fields = AgentFields(
        id=agent.get("id"),
        name=agent.get("name"),
    )

    # Sentinel metadata
    meta = SentinelMetadata(
        source=SentinelSource(
            provider="wazuh",
            index="wazuh-alerts",
            document_id=alert_id,
        ),
        data_mode=DataMode.LIVE,
    )

    return SecurityEvent(
        **{"@timestamp": timestamp},
        event=ev_fields,
        message=alert.get("full_log") or rule.get("description"),
        source=source_fields,
        destination=dest_fields,
        user=user_fields,
        host=host_fields,
        rule=rule_fields,
        agent=agent_fields,
        sentinel=meta,
    )


class WazuhProvider(ProviderInterface):
    """
    Wazuh Manager REST API adapter.
    Handles JWT authentication, alert retrieval, and canonical normalization.
    """

    def __init__(
        self,
        http_client: httpx.AsyncClient | None = None,
        settings: Settings | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._client = http_client
        self._jwt_token: str | None = None
        self._token_expires_at: float = 0

    @property
    def name(self) -> str:
        return "wazuh"

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self._settings.wazuh_api_url.rstrip("/"),
                timeout=self._settings.query_timeout_seconds,
                verify=False,  # default self-signed cert in dev/test
            )
        return self._client

    async def close(self) -> None:
        """Close HTTP client connection."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _authenticate(self) -> str:
        """Obtain or refresh JWT token from Wazuh API."""
        now = time.monotonic()
        if self._jwt_token and now < (self._token_expires_at - 60):
            return self._jwt_token

        client = await self._get_client()
        auth = (
            self._settings.wazuh_api_username,
            self._settings.wazuh_api_password,
        )
        try:
            resp = await client.post("/security/user/authenticate", auth=auth)
            resp.raise_for_status()
            data = resp.json().get("data", {})
            token = data.get("token")
            if not token:
                raise ValueError("Wazuh authentication response missing token")
            self._jwt_token = token
            self._token_expires_at = now + 900  # Wazuh tokens typically valid 15-30m
            return self._jwt_token
        except httpx.HTTPStatusError as e:
            if e.response.status_code in (401, 403):
                raise PermissionError("Wazuh API authentication failed: invalid credentials") from e
            raise RuntimeError(f"Wazuh authentication error: {e}") from e

    async def health_check(self) -> ProviderHealthResult:
        """Check Wazuh API connectivity and manager status."""
        start = time.monotonic()
        try:
            token = await self._authenticate()
            client = await self._get_client()
            headers = {"Authorization": f"Bearer {token}"}
            resp = await client.get("/manager/status", headers=headers)
            resp.raise_for_status()
            elapsed = int((time.monotonic() - start) * 1000)

            return ProviderHealthResult(
                provider=self.name,
                status=ProviderStatus.HEALTHY,
                version=self._settings.wazuh_api_version or "4.x",
                message=f"Wazuh manager responsive ({elapsed}ms)",
                checked_at=datetime.now(UTC),
            )
        except PermissionError as e:
            return ProviderHealthResult(
                provider=self.name,
                status=ProviderStatus.AUTH_FAILURE,
                message=str(e),
                checked_at=datetime.now(UTC),
            )
        except (httpx.ConnectError, httpx.TimeoutException) as e:
            return ProviderHealthResult(
                provider=self.name,
                status=ProviderStatus.UNAVAILABLE,
                message=f"Cannot reach Wazuh manager at {self._settings.wazuh_api_url}: {e}",
                checked_at=datetime.now(UTC),
            )
        except Exception as e:
            return ProviderHealthResult(
                provider=self.name,
                status=ProviderStatus.DEGRADED,
                message=f"Wazuh health check failed: {e}",
                checked_at=datetime.now(UTC),
            )

    async def search(self, request: SearchRequest) -> ProviderSearchResult:
        """Query Wazuh alerts endpoint and normalize results."""
        start = time.monotonic()
        token = await self._authenticate()
        client = await self._get_client()
        headers = {"Authorization": f"Bearer {token}"}

        params: dict[str, Any] = {
            "limit": min(request.page_size, 500),
            "sort": "-timestamp" if request.sort_order == "desc" else "+timestamp",
        }
        if request.cursor:
            params["offset"] = int(request.cursor)

        try:
            resp = await client.get("/alerts", headers=headers, params=params)
            resp.raise_for_status()
            data = resp.json().get("data", {})
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                # Invalidate cached token on 401
                self._jwt_token = None
            raise RuntimeError(f"Wazuh alert search failed: {e}") from e

        total_items = data.get("total_affected_items", 0)
        items = data.get("affected_items", [])

        events = [_normalize_wazuh_alert(item) for item in items]
        elapsed_ms = int((time.monotonic() - start) * 1000)

        # Basic aggregation from returned items if requested
        agg_results: list[AggregationResult] = []
        for agg in request.aggregations:
            agg_field = agg.get("field", "")
            agg_type = agg.get("type", "terms")
            if agg_type == "terms":
                from collections import Counter

                counts: Counter[str] = Counter()
                for ev in events:
                    if agg_field == "agent.name" and ev.agent:
                        counts[ev.agent.name or ""] += 1
                    elif agg_field == "rule.id" and ev.rule:
                        counts[ev.rule.id or ""] += 1
                buckets = [AggregationBucket(key=k, doc_count=c) for k, c in counts.most_common(10)]
                agg_results.append(
                    AggregationResult(name=agg.get("name", agg_field), buckets=buckets)
                )

        return ProviderSearchResult(
            events=events,
            metadata=SearchResultMetadata(
                total_hits=total_items,
                returned_count=len(events),
                took_ms=elapsed_ms,
                provider=self.name,
            ),
            aggregations=agg_results,
        )

    async def get_field_mappings(self) -> dict[str, str]:
        """Return supported Wazuh fields mapped to ECS."""
        return {
            "@timestamp": "date",
            "rule.id": "keyword",
            "rule.name": "keyword",
            "agent.id": "keyword",
            "agent.name": "keyword",
            "source.ip": "ip",
            "source.port": "integer",
            "destination.ip": "ip",
            "destination.port": "integer",
            "user.name": "keyword",
            "event.category": "keyword",
            "event.severity": "integer",
        }
