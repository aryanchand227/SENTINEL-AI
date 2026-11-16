"""
SENTINEL AI — Elasticsearch 8.x Provider Adapter.

Implements the ProviderInterface for live Elasticsearch clusters.
Restricts searches to server-configured index patterns.
Normalizes hits into canonical SecurityEvent models.
Reports shard failures and timeouts honestly.
"""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime
from typing import Any

from elasticsearch import ApiError, AsyncElasticsearch, ConnectionError, ConnectionTimeout

from backend.app.core.config import Settings, get_settings
from backend.app.domain.events import (
    DataMode,
    EventCategory,
    EventFields,
    EventKind,
    EventOutcome,
    HostFields,
    SecurityEvent,
    SentinelMetadata,
    SentinelSource,
    SourceFields,
    UserFields,
)
from backend.app.siem.elasticsearch.compiler import ElasticsearchDslCompiler
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


def _normalize_es_hit(hit: dict[str, Any]) -> SecurityEvent:
    """Normalize a raw Elasticsearch hit into a canonical SecurityEvent."""
    source = hit.get("_source", {})
    doc_id = hit.get("_id", "unknown")
    index_name = hit.get("_index", "unknown")

    # Timestamp extraction
    ts_raw = source.get("@timestamp") or source.get("timestamp")
    if ts_raw:
        try:
            timestamp = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            timestamp = datetime.now(UTC)
    else:
        timestamp = datetime.now(UTC)

    # Event fields
    raw_ev = source.get("event", {})
    eid = raw_ev.get("id") or doc_id

    # Parse Category safely
    cat_str = raw_ev.get("category", "authentication").lower()
    try:
        category = EventCategory(cat_str)
    except ValueError:
        category = EventCategory.AUTHENTICATION

    # Parse Outcome safely
    out_str = raw_ev.get("outcome")
    outcome = None
    if out_str:
        try:
            outcome = EventOutcome(out_str.lower())
        except ValueError:
            outcome = EventOutcome.UNKNOWN

    ev_fields = EventFields(
        id=str(eid),
        kind=EventKind.EVENT,
        category=category,
        type=raw_ev.get("type"),
        action=raw_ev.get("action"),
        outcome=outcome,
        severity=int(raw_ev.get("severity", 25)),
        created=timestamp,
    )

    # Source & User & Host groups
    raw_src = source.get("source", {})
    src_fields = (
        SourceFields(
            ip=raw_src.get("ip"),
            port=raw_src.get("port"),
        )
        if raw_src
        else None
    )

    raw_user = source.get("user", {})
    user_fields = (
        UserFields(
            name=raw_user.get("name"),
            id=raw_user.get("id"),
        )
        if raw_user
        else None
    )

    raw_host = source.get("host", {})
    host_fields = (
        HostFields(
            name=raw_host.get("name"),
            id=raw_host.get("id"),
        )
        if raw_host
        else None
    )

    # Sentinel metadata
    meta = SentinelMetadata(
        source=SentinelSource(
            provider="elasticsearch",
            index=index_name,
            document_id=doc_id,
        ),
        data_mode=DataMode.LIVE,
    )

    return SecurityEvent(
        **{"@timestamp": timestamp},
        event=ev_fields,
        message=source.get("message"),
        source=src_fields,
        user=user_fields,
        host=host_fields,
        sentinel=meta,
    )


class ElasticsearchProvider(ProviderInterface):
    """
    Elasticsearch 8.x read-only SIEM provider adapter.
    """

    def __init__(
        self,
        client: AsyncElasticsearch | None = None,
        settings: Settings | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._client = client
        self._cached_mappings: dict[str, str] | None = None
        self._mappings_cached_at: float = 0

    @property
    def name(self) -> str:
        return "elasticsearch"

    async def _get_client(self) -> AsyncElasticsearch:
        if self._client is None:
            kwargs: dict[str, Any] = {
                "hosts": [self._settings.elasticsearch_url],
                "request_timeout": self._settings.query_timeout_seconds,
            }
            if self._settings.elasticsearch_api_key:
                kwargs["api_key"] = self._settings.elasticsearch_api_key
            elif self._settings.elasticsearch_username:
                kwargs["basic_auth"] = (
                    self._settings.elasticsearch_username,
                    self._settings.elasticsearch_password,
                )
            self._client = AsyncElasticsearch(**kwargs)
        return self._client

    async def close(self) -> None:
        if self._client is not None:
            await self._client.close()
            self._client = None

    async def health_check(self) -> ProviderHealthResult:
        """Check connection to Elasticsearch cluster."""
        start = time.monotonic()
        try:
            client = await self._get_client()
            info = await client.info()
            version = info.get("version", {}).get("number", "8.x")
            cluster_name = info.get("cluster_name", "elasticsearch")
            elapsed = int((time.monotonic() - start) * 1000)

            return ProviderHealthResult(
                provider=self.name,
                status=ProviderStatus.HEALTHY,
                version=version,
                message=f"Cluster '{cluster_name}' healthy (response took {elapsed}ms)",
                checked_at=datetime.now(UTC),
            )
        except (ConnectionError, ConnectionTimeout) as e:
            return ProviderHealthResult(
                provider=self.name,
                status=ProviderStatus.UNAVAILABLE,
                message=(
                    f"Cannot connect to Elasticsearch at {self._settings.elasticsearch_url}: {e}"
                ),
                checked_at=datetime.now(UTC),
            )
        except ApiError as e:
            status_code = getattr(e, "status_code", 500)
            st = (
                ProviderStatus.AUTH_FAILURE
                if status_code in (401, 403)
                else ProviderStatus.DEGRADED
            )
            return ProviderHealthResult(
                provider=self.name,
                status=st,
                message=f"Elasticsearch API error: {e}",
                checked_at=datetime.now(UTC),
            )
        except Exception as e:
            return ProviderHealthResult(
                provider=self.name,
                status=ProviderStatus.DEGRADED,
                message=f"Unexpected error checking Elasticsearch: {e}",
                checked_at=datetime.now(UTC),
            )

    async def search(self, request: SearchRequest) -> ProviderSearchResult:
        """Execute a validated query against allowed Elasticsearch indices."""
        start_time = time.monotonic()
        client = await self._get_client()

        # Compile SQS to Query DSL
        dsl_body = ElasticsearchDslCompiler.compile(request)

        # Enforce server-configured index pattern allowlist (Section 2.2 / 8.2)
        target_indices = ",".join(self._settings.elasticsearch_index_patterns)

        warnings: list[str] = []
        is_partial = False

        try:
            resp = await client.search(
                index=target_indices,
                body=dsl_body,
                allow_no_indices=True,
                ignore_unavailable=True,
            )
        except ConnectionTimeout:
            raise TimeoutError(
                f"Elasticsearch search timed out after {self._settings.query_timeout_seconds}s"
            )
        except ApiError as e:
            logger.error("Elasticsearch search failed: %s", e)
            raise RuntimeError(f"Elasticsearch search failed: {e}") from e

        # Inspect shard failures honestly
        shards = resp.get("_shards", {})
        failed_shards = shards.get("failed", 0)
        if failed_shards > 0:
            is_partial = True
            warnings.append(f"{failed_shards} shard(s) failed during execution.")

        hits_data = resp.get("hits", {})
        total_hits = hits_data.get("total", {}).get("value", 0)
        raw_hits = hits_data.get("hits", [])

        # Normalize hits
        events: list[SecurityEvent] = []
        for hit in raw_hits:
            try:
                events.append(_normalize_es_hit(hit))
            except Exception as e:
                logger.warning("Failed to normalize hit %s: %e", hit.get("_id"), e)

        # Normalize aggregations
        agg_results: list[AggregationResult] = []
        raw_aggs = resp.get("aggregations", {})
        for agg_name, agg_content in raw_aggs.items():
            buckets_raw = agg_content.get("buckets", [])
            buckets = [
                AggregationBucket(
                    key=str(b.get("key_as_string") or b.get("key")),
                    doc_count=int(b.get("doc_count", 0)),
                )
                for b in buckets_raw
            ]
            agg_results.append(AggregationResult(name=agg_name, buckets=buckets))

        elapsed_ms = int((time.monotonic() - start_time) * 1000)

        return ProviderSearchResult(
            events=events,
            metadata=SearchResultMetadata(
                total_hits=total_hits,
                returned_count=len(events),
                took_ms=elapsed_ms,
                provider=self.name,
                is_partial=is_partial,
                warnings=warnings,
            ),
            aggregations=agg_results,
        )

    async def get_field_mappings(self) -> dict[str, str]:
        """Discover and cache field mappings from approved indices."""
        now = time.monotonic()
        if self._cached_mappings is not None and (now - self._mappings_cached_at) < 300:
            return self._cached_mappings

        target_indices = ",".join(self._settings.elasticsearch_index_patterns)
        client = await self._get_client()

        try:
            raw_mappings = await client.indices.get_mapping(
                index=target_indices,
                allow_no_indices=True,
                ignore_unavailable=True,
            )
            discovered: dict[str, str] = {}
            for _idx, details in raw_mappings.items():
                props = details.get("mappings", {}).get("properties", {})
                self._extract_properties(props, "", discovered)

            self._cached_mappings = discovered
            self._mappings_cached_at = now
            return discovered
        except Exception as e:
            logger.warning("Could not fetch Elasticsearch mappings: %s", e)
            # Fallback to standard canonical mappings
            return {
                "@timestamp": "date",
                "event.id": "keyword",
                "event.category": "keyword",
                "event.action": "keyword",
                "event.outcome": "keyword",
                "source.ip": "ip",
                "user.name": "keyword",
                "host.name": "keyword",
            }

    def _extract_properties(
        self,
        properties: dict[str, Any],
        prefix: str,
        out: dict[str, str],
    ) -> None:
        for name, defn in properties.items():
            full_name = f"{prefix}.{name}" if prefix else name
            if "properties" in defn:
                self._extract_properties(defn["properties"], full_name, out)
            else:
                out[full_name] = defn.get("type", "keyword")
