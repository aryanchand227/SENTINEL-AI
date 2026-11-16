"""
SENTINEL AI — Query Validator.

Enforces query safety policies:
- Validates field allowlists against the approved field registry
- Validates operator compatibility with field data types
- Enforces maximum time range window
- Enforces max result page size
- Enforces max aggregations and aggregation bucket sizes
- Validates sorting and requested fields
"""

from __future__ import annotations

from datetime import timedelta

from pydantic import BaseModel, ConfigDict, Field

from backend.app.core.config import get_settings
from backend.app.query.field_registry import (
    get_field_definition,
    is_field_approved,
    is_operator_allowed,
)
from backend.app.query.sqs import AggregationType, SentinelQuerySpec


class ValidationErrorDetail(BaseModel):
    model_config = ConfigDict(extra="forbid")

    field: str
    message: str
    error_code: str


class QueryValidationResult(BaseModel):
    """Result of SQS validation."""
    model_config = ConfigDict(extra="forbid")

    is_valid: bool
    errors: list[ValidationErrorDetail] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    sanitized_spec: SentinelQuerySpec | None = None


class QueryValidator:
    """Deterministic query safety validator."""

    def __init__(self) -> None:
        self._settings = get_settings()

    def validate(self, spec: SentinelQuerySpec) -> QueryValidationResult:
        errors: list[ValidationErrorDetail] = []
        warnings: list[str] = []

        # 1. Time range validation
        time_diff = spec.time_range.end - spec.time_range.start
        max_window = timedelta(hours=self._settings.max_query_window_hours)
        if time_diff > max_window:
            errors.append(
                ValidationErrorDetail(
                    field="time_range",
                    message=(
                        f"Requested time window of {time_diff.total_seconds() / 3600:.1f}h "
                        f"exceeds maximum allowed limit of {self._settings.max_query_window_hours}h"
                    ),
                    error_code="TIME_WINDOW_EXCEEDED",
                )
            )

        # 2. Page size limit
        if spec.page_size > self._settings.max_query_page_size:
            errors.append(
                ValidationErrorDetail(
                    field="page_size",
                    message=(
                        f"Requested page size of {spec.page_size} exceeds "
                        f"maximum allowed limit of {self._settings.max_query_page_size}"
                    ),
                    error_code="PAGE_SIZE_EXCEEDED",
                )
            )
        elif spec.page_size <= 0:
            errors.append(
                ValidationErrorDetail(
                    field="page_size",
                    message="Page size must be greater than zero",
                    error_code="INVALID_PAGE_SIZE",
                )
            )

        # 3. Filter validation
        for i, f in enumerate(spec.filters):
            field_name = f.field
            # Field registry existence check
            if not is_field_approved(field_name):
                errors.append(
                    ValidationErrorDetail(
                        field=f"filters[{i}].field",
                        message=f"Field '{field_name}' is not in the approved field registry",
                        error_code="UNAPPROVED_FIELD",
                    )
                )
                continue

            # Operator compatibility check
            if not is_operator_allowed(field_name, f.operator):
                field_def = get_field_definition(field_name)
                type_name = field_def.data_type.value if field_def else "unknown"
                errors.append(
                    ValidationErrorDetail(
                        field=f"filters[{i}].operator",
                        message=(
                            f"Operator '{f.operator.value}' is not allowed for "
                            f"field '{field_name}' of type '{type_name}'"
                        ),
                        error_code="INCOMPATIBLE_OPERATOR",
                    )
                )

        # 4. Aggregations validation
        if len(spec.aggregations) > 5:
            errors.append(
                ValidationErrorDetail(
                    field="aggregations",
                    message=f"Number of aggregations ({len(spec.aggregations)}) exceeds limit of 5",
                    error_code="TOO_MANY_AGGREGATIONS",
                )
            )

        for i, agg in enumerate(spec.aggregations):
            if not is_field_approved(agg.field):
                errors.append(
                    ValidationErrorDetail(
                        field=f"aggregations[{i}].field",
                        message=f"Field '{agg.field}' for aggregation is not in approved registry",
                        error_code="UNAPPROVED_AGGREGATION_FIELD",
                    )
                )
                continue

            field_def = get_field_definition(agg.field)
            if field_def and not field_def.aggregatable:
                errors.append(
                    ValidationErrorDetail(
                        field=f"aggregations[{i}].field",
                        message=f"Field '{agg.field}' is not aggregatable (text/message field)",
                        error_code="NON_AGGREGATABLE_FIELD",
                    )
                )

            if agg.size is not None:
                if agg.size > self._settings.max_aggregation_buckets:
                    errors.append(
                        ValidationErrorDetail(
                            field=f"aggregations[{i}].size",
                            message=(
                                f"Aggregation size of {agg.size} exceeds "
                                f"maximum limit of {self._settings.max_aggregation_buckets}"
                            ),
                            error_code="AGGREGATION_SIZE_EXCEEDED",
                        )
                    )
                elif agg.size <= 0:
                    errors.append(
                        ValidationErrorDetail(
                            field=f"aggregations[{i}].size",
                            message="Aggregation size must be positive",
                            error_code="INVALID_AGGREGATION_SIZE",
                        )
                    )

            if agg.type == AggregationType.DATE_HISTOGRAM and agg.field != "@timestamp":
                warnings.append(f"Date histogram requested on non-timestamp field '{agg.field}'")

        # 5. Sort field validation
        if not is_field_approved(spec.sort_field):
            errors.append(
                ValidationErrorDetail(
                    field="sort_field",
                    message=f"Sort field '{spec.sort_field}' is not in approved registry",
                    error_code="UNAPPROVED_SORT_FIELD",
                )
            )

        # 6. Requested fields validation
        for rf in spec.requested_fields:
            if not is_field_approved(rf):
                warnings.append(f"Requested field '{rf}' is not in standard registry")

        is_valid = len(errors) == 0
        return QueryValidationResult(
            is_valid=is_valid,
            errors=errors,
            warnings=warnings,
            sanitized_spec=spec if is_valid else None,
        )
