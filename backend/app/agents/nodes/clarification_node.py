"""
SENTINEL AI — Clarification Node.

Handles queries that fail validation or lack essential parameters.
Prevents unvalidated execution and provides actionable guidance.
"""

from __future__ import annotations

from typing import Any

from backend.app.agents.state import InvestigationState


async def clarify_query_node(state: InvestigationState) -> dict[str, Any]:
    """Provide helpful guidance when validation fails or parameters are ambiguous."""
    errors = state.get("errors", [])
    user_query = state.get("user_query", "")

    lines: list[str] = [
        "> [!WARNING]",
        "> **Query Validation Failed / Clarification Required**",
        "",
        f'Your query *"{user_query}"* could not be safely executed against the SIEM.',
        "",
        "### Reasons:",
    ]

    for err in errors:
        lines.append(f"- {err}")

    lines.append("")
    lines.append("### Recommended Action:")
    lines.append(
        "- Specify an approved field name "
        "(e.g. `user.name`, `source.ip`, `event.category`, `event.outcome`)."
    )
    lines.append("- Restrict the query time range to under 168 hours (7 days).")
    lines.append("- Ensure the requested page size is 500 or fewer records.")

    return {"final_response": "\n".join(lines)}
