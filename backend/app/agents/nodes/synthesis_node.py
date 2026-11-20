"""
SENTINEL AI — Synthesis Node.

Generates final structured analyst response.
Adheres strictly to evidence-first rules, synthetic disclosures,
and honest confidence semantics.
"""

from __future__ import annotations

from typing import Any

from backend.app.agents.state import InvestigationState
from backend.app.nlp.llm_client import LLMClient


async def synthesize_response_node(state: InvestigationState) -> dict[str, Any]:
    """Synthesize final SOC investigation response."""
    events = state.get("events", [])
    provider_name = state.get("provider_name", "synthetic")
    is_synthetic = provider_name == "synthetic"
    correlations = state.get("correlations", [])
    attack_candidates = state.get("attack_candidates", [])
    risk_assessment = state.get("risk_assessment")
    errors = state.get("errors", [])
    warnings = state.get("warnings", [])

    lines: list[str] = []

    # 1. Synthetic Data Banner
    if is_synthetic:
        lines.append("> [!NOTE]")
        lines.append(
            "> **SYNTHETIC DATA DISCLOSURE**: This query executed in deterministic simulation "
            "mode against verified synthetic security telemetry."
        )
        lines.append("")

    # 2. Executive Summary
    if not events:
        lines.append("### Investigation Results: No Events Detected")
        lines.append(
            "No security events matched the specified filter criteria "
            "within the queried time window."
        )
        if warnings:
            lines.append("")
            lines.append("**Warnings:**")
            for w in warnings:
                lines.append(f"- {w}")
        return {"final_response": "\n".join(lines)}

    lines.append(f"### Investigation Summary ({len(events)} Events Analyzed)")
    lines.append(
        f"Retrieved **{len(events)}** normalized security events via provider `{provider_name}`."
    )

    # Optional executive briefing narrative from Groq
    llm_client = LLMClient()
    ai_narrative: str | None = None
    if llm_client.is_configured:
        r_sev = risk_assessment.severity.upper() if risk_assessment else "UNKNOWN"
        r_score = risk_assessment.score if risk_assessment else 0
        r_drivers = ", ".join(risk_assessment.factors_increased if risk_assessment else [])
        c_patterns = ", ".join([f"{c.rule_id}: {c.observed_relationship}" for c in correlations])

        prompt = (
            f"You are SENTINEL AI, an expert SOC Analyst assistant. "
            f"Provide a concise, 2-sentence executive threat briefing summarizing this:\n"
            f"- Events retrieved: {len(events)} (provider: {provider_name})\n"
            f"- Risk level: {r_sev} (Score: {r_score}/100)\n"
            f"- Risk drivers: {r_drivers}\n"
            f"- Correlated patterns: {c_patterns}\n"
            f"STRICT INSTRUCTIONS: Base statements strictly on the provided evidence facts. "
            f"Do NOT invent new IPs, usernames, or attack vectors."
        )
        ai_narrative = await llm_client.generate_text(
            prompt,
            system_prompt=(
                "You are SENTINEL AI, a disciplined SOC assistant. "
                "Be direct, authoritative, and fact-bound."
            ),
        )
        if ai_narrative:
            lines.append("")
            lines.append(f"**Analyst Assessment:** {ai_narrative.strip()}")

    lines.append("")

    # 3. Risk Assessment Summary
    if risk_assessment:
        sev_badge = risk_assessment.severity.upper()
        lines.append(f"**Assessed Risk Level:** `{sev_badge}` (Score: {risk_assessment.score}/100)")
        if risk_assessment.factors_increased:
            lines.append("*Score Drivers:*")
            for factor in risk_assessment.factors_increased:
                lines.append(f"- {factor}")
        if risk_assessment.factors_reduced:
            lines.append("*Mitigating Factors:*")
            for factor in risk_assessment.factors_reduced:
                lines.append(f"- {factor}")
        lines.append("")

    # 4. Correlated Findings
    if correlations:
        lines.append("### Correlated Activity Patterns")
        for corr in correlations:
            lines.append(f"#### {corr.rule_id} (`{corr.confidence_label.upper()}` confidence)")
            lines.append(corr.observed_relationship)
            lines.append("")
            lines.append(f"*Rationale:* {corr.rationale}")
            lines.append("")
            lines.append(f"*Entities Involved:* {', '.join(corr.entities_involved)}")
            lines.append(f"*Supporting Evidence:* `{', '.join(corr.related_evidence_ids)}`")
            if corr.alternative_explanations:
                lines.append("*Alternative Explanations:*")
                for alt in corr.alternative_explanations:
                    lines.append(f"- {alt}")
            lines.append("")

    # 5. MITRE ATT&CK Candidate Techniques
    if attack_candidates:
        lines.append("### MITRE ATT&CK Mappings")
        lines.append(
            "| Technique ID | Technique Name | Tactic | Confidence | Supporting Evidence |"
        )
        lines.append("|---|---|---|---|---|")
        for cand in attack_candidates:
            ev_list = ", ".join(cand.evidence_ids[:3])
            if len(cand.evidence_ids) > 3:
                ev_list += f" (+{len(cand.evidence_ids) - 3} more)"
            row = (
                f"| `{cand.technique_id}` | {cand.technique_name} | "
                f"{cand.tactic} | `{cand.confidence}` | `{ev_list}` |"
            )
            lines.append(row)
        lines.append("")

    # 6. Errors or Warnings
    if errors or warnings:
        if warnings:
            lines.append("**Operational Warnings:**")
            for w in warnings:
                lines.append(f"- {w}")
        if errors:
            lines.append("**Operational Errors:**")
            for e in errors:
                lines.append(f"- {e}")
        lines.append("")

    lines.append("---")
    lines.append(
        "*Investigation findings are derived strictly from verified provider telemetry. "
        "Confirm before executing containment or remediation.*"
    )

    return {"final_response": "\n".join(lines)}
