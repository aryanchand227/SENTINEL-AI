"""
SENTINEL AI — Investigation Analysis Node.

Correlates events, maps MITRE ATT&CK techniques, assesses risk, and derives findings.
"""

from __future__ import annotations

import uuid
from typing import Any

from backend.app.agents.state import (
    InvestigationFinding,
    InvestigationState,
)
from backend.app.investigation.correlation import CorrelationEngine
from backend.app.investigation.mitre import MitreMapper
from backend.app.investigation.risk import RiskEngine
from backend.app.nlp.llm_client import LLMClient


async def analyze_events_node(state: InvestigationState) -> dict[str, Any]:
    """Analyze retrieved events using deterministic engines."""
    events = state.get("events", [])
    provider_name = state.get("provider_name", "synthetic")
    is_synthetic = provider_name == "synthetic"

    resolved_context = state.get("resolved_context")

    # 1. Deterministic Correlations
    correlations = CorrelationEngine.correlate(events)

    # Multi-turn correlation: link prior suspect accounts to subsequent successful logins
    if resolved_context and resolved_context.target_accounts:
        target_accounts_set = set(resolved_context.target_accounts)
        successes = [
            e
            for e in events
            if e.event.category.value == "authentication"
            and e.event.outcome
            and e.event.outcome.value == "success"
            and e.user
            and e.user.name in target_accounts_set
        ]
        if successes and not any(
            c.rule_id == "CORR_001_AUTH_BRUTE_FORCE_SUCCESS" for c in correlations
        ):
            from backend.app.investigation.correlation import Correlation

            prior_evs = list(resolved_context.prior_evidence_ids)
            succ_evs = [s.event.id for s in successes]
            matched_users = sorted({s.user.name for s in successes if s.user and s.user.name})
            correlations.append(
                Correlation(
                    correlation_id=f"corr-{uuid.uuid4().hex[:8]}",
                    rule_id="CORR_001_AUTH_BRUTE_FORCE_SUCCESS",
                    rule_version="1.0.0",
                    related_evidence_ids=prior_evs + succ_evs,
                    entities_involved=[f"user:{u}" for u in matched_users],
                    time_window_start=successes[0].timestamp,
                    time_window_end=successes[-1].timestamp,
                    observed_relationship=(
                        f"Monitored target account(s) ({', '.join(matched_users)}) logged in "
                        f"successfully ({len(successes)} event(s)) following failure history."
                    ),
                    rationale=(
                        "Successful login observed for account with prior failure history."
                    ),
                    confidence_label="high",
                    alternative_explanations=[
                        "Legitimate user remembered valid password after prior failure attempts."
                    ],
                    status="candidate",
                )
            )

    # 2. MITRE ATT&CK Mapping
    attack_candidates = MitreMapper.map_events(events)

    # 3. Transparent Risk Assessment
    risk_assessment = RiskEngine.evaluate(
        events=events,
        correlations=correlations,
        attack_candidates=attack_candidates,
        is_synthetic=is_synthetic,
    )

    # 4. Formulate Verified Findings
    findings: list[InvestigationFinding] = []

    has_auth_fail = any(
        e.event.category.value == "authentication"
        and e.event.outcome
        and e.event.outcome.value == "failure"
        for e in events
    )
    if has_auth_fail:
        fail_ids = [
            e.event.id
            for e in events
            if e.event.category.value == "authentication"
            and e.event.outcome
            and e.event.outcome.value == "failure"
        ]
        findings.append(
            InvestigationFinding(
                finding_id=f"fnd-{uuid.uuid4().hex[:8]}",
                finding_type="authentication_anomaly",
                title=f"Authentication Failures Detected ({len(fail_ids)} events)",
                description=f"Identified {len(fail_ids)} failed logon attempts in queried window.",
                classification="observed",
                severity="medium" if len(fail_ids) < 10 else "high",
                confidence_label="high",
                evidence_ids=fail_ids,
                limitations=["Single authentication failures without confirmed successful breach."],
            )
        )

    # Findings from correlations
    for corr in correlations:
        if corr.rule_id == "CORR_001_AUTH_BRUTE_FORCE_SUCCESS":
            ftype = "post_failure_success"
            sev = "critical"
            title = "Successful Authentication Following Prior Failures"
            findings.insert(
                0,
                InvestigationFinding(
                    finding_id=f"fnd-{uuid.uuid4().hex[:8]}",
                    finding_type=ftype,
                    title=title,
                    description=corr.observed_relationship,
                    classification="observed",
                    severity=sev,
                    confidence_label=corr.confidence_label,
                    evidence_ids=corr.related_evidence_ids,
                    limitations=corr.alternative_explanations,
                ),
            )
        elif corr.rule_id == "CORR_002_MULTI_ACCOUNT_TARGETING":
            ftype = "credential_spray_observed"
            sev = "high"
            title = "Multiple Accounts Targeted From Single Origin"
            findings.append(
                InvestigationFinding(
                    finding_id=f"fnd-{uuid.uuid4().hex[:8]}",
                    finding_type=ftype,
                    title=title,
                    description=corr.observed_relationship,
                    classification="observed",
                    severity=sev,
                    confidence_label=corr.confidence_label,
                    evidence_ids=corr.related_evidence_ids,
                    limitations=corr.alternative_explanations,
                ),
            )
        else:
            ftype = "correlated_behavior"
            sev = risk_assessment.severity
            title = f"Correlated Activity: {corr.rule_id}"
            findings.append(
                InvestigationFinding(
                    finding_id=f"fnd-{uuid.uuid4().hex[:8]}",
                    finding_type=ftype,
                    title=title,
                    description=corr.observed_relationship,
                    classification="observed",
                    severity=sev,
                    confidence_label=corr.confidence_label,
                    evidence_ids=corr.related_evidence_ids,
                    limitations=corr.alternative_explanations,
                ),
            )

    if not findings and events:
        high_sev = [e for e in events if e.event.severity >= 50]
        ev_ids = [e.event.id for e in high_sev] if high_sev else [e.event.id for e in events[:10]]
        findings.append(
            InvestigationFinding(
                finding_id=f"fnd-{uuid.uuid4().hex[:8]}",
                finding_type="security_events_observed",
                title=f"Security Activity Observed ({len(events)} events)",
                description=f"Retrieved {len(events)} records matching investigation criteria.",
                classification="observed",
                severity=risk_assessment.severity,
                confidence_label="high",
                evidence_ids=ev_ids,
                limitations=[],
            ),
        )

    # 5. Optional finding explanation enrichment via Groq
    llm_client = LLMClient()
    if llm_client.is_configured and findings:
        target_finding = findings[0]
        prompt = (
            f"Provide a 1-sentence analytical explanation for this SOC finding:\n"
            f"Title: {target_finding.title}\n"
            f"Observed: {target_finding.description}\n"
            f"Severity: {target_finding.severity}\n"
            f"Constraint: Base commentary strictly on the observation. Do not invent facts."
        )
        ai_note = await llm_client.generate_text(
            prompt,
            system_prompt="You are SENTINEL AI, an evidence-first threat analyst assistant.",
        )
        if ai_note:
            target_finding.description = (
                f"{target_finding.description} [Analyst Note: {ai_note.strip()}]"
            )

    return {
        "correlations": correlations,
        "attack_candidates": attack_candidates,
        "risk_assessment": risk_assessment,
        "findings": findings,
    }
