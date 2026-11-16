"""
SENTINEL AI — Transparent Risk Assessment Engine.

Implements deterministic and explainable risk scoring (Section 12).
Does not let LLM assign final severity.
Weights and rules are transparent and verifiable.
"""

from __future__ import annotations

from collections.abc import Sequence

from backend.app.domain.events import SecurityEvent
from backend.app.investigation.correlation import Correlation
from backend.app.investigation.mitre import AttackTechniqueCandidate
from pydantic import BaseModel, ConfigDict, Field


class RiskAssessment(BaseModel):
    """Explainable risk assessment with transparent score breakdown."""

    model_config = ConfigDict(extra="forbid")

    severity: str  # informational, low, medium, high, critical
    score: int  # 0 to 100
    factors_increased: list[str] = Field(default_factory=list)
    factors_reduced: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    rule_version: str = "1.0.0"
    limitations: list[str] = Field(default_factory=list)
    analyst_override: str | None = None
    override_rationale: str | None = None


class RiskEngine:
    """
    Computes explainable risk assessment based on events, correlations, and ATT&CK mappings.
    """

    @classmethod
    def evaluate(
        cls,
        events: Sequence[SecurityEvent],
        correlations: Sequence[Correlation] = (),
        attack_candidates: Sequence[AttackTechniqueCandidate] = (),
        is_synthetic: bool = False,
    ) -> RiskAssessment:
        if not events:
            return RiskAssessment(
                severity="informational",
                score=0,
                factors_reduced=["No matching security events detected in the evaluated window."],
                evidence_ids=[],
                limitations=["No events returned for evaluated query."],
            )

        score = 0
        factors_increased: list[str] = []
        factors_reduced: list[str] = []
        evidence_ids: set[str] = {ev.event.id for ev in events}
        limitations: list[str] = []

        if is_synthetic:
            limitations.append("Evaluated against SYNTHETIC data environment.")

        # 1. Base Event Severity Contribution (max 40 pts)
        max_event_sev = max(ev.event.severity for ev in events)
        base_pts = int(max_event_sev * 0.40)
        score += base_pts
        if base_pts > 0:
            factors_increased.append(
                f"Peak verified event severity was {max_event_sev}/100 (+{base_pts} pts)."
            )

        # 2. Correlated Behavior Patterns (up to 40 pts)
        for corr in correlations:
            if corr.rule_id == "CORR_001_AUTH_BRUTE_FORCE_SUCCESS":
                score += 25
                factors_increased.append(
                    "Brute force sequence concluded with successful logon (+25 pts)."
                )
            elif corr.rule_id == "CORR_002_MULTI_ACCOUNT_TARGETING":
                score += 20
                factors_increased.append(
                    "Multiple accounts targeted from single source origin (+20 pts)."
                )
            elif corr.rule_id == "CORR_003_ACCOUNT_MULTI_ORIGIN":
                score += 15
                factors_increased.append(
                    "Account authenticated from multiple geographic or network origins (+15 pts)."
                )
            elif corr.rule_id == "CORR_004_AUTH_TO_PROCESS_EXEC":
                score += 10
                factors_increased.append(
                    "Process execution directly observed following authentication (+10 pts)."
                )

        # 3. MITRE ATT&CK Corroboration (up to 15 pts)
        high_impact_tactics = {"Impact", "Execution", "Command and Control"}
        corroborated_tactics = {cand.tactic for cand in attack_candidates}
        if any(hit in corroborated_tactics for hit in high_impact_tactics):
            score += 15
            factors_increased.append(
                "Observed behavior matches high-impact MITRE ATT&CK tactics (+15 pts)."
            )
        elif len(attack_candidates) >= 2:
            score += 10
            factors_increased.append(
                f"Corroborated by {len(attack_candidates)} candidate ATT&CK techniques (+10 pts)."
            )

        # 4. Mitigating / Reductive Factors
        # If all events are failures with no success, deduct score
        has_success = any(ev.event.outcome and ev.event.outcome.value == "success" for ev in events)
        if not has_success and score > 30:
            score -= 10
            factors_reduced.append(
                "No successful compromise or unauthorized logon verified (-10 pts)."
            )

        # Bound score between 0 and 100
        final_score = max(0, min(100, score))

        # Severity Thresholds (Section 12)
        if final_score >= 85:
            severity = "critical"
        elif final_score >= 65:
            severity = "high"
        elif final_score >= 40:
            severity = "medium"
        elif final_score >= 20:
            severity = "low"
        else:
            severity = "informational"

        return RiskAssessment(
            severity=severity,
            score=final_score,
            factors_increased=factors_increased,
            factors_reduced=factors_reduced,
            evidence_ids=sorted(evidence_ids),
            rule_version="1.0.0",
            limitations=limitations,
        )
