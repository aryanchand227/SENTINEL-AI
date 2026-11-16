"""
SENTINEL AI — MITRE ATT&CK Knowledge Snapshot & Behavioral Mapping.

Maintains versioned MITRE ATT&CK Enterprise techniques catalog.
Maps observed security events and detection rules deterministically
into candidate attack techniques. Does NOT invent technique IDs.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from backend.app.domain.events import EventCategory, EventOutcome, SecurityEvent
from pydantic import BaseModel, ConfigDict, Field


class AttackTechniqueCandidate(BaseModel):
    """Candidate ATT&CK technique mapping supported by evidence."""

    model_config = ConfigDict(extra="forbid")

    technique_id: str
    technique_name: str
    tactic: str
    source_version: str = "v14.1"
    rationale: str
    evidence_ids: list[str] = Field(default_factory=list)
    confidence: str = "candidate"  # "candidate", "supported"
    status: str = "candidate"  # "candidate", "analyst_reviewed", "dismissed"


@dataclass(frozen=True)
class MitreTechniqueDefinition:
    id: str
    name: str
    tactic: str
    description: str


# Versioned local snapshot of approved MITRE ATT&CK Enterprise techniques
MITRE_CATALOG: dict[str, MitreTechniqueDefinition] = {
    "T1110.001": MitreTechniqueDefinition(
        id="T1110.001",
        name="Brute Force: Password Guessing",
        tactic="Credential Access",
        description="Adversaries may attempt to guess credentials for existing accounts.",
    ),
    "T1110.003": MitreTechniqueDefinition(
        id="T1110.003",
        name="Brute Force: Password Spraying",
        tactic="Credential Access",
        description="Adversaries may attempt a single password across many accounts.",
    ),
    "T1078": MitreTechniqueDefinition(
        id="T1078",
        name="Valid Accounts",
        tactic="Defense Evasion, Persistence, Initial Access",
        description="Adversaries may obtain and abuse credentials of existing accounts.",
    ),
    "T1059.001": MitreTechniqueDefinition(
        id="T1059.001",
        name="Command and Scripting Interpreter: PowerShell",
        tactic="Execution",
        description="Adversaries may abuse PowerShell commands and scripts for execution.",
    ),
    "T1059.004": MitreTechniqueDefinition(
        id="T1059.004",
        name="Command and Scripting Interpreter: Unix Shell",
        tactic="Execution",
        description="Adversaries may abuse Unix shells to execute commands.",
    ),
    "T1053.005": MitreTechniqueDefinition(
        id="T1053.005",
        name="Scheduled Task/Job: Scheduled Task",
        tactic="Execution, Persistence, Privilege Escalation",
        description="Adversaries may abuse task scheduling functionality.",
    ),
    "T1021.004": MitreTechniqueDefinition(
        id="T1021.004",
        name="Remote Services: SSH",
        tactic="Lateral Movement",
        description="Adversaries may log into remote systems using SSH.",
    ),
    "T1046": MitreTechniqueDefinition(
        id="T1046",
        name="Network Service Discovery",
        tactic="Discovery",
        description="Adversaries may attempt to enumerate network services running on hosts.",
    ),
    "T1071.001": MitreTechniqueDefinition(
        id="T1071.001",
        name="Application Layer Protocol: Web Protocols",
        tactic="Command and Control",
        description="Adversaries may communicate using application layer protocols (HTTP/HTTPS).",
    ),
    "T1486": MitreTechniqueDefinition(
        id="T1486",
        name="Data Encrypted for Impact",
        tactic="Impact",
        description="Adversaries may encrypt data on target systems to interrupt availability.",
    ),
    "T1562.001": MitreTechniqueDefinition(
        id="T1562.001",
        name="Impair Defenses: Disable or Modify Tools",
        tactic="Defense Evasion",
        description="Adversaries may disable or modify security tools to avoid detection.",
    ),
}


class MitreMapper:
    """
    Deterministic mapper from verified SecurityEvents to MITRE ATT&CK techniques.
    """

    @classmethod
    def map_events(cls, events: Sequence[SecurityEvent]) -> list[AttackTechniqueCandidate]:
        candidates: dict[str, AttackTechniqueCandidate] = {}

        for ev in events:
            ev_id = ev.event.id
            cat = ev.event.category
            outcome = ev.event.outcome
            msg = (ev.message or "").lower()
            action = (ev.event.action or "").lower()

            # 1. Authentication Brute Force: Password Guessing (T1110.001)
            if cat == EventCategory.AUTHENTICATION and outcome == EventOutcome.FAILURE:
                t_def = MITRE_CATALOG["T1110.001"]
                if t_def.id not in candidates:
                    candidates[t_def.id] = AttackTechniqueCandidate(
                        technique_id=t_def.id,
                        technique_name=t_def.name,
                        tactic=t_def.tactic,
                        rationale="Observed repeated authentication failure events.",
                        evidence_ids=[ev_id],
                        confidence="candidate",
                    )
                else:
                    if ev_id not in candidates[t_def.id].evidence_ids:
                        candidates[t_def.id].evidence_ids.append(ev_id)

            # 2. Valid Accounts (T1078)
            if cat == EventCategory.AUTHENTICATION and outcome == EventOutcome.SUCCESS:
                # If there are also failure events or suspicious context, flag Valid Accounts
                t_def = MITRE_CATALOG["T1078"]
                if t_def.id not in candidates:
                    candidates[t_def.id] = AttackTechniqueCandidate(
                        technique_id=t_def.id,
                        technique_name=t_def.name,
                        tactic=t_def.tactic,
                        rationale="Observed successful authentication on monitored account.",
                        evidence_ids=[ev_id],
                        confidence="candidate",
                    )
                else:
                    if ev_id not in candidates[t_def.id].evidence_ids:
                        candidates[t_def.id].evidence_ids.append(ev_id)

            # 3. Remote Services: SSH (T1021.004)
            if (
                "ssh" in msg
                or "sshd" in action
                or (
                    ev.network
                    and ev.network.protocol == "tcp"
                    and ev.destination
                    and ev.destination.port == 22
                )
            ):
                t_def = MITRE_CATALOG["T1021.004"]
                if t_def.id not in candidates:
                    candidates[t_def.id] = AttackTechniqueCandidate(
                        technique_id=t_def.id,
                        technique_name=t_def.name,
                        tactic=t_def.tactic,
                        rationale="Activity involves SSH remote service connections.",
                        evidence_ids=[ev_id],
                        confidence="candidate",
                    )
                else:
                    if ev_id not in candidates[t_def.id].evidence_ids:
                        candidates[t_def.id].evidence_ids.append(ev_id)

            # 4. Command and Scripting Interpreter: PowerShell (T1059.001)
            if cat == EventCategory.PROCESS and ("powershell" in msg or "pwsh" in action):
                t_def = MITRE_CATALOG["T1059.001"]
                if t_def.id not in candidates:
                    candidates[t_def.id] = AttackTechniqueCandidate(
                        technique_id=t_def.id,
                        technique_name=t_def.name,
                        tactic=t_def.tactic,
                        rationale="Execution of PowerShell interpreter observed.",
                        evidence_ids=[ev_id],
                        confidence="candidate",
                    )
                else:
                    if ev_id not in candidates[t_def.id].evidence_ids:
                        candidates[t_def.id].evidence_ids.append(ev_id)

            # 5. Data Encrypted for Impact / Ransomware (T1486)
            if (
                "ransomware" in msg
                or "encrypt" in msg
                or (ev.rule and "ransomware" in (ev.rule.name or "").lower())
            ):
                t_def = MITRE_CATALOG["T1486"]
                if t_def.id not in candidates:
                    candidates[t_def.id] = AttackTechniqueCandidate(
                        technique_id=t_def.id,
                        technique_name=t_def.name,
                        tactic=t_def.tactic,
                        rationale="Indicator of file encryption or ransomware pattern.",
                        evidence_ids=[ev_id],
                        confidence="candidate",
                    )
                else:
                    if ev_id not in candidates[t_def.id].evidence_ids:
                        candidates[t_def.id].evidence_ids.append(ev_id)

            # 6. Network Service Discovery (T1046)
            if (
                "port_scan" in action
                or "scan" in msg
                or (ev.rule and "scan" in (ev.rule.name or "").lower())
            ):
                t_def = MITRE_CATALOG["T1046"]
                if t_def.id not in candidates:
                    candidates[t_def.id] = AttackTechniqueCandidate(
                        technique_id=t_def.id,
                        technique_name=t_def.name,
                        tactic=t_def.tactic,
                        rationale="Port scanning or network enumeration activity observed.",
                        evidence_ids=[ev_id],
                        confidence="candidate",
                    )
                else:
                    if ev_id not in candidates[t_def.id].evidence_ids:
                        candidates[t_def.id].evidence_ids.append(ev_id)

        # Elevate confidence to "supported" when corroborated by multiple events
        for candidate in candidates.values():
            if len(candidate.evidence_ids) >= 3:
                candidate.confidence = "supported"

        return list(candidates.values())
