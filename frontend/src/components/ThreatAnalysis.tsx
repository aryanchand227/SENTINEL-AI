import React from 'react'
import {
  Crosshair,
  GitBranch,
  Flame,
  AlertTriangle,
} from 'lucide-react'
import type { Finding } from '../types'

interface ThreatAnalysisProps {
  activeFindings: Finding[]
}

export const ThreatAnalysis: React.FC<ThreatAnalysisProps> = ({ activeFindings }) => {
  const mitreTechniques = [
    {
      id: 'T1110',
      name: 'Brute Force',
      tactic: 'Credential Access',
      severity: 'High',
      description: 'Adversaries may use brute force techniques to attempt credential guessing or password spraying.',
      rule: 'CORR_001 (Multiple Failed Logons)',
    },
    {
      id: 'T1059.001',
      name: 'PowerShell',
      tactic: 'Execution',
      severity: 'Critical',
      description: 'Adversaries may abuse PowerShell commands and scripts for execution and defense evasion.',
      rule: 'CORR_002 (Suspicious Process Execution)',
    },
    {
      id: 'T1078',
      name: 'Valid Accounts',
      tactic: 'Initial Access / Persistence',
      severity: 'High',
      description: 'Adversaries may obtain and abuse credentials of existing accounts following successful brute force.',
      rule: 'CORR_003 (Post-Brute Force Success)',
    },
    {
      id: 'T1071.001',
      name: 'Web Protocols',
      tactic: 'Command and Control',
      severity: 'Critical',
      description: 'Adversaries may communicate using application layer protocols associated with web traffic (HTTP/S).',
      rule: 'CORR_004 (Multi-Stage Attack Chain)',
    },
    {
      id: 'T1053.005',
      name: 'Scheduled Task',
      tactic: 'Persistence',
      severity: 'Medium',
      description: 'Adversaries may configure task scheduling to execute programs at system startup or on a scheduled basis.',
      rule: 'Rule ID: persistence_task_created',
    },
  ]

  const correlationRules = [
    {
      id: 'CORR_001',
      name: 'Multiple Failed Logons from Same Source',
      condition: '>= 3 failed logons on user within 15m window',
      deduction: '+25 Risk Points',
      status: 'ACTIVE',
    },
    {
      id: 'CORR_002',
      name: 'Suspicious PowerShell Script Execution',
      condition: 'powershell.exe with -EncodedCommand or -ExecutionPolicy Bypass',
      deduction: '+35 Risk Points',
      status: 'ACTIVE',
    },
    {
      id: 'CORR_003',
      name: 'Successful Authentication Following Failures',
      condition: 'Failure events followed by outcome=success on same account within 1h',
      deduction: '+30 Risk Points',
      status: 'ACTIVE',
    },
    {
      id: 'CORR_004',
      name: 'Multi-Stage Attack Chain Correlation',
      condition: 'Failed logon + privilege escalation + persistence observed within 24h',
      deduction: '+40 Risk Points',
      status: 'ACTIVE',
    },
  ]

  return (
    <div className="p-6 space-y-6 overflow-y-auto max-w-7xl mx-auto w-full">
      {/* Header */}
      <div className="bg-slate-900 border border-slate-800 p-5 rounded-xl">
        <div className="flex items-center gap-2 text-sky-400 font-semibold text-xs tracking-wider uppercase mb-1">
          <Crosshair className="w-4 h-4" />
          <span>ATT&CK Threat Matrix & Correlation Engine</span>
        </div>
        <h1 className="text-xl font-bold text-slate-100">Deterministic Threat & Correlation Analysis</h1>
        <p className="text-xs text-slate-400 mt-1">
          Cataloged MITRE ATT&CK techniques, deterministic correlation engine rules (CORR_001 to CORR_004), and transparent risk scoring drivers.
        </p>
      </div>

      {/* Active Correlated Findings in Scope */}
      {activeFindings.length > 0 && (
        <div className="bg-slate-900 border border-red-900/40 rounded-xl p-5 space-y-3">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-red-400" />
            <h2 className="text-sm font-bold text-slate-100">
              Active Correlated Findings in Current Scope ({activeFindings.length})
            </h2>
          </div>
          <div className="space-y-2">
            {activeFindings.map((f, i) => (
              <div key={i} className="bg-slate-950 p-3 rounded-lg border border-slate-800 text-xs flex justify-between items-center">
                <div>
                  <span className="font-bold text-slate-100">{f.title}</span>
                  <span className="text-slate-400 ml-2 font-mono text-[11px]">({f.classification})</span>
                </div>
                <span className="font-mono text-red-400 uppercase text-[10px] px-2 py-0.5 rounded bg-red-950 border border-red-800">
                  {f.severity}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* MITRE ATT&CK Techniques Grid */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-bold text-slate-100">
            MITRE ATT&CK Enterprise Techniques Catalog (v14.1)
          </h2>
          <span className="text-xs font-mono text-slate-400">Snapshot Verified</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {mitreTechniques.map((tech) => (
            <div
              key={tech.id}
              className="bg-slate-950 p-4 rounded-lg border border-slate-800 space-y-2 hover:border-slate-700 transition"
            >
              <div className="flex justify-between items-start">
                <span className="font-mono text-xs font-bold text-sky-400 bg-sky-950/60 px-2 py-0.5 rounded border border-sky-800/80">
                  {tech.id}
                </span>
                <span className="text-[10px] font-semibold uppercase px-2 py-0.5 rounded bg-red-950 text-red-300 border border-red-800">
                  {tech.severity}
                </span>
              </div>

              <h3 className="text-xs font-bold text-slate-100">{tech.name}</h3>
              <span className="text-[10px] text-slate-400 font-mono block">Tactic: {tech.tactic}</span>
              <p className="text-xs text-slate-300 leading-relaxed">{tech.description}</p>

              <div className="pt-2 border-t border-slate-800/80 text-[10px] text-slate-400 font-mono">
                Triggered By: <span className="text-sky-300">{tech.rule}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Correlation Engine Rules */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <GitBranch className="w-4 h-4 text-emerald-400" />
            <h2 className="text-sm font-bold text-slate-100">Deterministic Correlation Engine Rules</h2>
          </div>
          <span className="text-xs font-mono text-emerald-400">Section 10 Implementation</span>
        </div>

        <div className="space-y-3">
          {correlationRules.map((rule) => (
            <div
              key={rule.id}
              className="bg-slate-950 p-4 rounded-lg border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs"
            >
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="font-mono font-bold text-sky-400">{rule.id}</span>
                  <span className="font-semibold text-slate-200">{rule.name}</span>
                </div>
                <p className="text-slate-400 text-[11px] font-mono">{rule.condition}</p>
              </div>

              <div className="flex items-center gap-3 shrink-0">
                <span className="font-mono text-orange-400 font-bold bg-orange-950/60 px-2 py-0.5 rounded border border-orange-800">
                  {rule.deduction}
                </span>
                <span className="font-mono text-[10px] text-emerald-400 bg-emerald-950/80 px-2 py-0.5 rounded border border-emerald-800">
                  {rule.status}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Transparent Risk Score Breakdown */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
        <div className="flex items-center gap-2 text-sm font-bold text-slate-100">
          <Flame className="w-4 h-4 text-orange-400" />
          <span>Explainable Bounded Risk Calculation Model</span>
        </div>
        <p className="text-xs text-slate-300 leading-relaxed">
          Unlike black-box risk engines, SENTINEL AI calculates transparent, deterministic risk scores bounded strictly between 0 and 100 with explicit mathematical drivers:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs pt-1">
          <div className="bg-slate-950 p-3 rounded border border-slate-800 space-y-1">
            <span className="text-[10px] font-bold text-slate-400 uppercase block">1. Base Threat Driver</span>
            <p className="text-slate-300 text-[11px]">
              Calculated from verified finding severity ratings: Critical (+35), High (+20), Medium (+10).
            </p>
          </div>
          <div className="bg-slate-950 p-3 rounded border border-slate-800 space-y-1">
            <span className="text-[10px] font-bold text-slate-400 uppercase block">2. Evidence Density</span>
            <p className="text-slate-300 text-[11px]">
              Weighted (+2 per verified event ID) to elevate multi-event distributed attack campaigns.
            </p>
          </div>
          <div className="bg-slate-950 p-3 rounded border border-slate-800 space-y-1">
            <span className="text-[10px] font-bold text-slate-400 uppercase block">3. Mitigating Bounds</span>
            <p className="text-slate-300 text-[11px]">
              Strictly clamped to [0, 100]. Mitigating factors (e.g. block actions) apply explicit deductions.
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}
