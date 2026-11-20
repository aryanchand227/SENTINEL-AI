#!/usr/bin/env python3
"""
SENTINEL AI — Standalone Evaluation Benchmark CLI Runner.

Executes the 10 benchmark scenarios from Appendix B (evaluation/questions.json)
through the compiled LangGraph multi-agent investigation workflow.
Outputs a structured summary table with latency, SQS validity, hit counts,
risk levels, and MITRE ATT&CK mappings.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Any

from backend.app.agents.graph import investigation_workflow
from backend.app.agents.state import InvestigationState, ResolvedInvestigationContext


async def run_evaluation(provider: str = "synthetic") -> int:
    eval_file = Path("evaluation/questions.json")
    if not eval_file.exists():
        print(f"Error: {eval_file} not found.", file=sys.stderr)
        return 1

    with open(eval_file, encoding="utf-8") as f:
        questions: list[dict[str, Any]] = json.load(f)

    print("=" * 90)
    print(f"  SENTINEL AI — Automated Evaluation Benchmark (Provider: {provider})")
    print(f"  Evaluating {len(questions)} Appendix B Security Scenarios")
    print("=" * 90)
    hdr = (
        f"{'ID':<8} | {'Scenario':<28} | {'Valid':<5} | "
        f"{'Hits':<5} | {'Risk':<5} | {'Time (ms)':<9} | {'Status'}"
    )
    print(hdr)
    print("-" * 90)

    results: list[dict[str, Any]] = []
    all_passed = True
    start_total = time.perf_counter()

    for q in questions:
        state: InvestigationState = {
            "request_id": f"cli-eval-req-{q['id']}",
            "user_id": "cli-eval-analyst",
            "conversation_id": f"cli-eval-conv-{q['id']}",
            "investigation_id": f"cli-eval-inv-{q['id']}",
            "provider_name": provider,
            "user_query": q["question"],
        }
        # Multi-turn follow-up scenario 2
        if q["id"] == "eval-02":
            state["resolved_context"] = ResolvedInvestigationContext(
                target_accounts=["jsmith"],
            )

        t0 = time.perf_counter()
        try:
            res = await investigation_workflow.ainvoke(state)
            latency_ms = (time.perf_counter() - t0) * 1000.0

            validation_res = res.get("validation_result")
            is_valid = validation_res.is_valid if validation_res else False
            events = res.get("events", [])
            hit_count = len(events)
            risk = res.get("risk_assessment")
            risk_score = risk.score if risk else 0

            passed = is_valid and (hit_count >= q.get("expected_min_hits", 1))
            if not passed:
                all_passed = False

            status_str = "PASS" if passed else "FAIL"
            print(
                f"{q['id']:<8} | {q['scenario_name'][:28]:<28} | {str(is_valid):<5} | "
                f"{hit_count:<5} | {risk_score:<5} | {latency_ms:<9.1f} | {status_str}"
            )

            results.append(
                {
                    "id": q["id"],
                    "scenario": q["scenario_name"],
                    "passed": passed,
                    "latency_ms": latency_ms,
                    "is_valid": is_valid,
                    "hit_count": hit_count,
                    "risk_score": risk_score,
                    "mitre_techniques": [m.technique_id for m in res.get("mitre_mappings", [])],
                }
            )
        except Exception as e:
            all_passed = False
            latency_ms = (time.perf_counter() - t0) * 1000.0
            print(
                f"{q['id']:<8} | {q['scenario_name'][:28]:<28} | {'ERR':<5} | "
                f"{0:<5} | {0:<5} | {latency_ms:<9.1f} | ERROR: {e}"
            )
            results.append(
                {
                    "id": q["id"],
                    "scenario": q["scenario_name"],
                    "passed": False,
                    "latency_ms": latency_ms,
                    "error": str(e),
                }
            )

    total_duration = time.perf_counter() - start_total
    passed_count = sum(1 for r in results if r.get("passed"))
    valid_sqs_count = sum(1 for r in results if r.get("is_valid"))
    avg_latency = sum(r["latency_ms"] for r in results) / len(results) if results else 0

    print("=" * 90)
    print("  SUMMARY BENCHMARK METRICS")
    print("=" * 90)
    pass_pct = (passed_count / len(results)) * 100
    valid_pct = (valid_sqs_count / len(results)) * 100
    print(f"  Total Scenarios Evaluated : {len(results)}")
    print(f"  Passed Scenarios          : {passed_count}/{len(results)} ({pass_pct:.1f}%)")
    print(f"  SQS Schema Validity Rate  : {valid_sqs_count}/{len(results)} ({valid_pct:.1f}%)")
    print(f"  Average Pipeline Latency  : {avg_latency:.1f} ms")
    print(f"  Total Benchmark Duration  : {total_duration:.2f} s")
    print("=" * 90)

    return 0 if all_passed else 1


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SENTINEL AI Automated Evaluation Benchmark Runner"
    )
    parser.add_argument(
        "--provider",
        choices=["synthetic", "elasticsearch", "wazuh"],
        default="synthetic",
        help="SIEM data provider to evaluate against (default: synthetic)",
    )
    args = parser.parse_args()

    exit_code = asyncio.run(run_evaluation(provider=args.provider))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
