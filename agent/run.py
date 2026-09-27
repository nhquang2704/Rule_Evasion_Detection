#!/usr/bin/env python3
"""CLI entry — chạy multi-agent investigation trên 1 alert.

Usage:
  python3 -m agent.run                          # Mock alert + mock tools
  python3 -m agent.run --es-real                # Tools query ES thật
  python3 -m agent.run --alert-file alert.json  # Alert từ file
  python3 -m agent.run --quiet                  # Bỏ verbose log per-step
"""

import os
import sys
import json
import asyncio
import argparse
import logging

# Allow running both as module and as script
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.orchestrator import investigate


MOCK_ALERT = {
    "@timestamp": "2026-05-14T10:23:45Z",
    "host": {"name": "WIN-01"},
    "user": {"name": "alice"},
    "process": {
        "name": "powershell.exe",
        "command_line": "powershell -e SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAA==",
        "parent": {"name": "outlook.exe"},
    },
    "red": {
        "stage1_score": 0.87,
        "stage1_model": "ensemble_f1",
        "top_rules": [
            {"rule_id": "powershell_encoded_command", "cosine_score": 0.91},
            {"rule_id": "powershell_suspicious", "cosine_score": 0.78},
        ],
        "evasion_type": "near_miss",
    },
    "source_event_id": "abc123",
}


async def amain():
    parser = argparse.ArgumentParser(description="RED Multi-Agent SOC Triage")
    parser.add_argument("--es-real", action="store_true", help="Query ES thật thay vì mock")
    parser.add_argument("--alert-file", type=str, help="Path tới alert JSON")
    parser.add_argument("--quiet", action="store_true", help="Bỏ verbose step logging")
    parser.add_argument("--save", type=str, help="Lưu investigation kết quả ra file JSON")
    args = parser.parse_args()

    logging.basicConfig(
        level=os.environ.get("AGENT_LOG_LEVEL", "INFO"),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    if args.alert_file:
        with open(args.alert_file, encoding="utf-8") as f:
            alert = json.load(f)
    else:
        alert = MOCK_ALERT

    logger = logging.getLogger("agent.run")
    logger.info("Starting investigation for host=%s",
                alert.get("host", {}).get("name"))

    inv = await investigate(alert, use_real_es=args.es_real, verbose=not args.quiet)

    # In kết quả
    print("\n" + "═" * 70)
    print(f"INVESTIGATION RESULT — {inv.investigation_id}")
    print("═" * 70)
    print(f"Duration: {inv.total_duration_ms:.0f}ms | "
          f"Tokens: {inv.total_tokens} | "
          f"Cost: ${inv.estimated_cost_usd:.6f}")
    print()

    if inv.workflow_plan:
        print(f"WORKFLOW: {inv.workflow_plan.workflow_type} (priority {inv.workflow_plan.priority})")
        print(f"  Reasoning: {inv.workflow_plan.reasoning}")
        print()

    if inv.triage:
        print(f"TRIAGE: {inv.triage.severity} | FP={inv.triage.is_false_positive} | "
              f"conf={inv.triage.confidence:.2f}")
        print(f"  Reasoning: {inv.triage.reasoning}")
        if inv.triage.quick_findings:
            print("  Findings:")
            for f in inv.triage.quick_findings:
                print(f"    • {f}")
        print()

    if inv.hunt:
        print(f"HUNT: {inv.hunt.related_events_count} related events, "
              f"sus_score={inv.hunt.suspicious_score:.2f}")
        if inv.hunt.timeline_vi:
            print("  Timeline:")
            for t in inv.hunt.timeline_vi:
                print(f"    • {t}")
        if inv.hunt.iocs_found:
            print(f"  IOCs: {inv.hunt.iocs_found}")
        print()

    if inv.red_analyst:
        print(f"RED ANALYST: technique={inv.red_analyst.evasion_technique} "
              f"(conf={inv.red_analyst.confidence:.2f})")
        print(f"  Reasoning: {inv.red_analyst.evasion_reasoning_vi}")
        if inv.red_analyst.discriminative_tokens:
            print(f"  Tokens: {inv.red_analyst.discriminative_tokens}")
        print()

    if inv.mitre:
        print(f"MITRE: {inv.mitre.primary_tactic} → {inv.mitre.primary_technique} "
              f"(baseline={inv.mitre.severity_baseline})")
        if inv.mitre.sub_techniques:
            print(f"  Sub-techniques: {inv.mitre.sub_techniques}")
        if inv.mitre.ttp_chain_vi:
            print("  TTP chain:")
            for t in inv.mitre.ttp_chain_vi:
                print(f"    → {t}")
        print()

    if inv.response:
        print(f"🛡️  RESPONSE: {len(inv.response.containment_actions)} actions, "
              f"notify_sent={inv.response.notification_sent}, "
              f"needs_approval={inv.response.requires_human_approval}")
        print(f"  Summary: {inv.response.summary_vi}")
        if inv.response.sigma_patch_yaml:
            print(f"\n  ⭐ Sigma patch ({len(inv.response.sigma_patch_yaml)} chars):")
            print("  " + "─" * 60)
            for line in inv.response.sigma_patch_yaml.split("\n"):
                print(f"  │ {line}")
            print("  " + "─" * 60)
            if inv.response.sigma_patch_explanation_vi:
                print(f"  Patch lý do: {inv.response.sigma_patch_explanation_vi}")
        if inv.response.containment_actions:
            print(f"\n  Containment actions:")
            for a in inv.response.containment_actions:
                approval = "🔒 needs approval" if a.needs_approval else "✓ auto"
                print(f"    [P{a.priority}] {a.action_type:18s} target={a.target:20s}  {approval}")
                print(f"           └─ {a.rationale_vi}")
        print()

    if inv.report:
        print(f"REPORT: {inv.report.title_vi}")
        print(f"  Summary: {inv.report.summary_vi}")
        print()
        print("─" * 70)
        print(inv.report.full_markdown_vi)
        print("─" * 70)
        if inv.report.recommended_actions_vi:
            print("\nĐề xuất hành động:")
            for i, a in enumerate(inv.report.recommended_actions_vi, 1):
                print(f"  {i}. {a}")

    print()
    print("Per-agent metadata:")
    for m in inv.agent_metadata:
        toks = m.tokens_prompt + m.tokens_completion
        cache_pct = 100 * m.tokens_cached / m.tokens_prompt if m.tokens_prompt else 0
        print(
            f"  • {m.agent_name:12s} steps={m.steps}  "
            f"duration={m.duration_ms:6.0f}ms  "
            f"tokens={toks:5d} (prompt={m.tokens_prompt}, "
            f"out={m.tokens_completion}, cached={m.tokens_cached} = {cache_pct:.0f}%)"
        )

    if args.save:
        with open(args.save, "w", encoding="utf-8") as f:
            f.write(inv.model_dump_json(indent=2))
        print(f"\n→ Saved to {args.save}")


def main():
    asyncio.run(amain())


if __name__ == "__main__":
    main()
