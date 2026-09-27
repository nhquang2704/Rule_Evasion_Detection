"""Orchestrator — chạy workflow multi-agent (async, có parallel).

Workflow MVP (3 agents):
  Supervisor → quyết định workflow
  Triage    → severity + FP filter (có tools)
  Report    → báo cáo tiếng Việt (dùng triage output)

Phase 2 (sẽ thêm sau):
  Sau Triage: chạy SONG SONG Hunt + RED Analyst + MITRE
  Sau đó Report (dùng tất cả output)
  Cuối: Response Agent đề xuất action
"""

import os
import time
import uuid
import asyncio
import logging
from typing import Optional

from agent import tools as tools_module
from agent.llm import LLMClient
from agent.agents import (
    run_supervisor, run_triage, run_forensic,
    run_hunt, run_red_analyst, run_mitre,
    run_response, run_report,
)
from agent.schemas import (
    Investigation, AgentMetadata, WorkflowPlan,
    TriageOutput, ForensicOutput,
    HuntOutput, RedAnalystOutput, MitreOutput,
    ResponseOutput, ReportOutput,
)

logger = logging.getLogger("agent.orchestrator")

# DeepSeek pricing (2026, ước tính, USD per 1M tokens) — dùng để estimate cost
COST_PER_M_INPUT = 0.27
COST_PER_M_CACHED = 0.07
COST_PER_M_OUTPUT = 1.10


async def investigate(
    alert: dict,
    use_real_es: bool = False,
    verbose: bool = True,
) -> Investigation:
    """Run full investigation workflow on 1 alert."""
    tools_module.USE_REAL_ES = use_real_es

    llm = LLMClient()
    t0 = time.time()
    inv_id = f"INV-{uuid.uuid4().hex[:12]}"
    metadata: list[AgentMetadata] = []

    # ── Step 1: Supervisor ──
    logger.info("═" * 60)
    logger.info("🎯 Supervisor: deciding workflow...")
    plan, sup_raw = await run_supervisor(llm, alert, verbose=verbose)
    metadata.append(_meta_from_raw("supervisor", sup_raw))
    logger.info("✓ Plan: workflow=%s, priority=%d, agents=%s",
                plan.workflow_type, plan.priority, plan.agents_to_run)
    logger.info("  Reasoning: %s", plan.reasoning)

    # Skip FP — early exit
    if plan.workflow_type == "skip_fp":
        logger.info("→ skip_fp: bỏ qua, không investigate thêm")
        return _build_investigation(inv_id, alert, plan, None, None, None, None, None, None, metadata, llm, t0)

    # ── Step 2: Triage ──
    logger.info("─" * 60)
    logger.info("🔍 Triage: gathering context với tools...")
    triage, tri_raw = await run_triage(llm, alert, verbose=verbose)
    metadata.append(_meta_from_raw("triage", tri_raw))
    logger.info("✓ Triage: severity=%s, FP=%s, confidence=%.2f",
                triage.severity, triage.is_false_positive, triage.confidence)

    # Early exit nếu Triage xác nhận FP
    if triage.is_false_positive:
        logger.info("→ Triage xác định FP — skip rest")
        return _build_investigation(inv_id, alert, plan, triage, None, None, None, None, None, None, metadata, llm, t0)

    # ── Step 2.5: Forensic — bằng chứng host-level từ Velociraptor ──
    # Chỉ chạy nếu severity đủ cao — LOW thì skip để tiết kiệm
    forensic: Optional[ForensicOutput] = None
    if triage.severity in ("CRITICAL", "HIGH", "MEDIUM"):
        logger.info("─" * 60)
        logger.info("🔬 Forensic: thu thập bằng chứng host qua Velociraptor...")
        forensic, for_raw = await run_forensic(llm, alert, triage, verbose=verbose)
        metadata.append(_meta_from_raw("forensic", for_raw))
        logger.info("✓ Forensic: grade=%s, verdict=%s, persistence=%s, c2=%s",
                    forensic.evidence_grade, forensic.forensic_verdict_vi,
                    forensic.persistence_found, forensic.c2_confirmed)

        # Forensic xác nhận benign → early exit
        if forensic.forensic_verdict_vi == "likely_benign":
            logger.info("→ Forensic xác định benign (evidence cứng) — close case")
            return _build_investigation(inv_id, alert, plan, triage, forensic, None, None, None, None, None, metadata, llm, t0)
    else:
        logger.info("→ Severity %s — skip Forensic để tiết kiệm", triage.severity)

    # ── Step 3: Hunt + RED Analyst + MITRE chạy SONG SONG ──
    logger.info("─" * 60)
    logger.info("⚡ Parallel investigation: Hunt + RED Analyst + MITRE")
    par_t0 = time.time()

    (hunt, hunt_raw), (red_analyst, red_raw), (mitre, mitre_raw) = await asyncio.gather(
        run_hunt(llm, alert, triage, verbose=verbose),
        run_red_analyst(llm, alert, verbose=verbose),
        run_mitre(llm, alert, verbose=verbose),
    )
    par_elapsed = (time.time() - par_t0) * 1000
    seq_estimate = (
        hunt_raw.get("_meta", {}).get("duration_ms", 0)
        + red_raw.get("_meta", {}).get("duration_ms", 0)
        + mitre_raw.get("_meta", {}).get("duration_ms", 0)
    )
    logger.info("✓ Parallel done in %.0fms (sequential ước ~%.0fms — tiết kiệm %.0fms)",
                par_elapsed, seq_estimate, seq_estimate - par_elapsed)
    metadata.extend([
        _meta_from_raw("hunt", hunt_raw),
        _meta_from_raw("red_analyst", red_raw),
        _meta_from_raw("mitre", mitre_raw),
    ])

    # ── Step 4: Response — Sigma patch + containment (sequential, cần outputs trên) ──
    logger.info("─" * 60)
    logger.info("🛡️  Response: sinh Sigma patch + containment actions...")
    response, resp_raw = await run_response(
        llm, alert, triage,
        hunt=hunt, red_analyst=red_analyst, mitre=mitre,
        forensic=forensic,
        verbose=verbose,
    )
    metadata.append(_meta_from_raw("response", resp_raw))
    logger.info("✓ Response: %d actions, sigma_patch=%d chars, notify_sent=%s",
                len(response.containment_actions),
                len(response.sigma_patch_yaml),
                response.notification_sent)

    # ── Step 5: Report — tổng hợp tất cả 5 agent outputs ──
    logger.info("─" * 60)
    logger.info("📝 Report: sinh báo cáo tiếng Việt (5 agents)...")
    report, rep_raw = await run_report(
        llm, alert, triage,
        hunt=hunt, red_analyst=red_analyst, mitre=mitre, response=response,
        forensic=forensic,
        verbose=verbose,
    )
    metadata.append(_meta_from_raw("report", rep_raw))
    logger.info("✓ Report: %s", report.title_vi)

    return _build_investigation(
        inv_id, alert, plan, triage, forensic, hunt, red_analyst, mitre, response, report,
        metadata, llm, t0,
    )


def _meta_from_raw(agent_name: str, raw: dict) -> AgentMetadata:
    """Build AgentMetadata từ _meta của react_loop (parallel-safe)."""
    m = raw.get("_meta", {})
    return AgentMetadata(
        agent_name=agent_name,
        duration_ms=m.get("duration_ms", 0.0),
        steps=m.get("steps", 0),
        tokens_prompt=m.get("tokens_prompt", 0),
        tokens_completion=m.get("tokens_completion", 0),
        tokens_cached=m.get("tokens_cached", 0),
        error=raw.get("error"),
    )


def _build_investigation(
    inv_id: str,
    alert: dict,
    plan: WorkflowPlan,
    triage: Optional[TriageOutput],
    forensic: Optional[ForensicOutput],
    hunt: Optional[HuntOutput],
    red_analyst: Optional[RedAnalystOutput],
    mitre: Optional[MitreOutput],
    response: Optional[ResponseOutput],
    report: Optional[ReportOutput],
    metadata: list[AgentMetadata],
    llm: LLMClient,
    t0: float,
) -> Investigation:
    usage = llm.usage_summary()
    cost = (
        (usage["prompt_tokens"] - usage["cached_tokens"]) / 1_000_000 * COST_PER_M_INPUT
        + usage["cached_tokens"] / 1_000_000 * COST_PER_M_CACHED
        + usage["completion_tokens"] / 1_000_000 * COST_PER_M_OUTPUT
    )
    return Investigation(
        investigation_id=inv_id,
        trigger_alert=alert,
        workflow_plan=plan,
        triage=triage,
        forensic=forensic,
        hunt=hunt,
        red_analyst=red_analyst,
        mitre=mitre,
        response=response,
        report=report,
        agent_metadata=metadata,
        total_duration_ms=round((time.time() - t0) * 1000, 1),
        total_tokens=usage["total_tokens"],
        estimated_cost_usd=round(cost, 6),
    )
