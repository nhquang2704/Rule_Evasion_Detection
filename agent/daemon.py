#!/usr/bin/env python3
"""RED Agent Daemon — Poll red-alerts → Multi-agent investigate → Write ai-investigations-*.

Run continuously, monitors red-alerts ES index for new RED findings.
Mỗi alert → 7-agent pipeline → kết quả ghi vào ai-investigations-* index.

Usage:
  # Production daemon (poll mỗi 60s, vô hạn)
  python3 -m agent.daemon --interval 60

  # Test mode — chạy 3 iterations rồi dừng
  python3 -m agent.daemon --interval 30 --max-iter 3

  # Dry-run (không ghi ES, chỉ in log)
  python3 -m agent.daemon --dry-run

  # Reset state + reprocess tất cả alerts
  python3 -m agent.daemon --reset-state

  # Chỉ process alert có RED score >= 0.7 (filter noise)
  python3 -m agent.daemon --score-threshold 0.7
"""

import os
import sys
import time
import asyncio
import argparse
import logging
import signal

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.orchestrator import investigate
from agent.es_io import (
    check_es_connection,
    ensure_ai_index,
    poll_new_alerts,
    write_investigation,
    load_state,
    save_state,
    reset_state,
)
from agent.kibana_cases import (
    compact_report_for_dashboard,
    create_case_for_investigation,
)

logger = logging.getLogger("agent.daemon")

# Graceful shutdown
_shutdown = False


def _handle_signal(signum, frame):
    global _shutdown
    if _shutdown:
        logger.warning("Got signal %d again — force exit now", signum)
        os._exit(128 + signum)
    logger.info("Got signal %d — shutting down sau iteration hiện tại...", signum)
    _shutdown = True


signal.signal(signal.SIGINT, _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)


async def process_alert(alert: dict, dry_run: bool = False) -> bool:
    """Investigate 1 alert + write result.

    Returns True nếu thành công, False nếu failed.
    """
    es_id = alert.pop("_es_id", "unknown")
    host = alert.get("host", {}).get("name", "unknown")
    score = alert.get("red", {}).get("stage1_score", 0)

    logger.info("─" * 70)
    logger.info("📥 Alert es_id=%s host=%s score=%.2f", es_id, host, score)

    t0 = time.time()
    try:
        inv = await investigate(alert, use_real_es=True, verbose=False)
    except Exception as e:
        logger.exception("Investigation crashed: %s", e)
        return False

    elapsed = time.time() - t0
    severity = inv.triage.severity if inv.triage else "?"
    actions_count = len(inv.response.containment_actions) if inv.response else 0

    logger.info(
        "✓ Done in %.1fs — severity=%s, %d actions, %d tokens, $%.4f",
        elapsed, severity, actions_count, inv.total_tokens, inv.estimated_cost_usd,
    )

    if dry_run:
        logger.info("[dry-run] không ghi ES — investigation_id=%s", inv.investigation_id)
        return True
    try:
        case_id, case_url = create_case_for_investigation(inv)
        if inv.report:
            inv.report.kibana_case_id = case_id
            inv.report.kibana_case_url = case_url
            inv.report.full_report_url = case_url
            inv.report.full_markdown_vi = compact_report_for_dashboard(inv, case_url)
            if case_url:
                logger.info("→ Full report URL: %s", case_url)
    except Exception as e:
        logger.exception("Kibana case creation failed: %s", e)
        if inv.report:
            inv.report.full_markdown_vi = compact_report_for_dashboard(inv, None)
    try:
        result = write_investigation(inv)
        logger.info("→ Indexed: %s/%s", result.get("_index"), result.get("_id"))
        return True
    except Exception as e:
        logger.exception("ES write failed: %s", e)
        return False


async def daemon_loop(
    interval: int,
    dry_run: bool,
    max_iter: int,
    score_threshold: float,
    batch_limit: int,
    since: str | None,
    until: str | None,
    no_state: bool,
    query_string: str | None,
    needs_agent_only: bool = False,
):
    # Khi --needs-agent-only: chỉ lấy alerts Stage 2 không attribution được
    if needs_agent_only and not query_string:
        query_string = "red.needs_agent:true"

    state = load_state()
    if since:
        state["last_processed_timestamp"] = since
    iter_count = 0

    logger.info("═" * 70)
    logger.info("🤖 Agent daemon started")
    logger.info("   interval=%ds | dry_run=%s | max_iter=%s | score>=%.2f",
                interval, dry_run, max_iter or "∞", score_threshold)
    logger.info("   needs_agent_only=%s | query=%s", needs_agent_only, query_string or "(all)")
    logger.info("   last_processed=%s | total_processed=%d",
                state.get("last_processed_timestamp", "(none — process all)"),
                state.get("processed_count", 0))
    if until:
        logger.info("   until=%s", until)
    logger.info("═" * 70)

    while not _shutdown:
        iter_count += 1
        t_iter = time.time()

        try:
            alerts = poll_new_alerts(
                since_timestamp=state.get("last_processed_timestamp"),
                until_timestamp=until,
                limit=batch_limit,
                score_threshold=score_threshold,
                query_string=query_string,
            )
        except Exception as e:
            logger.exception("Poll failed: %s — retry sau %ds", e, interval)
            state["error_count"] = state.get("error_count", 0) + 1
            await asyncio.sleep(interval)
            continue

        if alerts:
            logger.info("[Iter %d] Found %d new alert(s)", iter_count, len(alerts))
            for alert in alerts:
                if _shutdown:
                    break
                # Save timestamp BEFORE processing — nếu crash, không re-process
                alert_ts = alert.get("@timestamp")
                success = await process_alert(alert, dry_run=dry_run)
                if success:
                    state["processed_count"] += 1
                    if alert_ts:
                        state["last_processed_timestamp"] = alert_ts
                else:
                    state["error_count"] = state.get("error_count", 0) + 1
                if not dry_run and not no_state:
                    save_state(state)
        else:
            logger.info("[Iter %d] No new alerts (waited since %s)",
                        iter_count, state.get("last_processed_timestamp", "init"))

        iter_elapsed = time.time() - t_iter

        if max_iter and iter_count >= max_iter:
            logger.info("Reached max_iter=%d → stopping", max_iter)
            break

        if _shutdown:
            break

        sleep_time = max(0, interval - iter_elapsed)
        if sleep_time > 0:
            logger.debug("Sleep %.1fs trước iter tiếp", sleep_time)
            await asyncio.sleep(sleep_time)

    logger.info("Daemon stopped. Stats: processed=%d errors=%d",
                state.get("processed_count", 0), state.get("error_count", 0))


def main():
    parser = argparse.ArgumentParser(
        description="RED Agent Daemon — poll ES + investigate + write back",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--interval", type=int, default=60,
                        help="Polling interval (giây). Default 60")
    parser.add_argument("--max-iter", type=int, default=0,
                        help="Stop sau N iterations (0 = run forever)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Investigate nhưng KHÔNG ghi ES")
    parser.add_argument("--reset-state", action="store_true",
                        help="Xóa state file → process lại tất cả alerts từ đầu")
    parser.add_argument("--score-threshold", type=float, default=0.0,
                        help="Chỉ process alerts có RED score >= threshold (default 0.0)")
    parser.add_argument("--batch-limit", type=int, default=20,
                        help="Số alerts max lấy về mỗi iteration. Default 20")
    parser.add_argument("--since", type=str, default=None,
                        help="Override state timestamp; process alerts with @timestamp > this ISO value")
    parser.add_argument("--until", type=str, default=None,
                        help="Only process alerts with @timestamp <= this ISO/date-math value")
    parser.add_argument("--no-state", action="store_true",
                        help="Do not save .agent_daemon_state.json; useful for demo one-shot runs")
    parser.add_argument("--query-string", type=str, default=None,
                        help="Optional Elasticsearch query_string filter on red-alerts")
    parser.add_argument("--needs-agent-only", action="store_true",
                        help="Chỉ process alerts có red.needs_agent=true "
                             "(confidence=unknown — Stage 2 không attribution được)")
    parser.add_argument("--skip-health-check", action="store_true",
                        help="Bỏ qua ES connection check")
    parser.add_argument("--red-index", type=str, default=None,
                        help="Override ES_RED_INDEX (vd red-alerts-linux). Ghi đè cả .env "
                             "vì agent/__init__.py load_dotenv(override=True).")
    parser.add_argument("--ai-index", type=str, default=None,
                        help="Override ES_AI_INDEX output (vd ai-investigations-linux)")
    args = parser.parse_args()

    logging.basicConfig(
        level=os.environ.get("AGENT_LOG_LEVEL", "INFO"),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    # Override index sau khi dotenv đã load (override=True trong __init__) — phải set
    # module-global vì es_io/tools đọc ES_RED_INDEX ở call time.
    if args.red_index:
        import agent.es_io as _esio
        import agent.tools as _tools
        _esio.ES_RED_INDEX = args.red_index
        _tools.ES_RED_INDEX = args.red_index
        logger.info("ES_RED_INDEX override → %s", args.red_index)
    if args.ai_index:
        import agent.es_io as _esio
        _esio.ES_AI_INDEX = args.ai_index
        logger.info("ES_AI_INDEX override → %s", args.ai_index)

    if args.reset_state:
        reset_state()

    if not args.skip_health_check:
        if not check_es_connection():
            logger.error("ES connection failed — exit (skip với --skip-health-check)")
            sys.exit(1)

    if not args.dry_run:
        try:
            ensure_ai_index()
        except Exception as e:
            logger.error("Cannot ensure ai-investigations index: %s", e)
            sys.exit(2)

    try:
        asyncio.run(daemon_loop(
            interval=args.interval,
            dry_run=args.dry_run,
            max_iter=args.max_iter,
            score_threshold=args.score_threshold,
            batch_limit=args.batch_limit,
            since=args.since,
            until=args.until,
            no_state=args.no_state,
            query_string=args.query_string,
            needs_agent_only=args.needs_agent_only,
        ))
    except KeyboardInterrupt:
        logger.info("Interrupted by user")


if __name__ == "__main__":
    main()
