#!/usr/bin/env python3
"""Live evasion detection daemon — Linux/auditd edition.

Poll Elasticsearch (Elastic Agent auditd stream) for new EXECVE events,
run Stage 1 + Stage 2, and index alerts back to Elasticsearch.

Perbedaan vs detect_live.py (Windows):
  - Không filter theo winlog.event_id (auditd không có field đó).
  - Lọc tùy chọn theo data_stream.dataset (cấu hình qua dataset_filter trong YAML).
  - Alert doc bỏ winlog.*, thêm auditd.* fields.
  - Đọc sigma_rules_dirs (list) thay vì rules_dir (string đơn).

Chạy:
  source ~/venvs/rule_evasion_env/bin/activate
  python red_linux/scripts/detect_live_linux.py \\
    --config config/detect_live_linux.yml \\
    --es-host http://192.168.10.10:9200 \\
    --es-index "logs-auditd_manager.auditd-*" \\
    --out-index red-alerts-linux \\
    --threshold 0.46 --method cosine --interval 30
"""

import os

# PORTABILITY: tắt Intel oneDAL TRƯỚC khi import red.* — oneDAL ném std::bad_alloc khi
# inference SVM trên CPU khác (model train-oneDAL drop cột zero-coef → lệch dim). Model
# production đã được sửa thành pure-sklearn (repair_svm_portable.py → *_portable.zip).
# Đặt env này để chắc chắn chạy pure sklearn dù model nào. Xem red_linux/CLAUDE.md.
os.environ.setdefault("RED_DISABLE_INTELEX", "1")

import sys
import json
import time
import argparse
import logging
import datetime
from urllib.parse import urlsplit, urlunsplit

import numpy as np
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from red.normalize import Normalizer
from red.persist import load_result
from red.data import resolve_event_paths
from red.attribution import reciprocal_rank_fusion
from red.rule_metadata import SigmaRuleIndex, normalize_title
from red.sigma_exact import SigmaExactMatcher
from red.stage2_live import LiveAttributor

logger = logging.getLogger("detect_live_linux")

STATE_FILE = ".detect_live_linux_state.json"

LEVEL_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4, "": 5}


def _mitre_depth(tags: list) -> int:
    """Negated max MITRE sub-technique depth — deeper = more specific = sort earlier."""
    depth = 0
    for t in tags:
        if isinstance(t, str) and t.startswith("attack.t"):
            depth = max(depth, t.count("."))
    return -depth


def parse_preferred_sigma_ids(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip().lower() for item in value.split(",") if item.strip()]


def sort_exact_matches(exact_matches: list, preferred_ids: list[str]) -> list:
    if not exact_matches or not preferred_ids:
        return exact_matches

    def priority(match) -> tuple[int, str]:
        sigma_id = match.sigma_id.lower()
        for idx, preferred in enumerate(preferred_ids):
            if sigma_id == preferred or sigma_id.startswith(preferred):
                return idx, match.rule
        return len(preferred_ids), match.rule

    return sorted(exact_matches, key=priority)


def promote_exact_matches(top_rules, exact_matches, top_k):
    """Layer-3: đặt luật Sigma FIRE-THẬT (logic xác nhận) lên trước phỏng đoán cosine."""
    if not exact_matches:
        return top_rules
    promoted, seen = [], set()
    for m in exact_matches:
        if m.rule in seen:
            continue
        promoted.append((m.rule, 1.0))
        seen.add(m.rule)
    for rule_name, s in top_rules:
        if rule_name in seen:
            continue
        promoted.append((rule_name, s))
        seen.add(rule_name)
        if len(promoted) >= top_k:
            break
    return promoted[:top_k]


# ── Helpers ──────────────────────────────────────────────────────────────────

def mask_url_password(url: str) -> str:
    parts = urlsplit(url)
    if not parts.password:
        return url
    host = parts.hostname or ""
    if parts.port:
        host = f"{host}:{parts.port}"
    userinfo = parts.username or ""
    if userinfo:
        host = f"{userinfo}:****@{host}"
    return urlunsplit((parts.scheme, host, parts.path, parts.query, parts.fragment))


def es_search(es_host: str, index: str, query: dict) -> list:
    import requests
    url = f"{es_host.rstrip('/')}/{index}/_search"
    resp = requests.get(url, json=query, timeout=30, verify=False)
    resp.raise_for_status()
    return resp.json()["hits"]["hits"]


def es_index(es_host: str, index: str, doc: dict) -> None:
    import requests
    url = f"{es_host.rstrip('/')}/{index}/_doc"
    resp = requests.post(url, json=doc, timeout=10, verify=False)
    resp.raise_for_status()


def get_dotted(obj: dict, path: str):
    cur = obj
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def poll_new_events(
    es_host: str,
    index: str,
    since_ts: str,
    size: int = 500,
    timestamp_field: str = "@timestamp",
    until_ts: str | None = None,
    query_string: str | None = None,
    dataset_filter: str | None = None,
) -> tuple[list, str]:
    """Poll ES for Linux auditd events — không dùng winlog.event_id filter."""
    time_range = {"gt": since_ts}
    if until_ts:
        time_range["lte"] = until_ts

    filters = [{"range": {timestamp_field: time_range}}]

    # Lọc theo data_stream.dataset nếu cấu hình (vd: "auditd_manager.auditd")
    if dataset_filter:
        filters.append({"term": {"data_stream.dataset": dataset_filter}})

    must = []
    if query_string:
        must.append({"query_string": {"query": query_string}})

    query = {
        "query": {"bool": {"filter": filters, "must": must}},
        "sort": [{timestamp_field: "asc"}],
        "size": size,
    }

    hits = es_search(es_host, index, query)
    events = [h["_source"] for h in hits]
    last_ts = get_dotted(hits[-1]["_source"], timestamp_field) if hits else since_ts
    if not last_ts:
        last_ts = since_ts
    return events, last_ts


def extract_field(event: dict, paths: list) -> str:
    """Trích text từ event theo danh sách path ưu tiên.
    Hỗ trợ cả string lẫn list (process.args là mảng — tự join bằng dấu cách).
    """
    for path in paths:
        obj = event
        for key in path.split("."):
            obj = obj.get(key) if isinstance(obj, dict) else None
        if obj and isinstance(obj, str):
            return obj
        if obj and isinstance(obj, list):
            joined = " ".join(str(x) for x in obj if x)
            if joined:
                return joined
    return ""


def score_stage1(normalized: str, estimator, vectorizer, scaler, shift: float) -> float:
    # Portability: chạy pure sklearn (RED_DISABLE_INTELEX=1 ở đầu file) + model đã được
    # repair_svm_portable.py sửa coef_ về đủ dim → sparse input chạy mọi CPU, không
    # std::bad_alloc. Xem red_linux/CLAUDE.md.
    X = vectorizer.transform([normalized])
    raw = float(estimator.decision_function(X)[0])
    if scaler is not None:
        shifted = np.array([[raw - shift]])
        return float(np.clip(scaler.transform(shifted).flatten()[0], 0.0, 1.0))
    return raw


def attribute_stage2(
    normalized: str,
    rule_models: dict,
    cosine_attributor,
    method: str,
    top_k: int,
    rrf_k: int = 60,
) -> list:
    if method == "cosine" and cosine_attributor is not None:
        return cosine_attributor.score_samples([normalized])[0][:top_k]

    svm_scores = {}
    for rule_name, model in rule_models.items():
        try:
            X = model["vectorizer"].transform([normalized])
            svm_scores[rule_name] = float(model["estimator"].decision_function(X)[0])
        except Exception:
            pass
    svm_ranking = sorted(svm_scores.items(), key=lambda x: x[1], reverse=True)

    if method == "svm" or cosine_attributor is None:
        return svm_ranking[:top_k]

    cosine_ranking = cosine_attributor.score_samples([normalized])[0]
    return reciprocal_rank_fusion([svm_ranking, cosine_ranking], k=rrf_k)[:top_k]


def load_state(path: str, default_ts: str) -> str:
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f).get("last_ts", default_ts)
    return default_ts


def save_state(path: str, last_ts: str) -> None:
    with open(path, "w") as f:
        json.dump({"last_ts": last_ts}, f)


def parse_time_arg(value: str | None) -> str | None:
    if not value:
        return None
    value = value.strip()
    if value == "now":
        return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
    unit_sec = {"m": 60, "h": 3600, "d": 86400}
    if len(value) >= 2 and value[-1] in unit_sec:
        seconds = unit_sec[value[-1]] * int(value[:-1])
        return (
            datetime.datetime.utcnow() - datetime.timedelta(seconds=seconds)
        ).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    if value.endswith("Z"):
        return value
    if "T" in value:
        return value + "Z"
    raise ValueError(
        f"Invalid time value '{value}'. Use 15m, 2h, now, or 2026-05-15T10:00:00Z"
    )


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Live evasion detection (Linux/auditd) via Elasticsearch polling"
    )
    parser.add_argument("--config", type=str, required=True)
    parser.add_argument("--es-host", type=str, default="http://localhost:9200")
    parser.add_argument("--es-index", type=str, default="logs-auditd_manager.auditd-*")
    parser.add_argument("--out-index", type=str, default="red-alerts-linux")
    parser.add_argument("--threshold", type=float, default=0.46)
    parser.add_argument("--method", type=str, default="cosine",
                        choices=["svm", "cosine", "hybrid"])
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--interval", type=int, default=30,
                        help="Poll interval in seconds (default 30)")
    parser.add_argument("--lookback", type=str, default="1h")
    parser.add_argument("--since", type=str, default=None)
    parser.add_argument("--until", type=str, default=None)
    parser.add_argument("--timestamp-field", type=str, default="@timestamp")
    parser.add_argument("--query-string", type=str, default=None,
                        help="Extra Elasticsearch query_string filter")
    parser.add_argument("--state-file", type=str, default=STATE_FILE)
    parser.add_argument("--reset-state", action="store_true")
    parser.add_argument("--no-state", action="store_true")
    parser.add_argument("--max-iter", type=int, default=0,
                        help="Stop after N iterations (0 = run forever)")
    parser.add_argument("--batch-size", type=int, default=500)
    parser.add_argument("--exact-sigma", action=argparse.BooleanOptionalAction, default=True,
                        help="Layer-3: chạy logic Sigma trên event, đẩy luật fire-thật lên #1 "
                             "(tắt bằng --no-exact-sigma)")
    parser.add_argument(
        "--exact-sigma-max-matches",
        type=int,
        default=10,
        help="Maximum exact Sigma matches to store in each alert.",
    )
    parser.add_argument(
        "--exact-sigma-prefer-ids",
        type=str,
        default="",
        help="Comma-separated Sigma UUIDs or prefixes to prefer when multiple exact rules fire.",
    )
    parser.add_argument("--stage2-mode", choices=["legacy", "live"], default="live",
                        help="live (mặc định) = Stage 2/3 mới: 2-pass Sigma + decode + confidence; "
                             "legacy = cosine + promote_exact_matches cũ")
    parser.add_argument(
        "--min-text-len", type=int, default=15,
        help="Bỏ qua event có command_line dưới N ký tự (tránh FP ngắn). Default 15.",
    )
    args = parser.parse_args()
    preferred_sigma_ids = parse_preferred_sigma_ids(args.exact_sigma_prefer_ids)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )
    logging.getLogger("sklearnex").setLevel(logging.WARNING)

    import yaml
    with open(args.config) as f:
        cfg = yaml.safe_load(f)
    data_cfg = cfg.get("data", {})
    out_cfg = cfg.get("output", {})

    # ── Field mapping ─────────────────────────────────────────────────────────
    search_fields = data_cfg.get("search_fields", ["CommandLine", "Image"])
    event_field_map = data_cfg.get("event_field_map", {})
    event_paths = resolve_event_paths(search_fields, event_field_map)
    logger.info("Monitoring field paths: %s", event_paths)

    dataset_filter = data_cfg.get("dataset_filter")
    if dataset_filter:
        logger.info("Dataset filter: data_stream.dataset = %s", dataset_filter)

    # ── Load Stage 1 ──────────────────────────────────────────────────────────
    s1_path = os.path.expanduser(out_cfg["train_result_path"])
    logger.info("Loading Stage 1 from %s ...", s1_path)
    r1 = load_result(s1_path)
    s1_estimator = r1["estimator"]
    s1_vectorizer = r1["vectorizer"]
    s1_scaler = r1.get("scaler")
    s1_shift = float(r1.get("shift", 0.0))
    logger.info("Stage 1 ready")

    # ── Load Stage 2 ──────────────────────────────────────────────────────────
    out_dir = os.path.expanduser(out_cfg.get("dir", "models/linux_process_creation"))
    attr_name = out_cfg.get("attr_result_name", "attr_ensemble")
    s2_path = os.path.join(out_dir, f"train_rslt_{attr_name}.zip")
    logger.info("Loading Stage 2 from %s ...", s2_path)
    r2 = load_result(s2_path)
    rule_models = r2["rule_models"]
    cosine_attributor = r2.get("cosine_attributor")
    logger.info(
        "Stage 2 ready — %d rule models, cosine=%s",
        len(rule_models),
        "yes" if cosine_attributor else "no",
    )

    # ── Sigma rule index (metadata enrichment) ────────────────────────────────
    # Hỗ trợ cả sigma_rules_dirs (list) lẫn rules_dir (string đơn)
    sigma_dirs_raw = data_cfg.get("sigma_rules_dirs") or (
        [data_cfg["rules_dir"]] if data_cfg.get("rules_dir") else []
    )
    all_rule_dirs = [os.path.expanduser(d) for d in sigma_dirs_raw]
    rule_index = None
    if all_rule_dirs:
        rule_index = SigmaRuleIndex.from_rules_dirs(all_rule_dirs)
        logger.info(
            "SigmaRuleIndex: %d rules indexed from %s",
            len(rule_index),
            all_rule_dirs,
        )

    # ── Layer-3 / Stage 2 live: Sigma-logic exact matcher ────────────────────
    exact_matcher = None
    if all_rule_dirs and args.exact_sigma:
        exact_matcher = SigmaExactMatcher.from_rules_dirs(
            all_rule_dirs,
            event_field_map=event_field_map,
            search_fields=search_fields,
        )
        logger.info("Stage 2 Sigma Matcher: loaded %d rule dirs", len(all_rule_dirs))

    # ── Stage 2/3 live attributor (2-pass Sigma + decode + confidence) ───────
    live_attributor = None
    if args.stage2_mode == "live" and exact_matcher is not None:
        live_attributor = LiveAttributor(
            matcher=exact_matcher,
            cosine_attributor=cosine_attributor,
            normalizer=Normalizer(),
            event_field_map=event_field_map,
            search_fields=search_fields,
        )
        logger.info("Stage 2 live mode BẬT (Pass 1 Sigma + decode + Pass 2 Sigma + cosine + confidence)")

    normalizer = Normalizer()

    # ── State ─────────────────────────────────────────────────────────────────
    if args.reset_state and os.path.exists(args.state_file):
        os.remove(args.state_file)
        logger.info("Removed state file: %s", args.state_file)

    unit_sec = {"m": 60, "h": 3600, "d": 86400}
    lookback_sec = unit_sec.get(args.lookback[-1], 3600) * int(args.lookback[:-1])
    default_ts = (
        datetime.datetime.utcnow() - datetime.timedelta(seconds=lookback_sec)
    ).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    explicit_since = parse_time_arg(args.since)
    until_ts = parse_time_arg(args.until)
    if explicit_since:
        since_ts = explicit_since
    elif args.no_state:
        since_ts = default_ts
    else:
        since_ts = load_state(args.state_file, default_ts)

    logger.info(
        "Starting — polling %s every %ds (%s > %s%s)",
        args.es_index,
        args.interval,
        args.timestamp_field,
        since_ts,
        f", <= {until_ts}" if until_ts else "",
    )
    logger.info(
        "Alerts → %s/%s, threshold=%.2f, method=%s",
        mask_url_password(args.es_host),
        args.out_index,
        args.threshold,
        args.method,
    )

    # ── Poll loop ─────────────────────────────────────────────────────────────
    iter_count = 0
    while True:
        try:
            iter_count += 1
            events, last_ts = poll_new_events(
                args.es_host,
                args.es_index,
                since_ts,
                args.batch_size,
                timestamp_field=args.timestamp_field,
                until_ts=until_ts,
                query_string=args.query_string,
                dataset_filter=dataset_filter,
            )

            if events:
                logger.info("Fetched %d new events (up to %s)", len(events), last_ts)
                n_alerts = 0

                for event in events:
                    text = extract_field(event, event_paths)
                    if not text:
                        continue
                    if len(text.strip()) < args.min_text_len:
                        continue

                    normalized = normalizer.normalize(text)
                    if not normalized:
                        continue

                    score = score_stage1(
                        normalized, s1_estimator, s1_vectorizer, s1_scaler, s1_shift
                    )
                    if score < args.threshold:
                        continue

                    # ── Stage 2/3: live mode (2-pass) hoặc legacy ───────────
                    stage2_extra: dict = {}
                    if live_attributor is not None:
                        verdict = live_attributor.attribute(event, text)
                        top_rule_name = verdict.top_rule
                        top_rules = verdict.cosine_top or (
                            [(r, 1.0) for r in (verdict.evaded_rule or verdict.evasion_technique)]
                        )
                        stage2_extra = verdict.to_dict()
                    else:
                        # legacy: cosine + promote_exact_matches
                        top_rules = attribute_stage2(
                            normalized, rule_models, cosine_attributor,
                            args.method, args.top_k,
                        )
                        exact_matches = exact_matcher.match_event(event) if exact_matcher else []
                        exact_matches = sort_exact_matches(exact_matches, preferred_sigma_ids)
                        if exact_matches:
                            top_rules = promote_exact_matches(top_rules, exact_matches, args.top_k)
                        top_rule_name = top_rules[0][0] if top_rules else None
                        stage2_extra = {
                            "red.exact_sigma_match": bool(exact_matches),
                            "red.exact_sigma_matches": [
                                m.to_alert_dict()
                                for m in exact_matches[:args.exact_sigma_max_matches]
                            ],
                        }

                    alert = {
                        "@timestamp": event.get("@timestamp"),
                        "red.detection_score": round(score, 4),
                        "red.attribution_method": args.method,
                        "red.stage2_mode": args.stage2_mode,
                        "red.top_rule": top_rule_name,
                        "red.command_line": text,
                        "host.name": event.get("host", {}).get("name", "unknown"),
                        "host.os.type": "linux",
                        "process": event.get("process", {}),
                        "user": event.get("user", {}),
                        "auditd": event.get("auditd", {}),
                        **stage2_extra,
                    }

                    if rule_index is not None:
                        evaded = stage2_extra.get("red.evaded_rule") or []
                        if evaded:
                            # Sigma fired: populate from evaded rules (score=1.0 = exact match)
                            alert["red.evaded_rules_meta"] = [
                                {
                                    "score": 1.0,
                                    "rule": r,
                                    **rule_index.lookup_dict(normalize_title(r)),
                                }
                                for r in evaded
                            ]
                            evaded_meta = [
                                (r, rule_index.lookup_dict(normalize_title(r)))
                                for r in evaded
                            ]
                            evaded_sorted = sorted(
                                evaded_meta,
                                key=lambda rm: (
                                    LEVEL_ORDER.get(rm[1].get("level", ""), 5),
                                    _mitre_depth(rm[1].get("tags", [])),
                                ),
                            )
                            alert["red.primary_rule"] = evaded_sorted[0][0]
                        else:
                            # Cosine fallback: populate from top_rules cosine attribution
                            alert["red.evaded_rules_meta"] = [
                                {
                                    "score": round(s, 4),
                                    "rule": r,
                                    **rule_index.lookup_dict(normalize_title(r)),
                                }
                                for r, s in top_rules[:args.top_k]
                            ]
                            alert["red.primary_rule"] = top_rule_name

                    es_index(args.es_host, args.out_index, alert)
                    n_alerts += 1

                    logger.info(
                        "[ALERT] host=%s  score=%.3f  conf=%s  top=%s | %s",
                        alert["host.name"],
                        score,
                        alert.get("red.confidence", "legacy"),
                        alert["red.top_rule"],
                        text[:120],
                    )

                since_ts = last_ts
                if not args.no_state and not explicit_since:
                    save_state(args.state_file, since_ts)

                if n_alerts:
                    logger.info("Indexed %d alerts to '%s'", n_alerts, args.out_index)
            else:
                logger.debug("No new events since %s", since_ts)

        except KeyboardInterrupt:
            logger.info("Interrupted — saving state and exiting.")
            if not args.no_state and not explicit_since:
                save_state(args.state_file, since_ts)
            break
        except Exception as exc:
            logger.error("Poll error: %s", exc, exc_info=True)

        if args.max_iter and iter_count >= args.max_iter:
            logger.info("Reached max_iter=%d — exiting.", args.max_iter)
            break

        time.sleep(args.interval)


if __name__ == "__main__":
    main()
