#!/usr/bin/env python3
"""Batch evasion detection on exported JSONL events.

Reads a JSONL file (from elk_export.py), runs Stage 1 (misuse detection)
then Stage 2 (rule attribution) on suspicious events, outputs alerts.

Usage:
  python scripts/detect_batch.py \\
    --config config/process_creation.yaml \\
    --events exported_events.jsonl \\
    --threshold 0.5 \\
    --method hybrid \\
    --out alerts.jsonl
"""

import os
import sys
import json
import argparse
import logging
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from red.normalize import Normalizer
from red.persist import load_result
from red.data import resolve_event_paths
from red.attribution import reciprocal_rank_fusion
from red.rule_metadata import SigmaRuleIndex

logger = logging.getLogger("detect_batch")


def extract_field(event: dict, paths: list) -> str:
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


def load_stage1(result_path: str):
    train_result = load_result(result_path)
    return (
        train_result["estimator"],
        train_result["vectorizer"],
        train_result.get("scaler"),
        float(train_result.get("shift", 0.0)),
    )


def load_stage2(result_path: str):
    attr_result = load_result(result_path)
    return attr_result["rule_models"], attr_result.get("cosine_attributor")


def score_event(normalized: str, estimator, vectorizer, scaler, shift: float) -> float:
    X = vectorizer.transform([normalized])
    raw = float(estimator.decision_function(X)[0])
    if scaler is not None:
        shifted = np.array([[raw - shift]])
        return float(np.clip(scaler.transform(shifted).flatten()[0], 0.0, 1.0))
    return raw


def _append_alert(alerts: list, event: dict, text: str, score: float,
                  method: str, top_rules: list, rule_index=None) -> None:
    top_rule_name = top_rules[0][0] if top_rules else None

    # Build top_rules với metadata Sigma (filename + UUID) nếu có rule_index
    top_rules_enriched = []
    for r, s in top_rules:
        entry = {"rule": r, "score": round(s, 4)}
        if rule_index is not None:
            meta = rule_index.lookup_dict(r)
            entry["sigma_filename"] = meta.get("filename")
            entry["sigma_id"] = meta.get("sigma_id")
            entry["sigma_title"] = meta.get("title")
        top_rules_enriched.append(entry)

    alert = {
        "@timestamp": event.get("@timestamp"),
        "host": event.get("host", {}).get("name", "unknown"),
        "command_line": text,
        "detection_score": round(score, 4),
        "attribution_method": method,
        "top_rules": top_rules_enriched,
        "top_rule": top_rule_name,
    }
    # Inject top-level Sigma metadata cho rule cao điểm nhất (dễ filter trong Kibana)
    if top_rule_name and rule_index is not None:
        meta = rule_index.lookup_dict(top_rule_name)
        alert["top_rule_sigma_filename"] = meta.get("filename")
        alert["top_rule_sigma_id"] = meta.get("sigma_id")
        alert["top_rule_sigma_title"] = meta.get("title")
    alerts.append(alert)


def attribute_event(normalized: str, rule_models: dict, cosine_attributor,
                    method: str, top_k: int, rrf_k: int = 60) -> list:
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

    if method == "cosine":
        return cosine_ranking[:top_k]

    return reciprocal_rank_fusion([svm_ranking, cosine_ranking], k=rrf_k)[:top_k]


def main():
    parser = argparse.ArgumentParser(description="Batch evasion detection on JSONL events")
    parser.add_argument("--config", type=str, required=True, help="YAML config file")
    parser.add_argument("--events", type=str, required=True, help="Input JSONL events file")
    parser.add_argument("--threshold", type=float, default=0.0,
                        help="Stage 1 detection threshold (default 0 = raw decision boundary)")
    parser.add_argument("--method", type=str, default="hybrid",
                        choices=["svm", "cosine", "hybrid"],
                        help="Attribution method")
    parser.add_argument("--top-k", type=int, default=5, help="Top-K rules to return")
    parser.add_argument("--out", type=str, default=None,
                        help="Output JSONL file (default: stdout)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")

    import yaml
    with open(args.config) as f:
        cfg = yaml.safe_load(f)
    data_cfg = cfg.get("data", {})
    out_cfg = cfg.get("output", {})

    search_fields = data_cfg.get("search_fields", ["CommandLine"])
    event_field_map = data_cfg.get("event_field_map", {})
    event_paths = resolve_event_paths(search_fields, event_field_map)
    logger.info("Field paths: %s", event_paths)

    # Stage 1
    s1_path = os.path.expanduser(out_cfg["train_result_path"])
    s1_estimator, s1_vectorizer, s1_scaler, s1_shift = load_stage1(s1_path)
    logger.info("Stage 1 loaded from %s", s1_path)

    # Stage 2
    out_dir = os.path.expanduser(out_cfg.get("dir", "models"))
    attr_name = out_cfg.get("attr_result_name", "attr_ensemble")
    s2_path = os.path.join(out_dir, f"train_rslt_{attr_name}.zip")
    rule_models, cosine_attributor = load_stage2(s2_path)
    logger.info("Stage 2 loaded: %d rules, cosine=%s", len(rule_models),
                "yes" if cosine_attributor else "no")

    # Build SigmaRuleIndex để inject metadata (filename + UUID + title) vào alert
    rules_dir = data_cfg.get("rules_dir")
    rule_index = None
    if rules_dir:
        # Load rules_dir của event type này + 2 dir khác để lookup được rule cross-type
        all_rule_dirs = [rules_dir]
        # Bonus: load thêm các thư mục anh em (process_creation, registry, powershell)
        rules_base = os.path.dirname(os.path.expanduser(rules_dir))
        for sibling in ("powershell", "process_creation", "registry"):
            sib_path = os.path.join(rules_base, sibling)
            if os.path.isdir(sib_path) and sib_path != os.path.expanduser(rules_dir):
                all_rule_dirs.append(sib_path)
        rule_index = SigmaRuleIndex.from_rules_dirs(all_rule_dirs)
        logger.info("SigmaRuleIndex: %d rules indexed for metadata enrichment", len(rule_index))

    normalizer = Normalizer()

    with open(args.events, encoding="utf-8") as f:
        events = [json.loads(line) for line in f if line.strip()]
    logger.info("Loaded %d events from %s", len(events), args.events)

    # ── Step 1: Extract + normalize all texts (filter out empties) ──
    valid_events = []
    valid_texts = []
    valid_normalized = []
    skipped = 0
    for event in events:
        text = extract_field(event, event_paths)
        if not text:
            skipped += 1
            continue
        normalized = normalizer.normalize(text)
        if not normalized:
            skipped += 1
            continue
        valid_events.append(event)
        valid_texts.append(text)
        valid_normalized.append(normalized)
    logger.info("Valid events: %d (skipped %d)", len(valid_normalized), skipped)

    if not valid_normalized:
        logger.warning("No valid events to score")
        return

    # ── Step 2: Batch Stage 1 — vectorize + decision_function ONCE ──
    logger.info("Stage 1: vectorizing and scoring %d events in batch...", len(valid_normalized))
    X = s1_vectorizer.transform(valid_normalized)
    raw_scores = s1_estimator.decision_function(X)
    raw_scores = np.asarray(raw_scores).ravel()
    if s1_scaler is not None:
        shifted = (raw_scores - s1_shift).reshape(-1, 1)
        scores = np.clip(s1_scaler.transform(shifted).flatten(), 0.0, 1.0)
    else:
        scores = raw_scores

    # ── Step 3: Filter suspicious ──
    alerts = []
    suspicious_idx = np.where(scores >= args.threshold)[0]
    logger.info("Suspicious events (score ≥ %.2f): %d / %d",
                args.threshold, len(suspicious_idx), len(scores))

    if len(suspicious_idx) == 0:
        logger.info("No alerts.")
    else:
        # ── Step 4: Batch Stage 2 attribution ──
        suspicious_normalized = [valid_normalized[i] for i in suspicious_idx]
        logger.info("Stage 2: attributing %d suspicious events with method=%s...",
                    len(suspicious_normalized), args.method)

        if args.method == "cosine" and cosine_attributor is not None:
            # Single batched call — fits all samples at once
            all_rankings = cosine_attributor.score_samples(suspicious_normalized)
            for j, i in enumerate(suspicious_idx):
                top_rules = all_rankings[j][:args.top_k]
                _append_alert(alerts, valid_events[i], valid_texts[i],
                              float(scores[i]), args.method, top_rules, rule_index)
        else:
            # SVM / Hybrid fallback — per-event (slower but rarely used in prod)
            for i in suspicious_idx:
                top_rules = attribute_event(valid_normalized[i], rule_models,
                                            cosine_attributor, args.method,
                                            args.top_k)
                _append_alert(alerts, valid_events[i], valid_texts[i],
                              float(scores[i]), args.method, top_rules, rule_index)

    logger.info("Done — %d alerts / %d events processed (%d skipped, no command line)",
                len(alerts), len(events), skipped)

    out_lines = [json.dumps(a, ensure_ascii=False) for a in alerts]
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write("\n".join(out_lines) + "\n")
        logger.info("Alerts saved to %s", args.out)
    else:
        for line in out_lines:
            print(line)


if __name__ == "__main__":
    main()
