"""Small runtime Sigma matcher for live RED attribution.

This is intentionally narrower than pySigma: it evaluates the common Windows
Sigma detection shapes used by the demo rules directly against the raw ECS /
Winlog event. The live detector uses it as a precision layer after Stage 1:
if a Sigma rule truly fires on the event, that rule is promoted above the
cosine/SVM attribution guess.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from typing import Any

import yaml

from red.rule_metadata import normalize_title

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ExactSigmaMatch:
    rule: str
    filename: str
    relpath: str
    sigma_id: str
    title: str

    def to_alert_dict(self) -> dict:
        return {
            "rule": self.rule,
            "sigma_filename": self.filename,
            "sigma_id": self.sigma_id,
            "sigma_title": self.title,
        }


class SigmaExactMatcher:
    """Evaluate simple Sigma YAML detection blocks against one event."""

    def __init__(
        self,
        rules: list[dict[str, Any]],
        event_field_map: dict[str, list[str]] | None = None,
        search_fields: list[str] | None = None,
    ) -> None:
        self.rules = rules
        self.event_field_map = event_field_map or {}
        self.search_fields = search_fields or list(self.event_field_map)

    @classmethod
    def from_rules_dirs(
        cls,
        rules_dirs: list[str],
        event_field_map: dict[str, list[str]] | None = None,
        search_fields: list[str] | None = None,
    ) -> "SigmaExactMatcher":
        rules: list[dict[str, Any]] = []
        for rules_dir in rules_dirs:
            rules.extend(_load_rules_dir(rules_dir))
        logger.info("SigmaExactMatcher: loaded %d rules", len(rules))
        return cls(rules, event_field_map=event_field_map, search_fields=search_fields)

    def match_event(self, event: dict[str, Any]) -> list[ExactSigmaMatch]:
        matches: list[ExactSigmaMatch] = []
        for rule in self.rules:
            detection = rule.get("detection")
            if not isinstance(detection, dict):
                continue
            try:
                if self._match_detection(detection, event):
                    matches.append(
                        ExactSigmaMatch(
                            rule=rule["normalized"],
                            filename=rule["filename"],
                            relpath=rule["relpath"],
                            sigma_id=rule.get("id", ""),
                            title=rule["title"],
                        )
                    )
            except Exception as exc:
                logger.debug("Sigma exact skip %s: %s", rule.get("relpath"), exc)
        return matches

    def _match_detection(self, detection: dict[str, Any], event: dict[str, Any]) -> bool:
        group_results = {}
        for name, content in detection.items():
            if name == "condition":
                continue
            group_results[name] = self._match_selection(content, event)

        condition = detection.get("condition")
        if not condition:
            return any(group_results.values())
        if isinstance(condition, list):
            return any(self._eval_condition(str(item), group_results) for item in condition)
        return self._eval_condition(str(condition), group_results)

    def _match_selection(self, content: Any, event: dict[str, Any]) -> bool:
        if isinstance(content, dict):
            for field_spec, expected in content.items():
                if not self._match_field_spec(field_spec, expected, event):
                    return False
            return True

        if isinstance(content, list):
            if not content:
                return False
            return any(self._match_selection(item, event) for item in content)

        if isinstance(content, str):
            return self._match_keyword(content, event)

        return False

    def _match_field_spec(self, field_spec: str, expected: Any, event: dict[str, Any]) -> bool:
        if field_spec.lower() == "keywords":
            return self._match_keywords(expected, event)

        parts = field_spec.split("|")
        field = parts[0]
        modifiers = {part.lower() for part in parts[1:]}
        actual_values = self._field_values(event, field)
        if "exists" in modifiers:
            should_exist = bool(expected)
            return bool(actual_values) is should_exist
        if not actual_values:
            return False

        if isinstance(expected, list):
            if "all" in modifiers:
                return all(
                    self._match_one(actual_values, item, modifiers - {"all"})
                    for item in expected
                )
            return any(self._match_one(actual_values, item, modifiers) for item in expected)

        return self._match_one(actual_values, expected, modifiers)

    def _match_keywords(self, expected: Any, event: dict[str, Any]) -> bool:
        if isinstance(expected, list):
            return any(self._match_keyword(item, event) for item in expected)
        return self._match_keyword(expected, event)

    def _match_keyword(self, expected: Any, event: dict[str, Any]) -> bool:
        needle = _lower(expected)
        if not needle:
            return False
        return any(needle in _lower(value) for value in self._all_event_values(event))

    def _match_one(self, actual_values: list[str], expected: Any, modifiers: set[str]) -> bool:
        if isinstance(expected, dict):
            return False
        needle = _lower(expected)
        if not needle:
            return False

        for actual in actual_values:
            haystack = _lower(actual)
            if "contains" in modifiers or "windash" in modifiers:
                if needle in haystack:
                    return True
            elif "endswith" in modifiers:
                if haystack.endswith(needle):
                    return True
            elif "startswith" in modifiers:
                if haystack.startswith(needle):
                    return True
            elif "re" in modifiers or "regex" in modifiers:
                try:
                    if re.search(str(expected), str(actual), flags=re.IGNORECASE):
                        return True
                except re.error:
                    return False
            else:
                if haystack == needle:
                    return True
        return False

    def _field_values(self, event: dict[str, Any], sigma_field: str) -> list[str]:
        paths = list(self.event_field_map.get(sigma_field, []))
        paths.extend(_fallback_paths(sigma_field))

        values: list[str] = []
        seen = set()
        for path in paths:
            value = _get_dotted(event, path)
            for item in _flatten_strings(value):
                if item and item not in seen:
                    values.append(item)
                    seen.add(item)
        return values

    def _all_event_values(self, event: dict[str, Any]) -> list[str]:
        values: list[str] = []
        fields = self.search_fields or list(self.event_field_map)
        for field in fields:
            values.extend(self._field_values(event, field))
        if not values:
            values.extend(_flatten_strings(event))
        return values

    def _eval_condition(self, condition: str, group_results: dict[str, bool]) -> bool:
        expr = condition

        def repl_of(match: re.Match) -> str:
            quantifier = match.group(1).lower()
            pattern = match.group(2)
            if pattern.endswith("*"):
                prefix = pattern[:-1]
                values = [value for key, value in group_results.items() if key.startswith(prefix)]
            else:
                values = [group_results.get(pattern, False)]
            result = all(values) if quantifier == "all" else any(values)
            return str(bool(result))

        expr = re.sub(r"\b(all|1)\s+of\s+([A-Za-z0-9_]+\*?)", repl_of, expr, flags=re.I)
        for name in sorted(group_results, key=len, reverse=True):
            expr = re.sub(rf"\b{re.escape(name)}\b", str(bool(group_results[name])), expr)
        if re.search(r"[^A-Za-z0-9_()\s]", expr):
            logger.debug("Unsupported Sigma condition syntax after rewrite: %s", condition)
            return False
        try:
            return bool(eval(expr, {"__builtins__": {}}, {}))
        except Exception:
            logger.debug("Could not evaluate Sigma condition: %s -> %s", condition, expr)
            return False


def _load_rules_dir(rules_dir: str) -> list[dict[str, Any]]:
    rules_dir = os.path.expanduser(rules_dir)
    rules: list[dict[str, Any]] = []
    if not os.path.isdir(rules_dir):
        logger.warning("SigmaExactMatcher: rules_dir not found: %s", rules_dir)
        return rules

    for root, _, files in os.walk(rules_dir):
        for filename in sorted(files):
            if not filename.endswith((".yml", ".yaml")):
                continue
            path = os.path.join(root, filename)
            for doc in _load_yaml_docs(path):
                title = doc.get("title")
                detection = doc.get("detection")
                if not title or not isinstance(detection, dict):
                    continue
                relpath = os.path.relpath(path, rules_dir)
                rules.append(
                    {
                        "filename": filename,
                        "relpath": relpath,
                        "id": str(doc.get("id", "")),
                        "title": str(title),
                        "normalized": normalize_title(str(title)),
                        "detection": detection,
                    }
                )
    return rules


def _load_yaml_docs(path: str) -> list[dict[str, Any]]:
    docs: list[dict[str, Any]] = []
    try:
        with open(path, encoding="utf-8") as handle:
            loaded = list(yaml.safe_load_all(handle))
    except Exception as exc:
        logger.debug("Skip Sigma YAML %s: %s", path, exc)
        return docs

    for item in loaded:
        if isinstance(item, dict):
            docs.append(item)
        elif isinstance(item, list):
            docs.extend(entry for entry in item if isinstance(entry, dict))
    return docs


def _fallback_paths(sigma_field: str) -> list[str]:
    return [
        sigma_field,
        f"winlog.event_data.{sigma_field}",
        f"Details.{sigma_field}",
        f"ExtraFieldInfo.{sigma_field}",
    ]


def _get_dotted(obj: Any, path: str) -> Any:
    cur = obj
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _flatten_strings(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (int, float, bool)):
        return [str(value)]
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            out.extend(_flatten_strings(item))
        return out
    if isinstance(value, dict):
        out: list[str] = []
        for item in value.values():
            out.extend(_flatten_strings(item))
        return out
    return [str(value)]


def _lower(value: Any) -> str:
    return str(value).lower()
