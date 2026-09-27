"""Data loading for benign samples, Sigma rules, and match/evasion events.

Handles three data sources:
  - Benign samples: plain text files (one sample per line) or JSONL
  - Sigma rules: YAML files with detection filters parsed via luqum
  - Events: JSON files for matches and evasions organized per-rule

The central flow:
  1. load_benign_samples()         → list[str]
  2. load_rule_set()               → dict[rule_name → RuleData]
  3. extract_commandlines(events)  → list[str]
  4. extract_filter_values(rules)  → list[str]
"""

import os
import re
import json
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional

import yaml
import numpy as np

logger = logging.getLogger(__name__)


def resolve_event_paths(
    sigma_fields: List[str],
    event_field_map: Optional[Dict[str, List[str]]] = None,
) -> List[str]:
    """Translate Sigma field names → JSON paths to try when reading event dicts.

    Sigma YAML dùng tên native (CommandLine, ScriptBlockText, TargetObject, ...).
    Event JSON (Hayabusa/ECS) dùng tên dotted (winlog.event_data.CommandLine, ...).
    Config khai báo `search_fields` (Sigma) + `event_field_map` (Sigma → list JSON paths).
    Hàm này dùng map để resolve, fallback về tên gốc nếu không có entry.
    """
    if not event_field_map:
        return list(sigma_fields)
    paths: List[str] = []
    for sf in sigma_fields:
        mapped = event_field_map.get(sf)
        if mapped:
            paths.extend(mapped)
        else:
            paths.append(sf)
    return paths


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------

@dataclass
class RuleData:
    """Holds data for a single Sigma rule."""
    name: str
    filters: list = field(default_factory=list)       # AMIDES filter strings from YAML
    matches: list = field(default_factory=list)        # match event dicts
    evasions: list = field(default_factory=list)       # evasion event dicts
    sigma_values: list = field(default_factory=list)   # values extracted from raw Sigma detection


# ---------------------------------------------------------------------------
# Benign sample loading
# ---------------------------------------------------------------------------

def _extract_field_from_dict(obj: dict, field: Optional[str]) -> Optional[str]:
    """Extract a value from a nested dict using a dot-separated field path.

    If field is None, falls back to trying common CommandLine paths.
    """
    if field:
        val = obj
        for part in field.split("."):
            if isinstance(val, dict):
                val = val.get(part)
            else:
                return None
        return str(val).strip() if val else None

    # Fallback: try common paths when no field specified
    candidates = [
        lambda o: o["process"]["command_line"],
        lambda o: o["winlog"]["event_data"]["CommandLine"],
        lambda o: o["winlog"]["event_data"]["ScriptBlockText"],
        lambda o: o["CommandLine"],
        lambda o: o["ScriptBlockText"],
        lambda o: o["command_line"],
        lambda o: o["Details"]["Cmdline"],
        lambda o: o["Details"]["ScriptBlockText"],
        lambda o: o["Details"]["ScriptBlock"],
    ]
    for fn in candidates:
        try:
            val = fn(obj)
            if isinstance(val, str) and val.strip():
                return val.strip()
        except (KeyError, TypeError):
            pass
    return None


def _iter_benign_file(path: str, field: Optional[str] = None):
    """Yield CommandLine strings from a file, auto-detecting format.

    Supported formats:
      - Plain text (.txt or no extension): one value per line
      - JSONL / NDJSON (.jsonl, .ndjson): one JSON object per line
      - JSON (.json): array of objects or single object
      - CSV (.csv): header row required; uses `field` to find column

    Parameters
    ----------
    path : str
        Path to benign data file.
    field : str, optional
        Dot-separated field path to extract from JSON/CSV objects.
        e.g. "process.command_line", "winlog.event_data.ScriptBlockText"
        If None, falls back to trying common CommandLine paths.
    """
    import csv
    ext = os.path.splitext(path)[1].lower()

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        if ext in (".jsonl", ".ndjson"):
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    val = _extract_field_from_dict(obj, field) if isinstance(obj, dict) else None
                    if val:
                        yield val
                except json.JSONDecodeError:
                    pass

        elif ext == ".json":
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                return
            items = data if isinstance(data, list) else [data]
            for obj in items:
                if isinstance(obj, dict):
                    val = _extract_field_from_dict(obj, field)
                    if val:
                        yield val

        elif ext == ".csv":
            reader = csv.DictReader(f)
            col = None
            # Determine target column from field or by guessing
            if field:
                col_key = field.split(".")[-1].lower()
            else:
                col_key = None
            for row in reader:
                if col is None:
                    for c in row:
                        c_low = c.lower()
                        if col_key and c_low == col_key:
                            col = c
                            break
                        if not col_key and c_low in ("commandline", "command_line", "cmdline",
                                                      "scriptblocktext", "targetobject", "url"):
                            col = c
                            break
                    if col is None:
                        logger.warning("No matching column for field '%s' in %s", field, path)
                        return
                val = row.get(col, "").strip()
                if val:
                    yield val

        else:  # plain text
            for line in f:
                line = line.rstrip("\n")
                if line:
                    yield line


def load_benign_samples(path: str, field: Optional[str] = None) -> List[str]:
    """Load benign samples from a file (auto-detects format).

    Parameters
    ----------
    path : str
        Path to benign data file.
    field : str, optional
        Dot-separated field path to extract (e.g. "process.command_line").
    """
    samples = list(_iter_benign_file(path, field))
    logger.info("Loaded %d benign samples from %s", len(samples), path)
    return samples


def benign_samples_iter(path: str, field: Optional[str] = None, max_samples: Optional[int] = None):
    """Yield benign samples one at a time (memory efficient, auto-detects format).

    Parameters
    ----------
    max_samples : int, optional
        Cap the number of samples yielded. Useful when benign data is very large
        (e.g., 1.5M URLs) and would cause OOM in SVM training.
    """
    count = 0
    for sample in _iter_benign_file(path, field):
        yield sample
        count += 1
        if max_samples and count >= max_samples:
            break


def count_benign_samples(path: str, field: Optional[str] = None, max_samples: Optional[int] = None) -> int:
    """Count benign samples without loading all into memory."""
    count = sum(1 for _ in _iter_benign_file(path, field))
    if max_samples:
        return min(count, max_samples)
    return count


# ---------------------------------------------------------------------------
# Command-line extraction from event dicts
# ---------------------------------------------------------------------------

def extract_commandline(event: dict, search_fields: Optional[List[str]] = None) -> Optional[str]:
    """Extract a value from an event dict using search_fields or common fallback paths.

    Parameters
    ----------
    event : dict
        Event dictionary.
    search_fields : list of str, optional
        Dot-separated field paths to try (e.g. ["winlog.event_data.TargetObject"]).
        Falls back to common CommandLine paths if None.
    """
    if search_fields:
        for field in search_fields:
            val = _extract_field_from_dict(event, field)
            if val:
                return val
        return None

    # Default fallback for process_creation
    try:
        return event["process"]["command_line"]
    except (KeyError, TypeError):
        pass
    try:
        return event["winlog"]["event_data"]["CommandLine"]
    except (KeyError, TypeError):
        pass
    return None


def extract_commandlines(events: List[dict], search_fields: Optional[List[str]] = None) -> List[str]:
    """Extract field values from a list of event dicts using search_fields."""
    results = []
    for event in events:
        val = extract_commandline(event, search_fields)
        if val is not None:
            results.append(val)
    return results


# ---------------------------------------------------------------------------
# Sigma rule filter value extraction (using luqum)
# ---------------------------------------------------------------------------

def extract_filter_values(filter_str: str, search_fields: List[str]) -> List[str]:
    """Parse a Sigma rule filter string and extract values for given fields.

    Uses luqum to parse the Lucene-like filter expression and visits the
    AST to extract SearchField values matching the requested field names.

    Parameters
    ----------
    filter_str : str
        Lucene-like filter expression from the Sigma rule YAML.
    search_fields : list of str
        Field names to extract values for, e.g. ["process.command_line"].

    Returns
    -------
    list of str
        Extracted field values.
    """
    try:
        from luqum.parser import parser as luqum_parser
        from luqum.visitor import TreeVisitor
        from luqum.tree import NoneItem

        tree = luqum_parser.parse(filter_str)
        visitor = _FieldValueVisitor(search_fields)
        visitor.visit(tree)
        return visitor.values
    except Exception as e:
        logger.warning("Failed to parse filter '%s': %s", filter_str[:80], e)
        return []


class _FieldValueVisitor:
    """luqum TreeVisitor that extracts values for specified search fields."""

    def __init__(self, fields: List[str]):
        from luqum.visitor import TreeVisitor
        self._visitor_cls = TreeVisitor
        self._fields = fields
        self.values = []
        self._inner = _InnerVisitor(fields, self.values)

    def visit(self, tree):
        self._inner.visit(tree)


class _InnerVisitor:
    """Actual visitor implementation using luqum's TreeVisitor."""

    def __init__(self, fields, values_list):
        from luqum.visitor import TreeVisitor
        from luqum.tree import NoneItem

        self._fields = fields
        self._values = values_list
        self._NoneItem = NoneItem

        class Visitor(TreeVisitor):
            def __init__(inner_self):
                super().__init__(track_parents=False)

            def visit_search_field(inner_self, node, context):
                match = False
                for fld in fields:
                    if node.name == fld or node.name.startswith(fld + "|"):
                        match = True
                if match:
                    context = inner_self.child_context(node, NoneItem(), context)
                    context[node.name.split("|")[0]] = True
                yield from inner_self.generic_visit(node, context)

            def visit_phrase(inner_self, node, context):
                for fld in fields:
                    if context.get(fld, False):
                        val = node.value
                        if val.startswith('"') and val.endswith('"'):
                            val = val[1:-1]
                        values_list.append(val)
                yield from inner_self.generic_visit(node, context)

            def visit_not(inner_self, node, context):
                yield NoneItem()

        self._visitor = Visitor()

    def visit(self, tree):
        self._visitor.visit(tree)


# ---------------------------------------------------------------------------
# Rule set loading
# ---------------------------------------------------------------------------

MATCH_REGEX = re.compile(r"^.+_Match_\d+\.json$")
EVASION_REGEX = re.compile(r"^.+_Evasion_.+_\d+\.json$")


def load_rule_set(events_dir: str, rules_dir: str,
                  evasions_dir: Optional[str] = None) -> Dict[str, RuleData]:
    """Load a complete rule set from events and rules directories.

    Parameters
    ----------
    events_dir : str
        Path to directory containing per-rule subdirectories with match JSON files.
    rules_dir : str
        Path to directory containing per-rule YAML files.
    evasions_dir : str, optional
        Separate directory for evasion JSON files (mirrors events_dir structure).
        If None, evasions are loaded from events_dir (legacy AMIDES layout).

    Returns
    -------
    dict of str → RuleData
        Mapping from rule name to its data.
    """
    # Pre-build a map: stem → full path for all YAMLs under rules_dir (recursive)
    yaml_map: Dict[str, str] = {}
    if os.path.isdir(rules_dir):
        for dirpath, _, filenames in os.walk(rules_dir):
            for fname in filenames:
                if fname.endswith(".yml"):
                    stem = fname[:-4]
                    yaml_map[stem] = os.path.join(dirpath, fname)

    rule_set = {}

    events_dir_exists = os.path.isdir(events_dir) if events_dir else False

    if events_dir_exists:
        # Normal mode: discover rules from events_dir subdirectories
        rule_names = sorted(
            d for d in os.listdir(events_dir)
            if os.path.isdir(os.path.join(events_dir, d))
        )
        for rule_dir_name in rule_names:
            rule_events_path = os.path.join(events_dir, rule_dir_name)
            rule_yaml_path = yaml_map.get(rule_dir_name, os.path.join(rules_dir, f"{rule_dir_name}.yml"))
            rule_evasions_path = (
                os.path.join(evasions_dir, rule_dir_name)
                if evasions_dir and os.path.isdir(os.path.join(evasions_dir, rule_dir_name))
                else None
            )
            try:
                rule_data = _load_single_rule(
                    rule_dir_name, rule_events_path, rule_yaml_path,
                    evasions_path=rule_evasions_path,
                )
                if rule_data is not None:
                    rule_set[rule_data.name] = rule_data
            except Exception as e:
                logger.warning("Skipping rule %s: %s", rule_dir_name, e)
        logger.info("Loaded %d rules from %s", len(rule_set), events_dir)
    else:
        # rule_filters-only mode: discover rules from rules_dir YAML files
        if not os.path.isdir(rules_dir):
            raise FileNotFoundError(
                f"Neither events_dir ({events_dir}) nor rules_dir ({rules_dir}) found"
            )
        logger.info("events_dir not found — loading rules from rules_dir only: %s", rules_dir)
        for rule_dir_name, rule_yaml_path in sorted(yaml_map.items()):
            try:
                rule_data = _load_single_rule_from_yaml(rule_dir_name, rule_yaml_path)
                if rule_data is not None:
                    rule_set[rule_data.name] = rule_data
            except Exception as e:
                logger.warning("Skipping rule %s: %s", rule_dir_name, e)
        logger.info("Loaded %d rules from %s", len(rule_set), rules_dir)

    return rule_set


def _load_json_events(path: str, rule_data: "RuleData"):
    """Load match and evasion JSON files from a directory into rule_data."""
    if not path or not os.path.isdir(path):
        return
    for fname in sorted(os.listdir(path)):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(path, fname)
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                event = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.debug("Skipping %s: %s", fpath, e)
            continue
        if MATCH_REGEX.match(fname):
            if isinstance(event, dict):
                rule_data.matches.append(event)
        elif EVASION_REGEX.match(fname):
            if isinstance(event, dict):
                rule_data.evasions.append(event)


def _load_single_rule(
    dir_name: str, events_path: str, rule_yaml_path: str,
    evasions_path: Optional[str] = None,
) -> Optional[RuleData]:
    """Load matches, evasions, and rule filter for a single rule."""
    rule_data = RuleData(name=dir_name)

    # Load matches from events_path (always)
    _load_json_events(events_path, rule_data)

    # Load evasions from separate dir if provided, else from events_path
    if evasions_path:
        _load_json_events(evasions_path, rule_data)
    # (if evasions_path is None, evasions from events_path already loaded above)

    # Load rule filter from YAML
    if os.path.isfile(rule_yaml_path):
        try:
            with open(rule_yaml_path, "r", encoding="utf-8") as f:
                rules_yaml = list(yaml.safe_load_all(f))
            # Flatten if nested list
            rules_list = []
            for item in rules_yaml:
                if isinstance(item, list):
                    rules_list.extend(item)
                elif isinstance(item, dict):
                    rules_list.append(item)

            for rule in rules_list:
                if isinstance(rule, dict):
                    if "filter" in rule:
                        rule_data.filters.append(rule["filter"])
                    if "detection" in rule:
                        rule_data.sigma_values.append(rule["detection"])
                    if "pre_detector" in rule:
                        title = rule["pre_detector"].get("title")
                        if title:
                            rule_data.name = title
        except Exception as e:
            logger.debug("Could not load rule YAML %s: %s", rule_yaml_path, e)

    return rule_data


def extract_sigma_detection_values(detection: dict, search_fields) -> list:
    """Public wrapper: extract values from a Sigma detection block for given fields."""
    return _extract_sigma_detection_values(detection, set(search_fields))


def _extract_sigma_detection_values(detection: dict, search_fields: set) -> list:
    """Extract string values from a raw Sigma detection block for matching fields.

    Fix v2 (2026-05-20) — broader extraction để cover thêm rule:
      - Field name match case-INSENSITIVE (`parent_image` == `ParentImage`)
      - `keywords` section (list of plain strings, không có field constraint) → luôn extract
      - List of strings ở top-level (vd rule chỉ check 1 list không có field) → extract
      - Plain string value ở top-level → extract
      - Recursive handle nested groups
    Skip key 'condition' (logic combinator, không phải value).
    """
    values = []
    if not isinstance(detection, dict):
        return values

    # Normalize cho lookup: case-insensitive + bỏ underscore
    # → 'parent_image' / 'ParentImage' / 'PARENT_IMAGE' đều match
    def _norm_field(f: str) -> str:
        return f.lower().replace("_", "")

    search_fields_norm = {_norm_field(f) for f in search_fields}

    for key, content in detection.items():
        if key == "condition":
            continue

        # SPECIAL CASE: 'keywords' section — Sigma convention cho list of strings
        # không có field constraint, áp dụng cho mọi field. Luôn extract.
        is_keywords = key.lower() == "keywords"

        if isinstance(content, dict):
            # Named group: {field_spec: value, ...}
            for field_spec, field_value in content.items():
                field_name = field_spec.split("|")[0]
                # Match exact OR case-insensitive (ignore underscore + case)
                if _norm_field(field_name) not in search_fields_norm:
                    continue
                if isinstance(field_value, str):
                    values.append(field_value)
                elif isinstance(field_value, list):
                    values.extend(v for v in field_value if isinstance(v, str))
                elif isinstance(field_value, dict):
                    # Nested dict (rare): recurse
                    values.extend(
                        _extract_sigma_detection_values(field_value, search_fields)
                    )
        elif isinstance(content, list):
            # List có thể là:
            #  - sub-groups (dict items) → recurse
            #  - keywords list (plain strings) → extract nếu key=='keywords' hoặc list toàn string
            all_strings = all(isinstance(it, str) for it in content) if content else False
            for item in content:
                if isinstance(item, dict):
                    values.extend(_extract_sigma_detection_values(item, search_fields))
                elif isinstance(item, str) and (is_keywords or all_strings):
                    values.append(item)
        elif isinstance(content, str) and is_keywords:
            # 'keywords: "single_string"' edge case
            values.append(content)

    return values


def _load_single_rule_from_yaml(dir_name: str, rule_yaml_path: str) -> Optional[RuleData]:
    """Load rule filter only (no match events) — used when events_dir is absent."""
    rule_data = RuleData(name=dir_name)
    if not os.path.isfile(rule_yaml_path):
        return None
    try:
        with open(rule_yaml_path, "r", encoding="utf-8") as f:
            rules_yaml = list(yaml.safe_load_all(f))
        rules_list = []
        for item in rules_yaml:
            if isinstance(item, list):
                rules_list.extend(item)
            elif isinstance(item, dict):
                rules_list.append(item)
        for rule in rules_list:
            if isinstance(rule, dict):
                if "filter" in rule:
                    rule_data.filters.append(rule["filter"])
                if "pre_detector" in rule:
                    title = rule["pre_detector"].get("title")
                    if title:
                        rule_data.name = title
                # Store raw Sigma detection block for later field extraction
                if "detection" in rule:
                    rule_data.sigma_values.append(rule["detection"])  # stored as dict, extracted later
                if "title" in rule:
                    rule_data.name = rule["title"]
    except Exception as e:
        logger.debug("Could not load rule YAML %s: %s", rule_yaml_path, e)
    return rule_data if (rule_data.filters or rule_data.sigma_values) else None


# ---------------------------------------------------------------------------
# High-level data preparation helpers
# ---------------------------------------------------------------------------

def get_all_filter_values(
    rule_set: Dict[str, RuleData],
    search_fields: List[str],
) -> List[str]:
    """Extract all filter field values across the entire rule set.

    Handles two formats:
    - AMIDES filter strings (parsed via Luqum)
    - Raw Sigma detection blocks (extracted by field name matching)
    """
    values = []
    search_fields_set = set(search_fields)
    for rule_data in rule_set.values():
        # AMIDES-format filter strings
        for filt in rule_data.filters:
            vals = extract_filter_values(filt, search_fields)
            values.extend(vals)
        # Raw Sigma detection dicts
        for detection in rule_data.sigma_values:
            if isinstance(detection, dict):
                vals = _extract_sigma_detection_values(detection, search_fields_set)
                values.extend(vals)
    logger.info("Extracted %d filter values for fields %s", len(values), search_fields)
    return values


def get_all_yaml_filter_values(rules_dir: str, search_fields: List[str]) -> List[str]:
    """Extract filter/detection values from ALL YAML files under rules_dir (recursive).

    Used when rules_dir filenames don't match events_dir subdir names
    (e.g., powershell: Hayabusa titles vs Sigma file stems).
    """
    values = []
    search_fields_set = set(search_fields)
    if not os.path.isdir(rules_dir):
        return values
    for dirpath, _, filenames in os.walk(rules_dir):
        for fname in filenames:
            if not fname.endswith(".yml"):
                continue
            fpath = os.path.join(dirpath, fname)
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    docs = list(yaml.safe_load_all(f))
                for doc in docs:
                    if not isinstance(doc, dict):
                        continue
                    if "filter" in doc:
                        vals = extract_filter_values(doc["filter"], search_fields)
                        values.extend(vals)
                    if "detection" in doc:
                        vals = _extract_sigma_detection_values(doc["detection"], search_fields_set)
                        values.extend(vals)
            except Exception as e:
                logger.debug("Skipping %s: %s", fpath, e)
    logger.info("Extracted %d yaml filter values from %s", len(values), rules_dir)
    return values


def get_all_matches(rule_set: Dict[str, RuleData]) -> List[dict]:
    """Collect all match events across the entire rule set."""
    matches = []
    for rd in rule_set.values():
        matches.extend(rd.matches)
    return matches


def get_all_evasions(rule_set: Dict[str, RuleData]) -> List[dict]:
    """Collect all evasion events across the entire rule set."""
    evasions = []
    for rd in rule_set.values():
        evasions.extend(rd.evasions)
    return evasions


def create_labels(num_benign: int, num_malicious: int) -> np.ndarray:
    """Create a labels array: 0 for benign, 1 for malicious."""
    return np.array([0] * num_benign + [1] * num_malicious)
