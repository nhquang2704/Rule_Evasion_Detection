"""SigmaRuleIndex — map internal RED key → Sigma rule metadata.

Khi RED Stage 2 train, key dict `rule_models` được normalize từ field `title:`
của Sigma rule YAML. Module này build lookup table:

    internal_name (RED key)  →  filename + sigma_id (UUID) + title

Cho phép alert có metadata để SOC analyst trace ngược về file Sigma gốc và
mở trong Kibana Security/Rules.

Usage:
    from red.rule_metadata import SigmaRuleIndex

    index = SigmaRuleIndex.from_rules_dir("~/data/sigma/rules/windows/powershell")
    meta = index.lookup("suspicious_powershell_invocations_-_specific")
    # → {"filename": "posh_ps_susp_invocation_specific.yml",
    #    "sigma_id": "ae7fbf8e-f3cb-49fd-8db4-5f3bed522c71",
    #    "title": "Suspicious PowerShell Invocations - Specific"}
"""

import os
import re
import logging
from dataclasses import dataclass
from typing import Optional

import yaml

logger = logging.getLogger(__name__)


def normalize_title(title: str) -> str:
    """Chuẩn hóa title sang snake_case (khớp với Hayabusa subdir name + RED key).

    Hayabusa convention (verified với rule_models keys trong RED model):
    - lowercase
    - ' - ' giữa từ → '_'
    - '.', '-' (intra-word, vd "In-Memory", "Reflection.Assembly") → '_'
    - whitespace → '_'
    - strip non-alphanum
    - collapse multi '_'
    """
    s = title.lower()
    # ' - ' (whitespace dash whitespace) → space
    s = re.sub(r"\s+-\s+", " ", s)
    # Replace intra-word punctuation (- . / : ;) → '_'
    s = re.sub(r"[-./:;]", "_", s)
    # Whitespace → _
    s = re.sub(r"\s+", "_", s)
    # Strip non-alphanum + _
    s = re.sub(r"[^a-z0-9_]", "", s)
    # Collapse multi _
    s = re.sub(r"_+", "_", s)
    return s.strip("_")


@dataclass
class SigmaRuleMeta:
    filename: str        # vd "posh_ps_susp_download.yml"
    relpath: str         # relative path dưới rules_dir
    sigma_id: str        # UUID
    title: str           # Human-readable title
    normalized: str      # internal key (= RED rule_models key)
    description: str = ""         # Sigma rule description
    level: str = ""               # informational/low/medium/high/critical
    tags: list = None             # MITRE ATT&CK tags, e.g. ["attack.t1070.001"]
    detection_yaml: str = ""      # raw YAML content — for AI Agent

    def __post_init__(self):
        if self.tags is None:
            self.tags = []

    def to_dict(self) -> dict:
        return {
            "filename": self.filename,
            "sigma_id": self.sigma_id,
            "title": self.title,
            "description": self.description,
            "level": self.level,
            "tags": self.tags,
            "detection_yaml": self.detection_yaml,
        }


class SigmaRuleIndex:
    """Cache trong RAM toàn bộ Sigma rules dưới rules_dir, hỗ trợ lookup theo
    normalized key.

    Build 1 lần khi script start, reuse cho mọi alert.
    """

    def __init__(self) -> None:
        self._by_normalized: dict[str, SigmaRuleMeta] = {}
        self._loaded_dirs: list[str] = []

    @classmethod
    def from_rules_dir(cls, rules_dir: str) -> "SigmaRuleIndex":
        idx = cls()
        idx.load_dir(rules_dir)
        return idx

    @classmethod
    def from_rules_dirs(cls, rules_dirs: list[str]) -> "SigmaRuleIndex":
        idx = cls()
        for d in rules_dirs:
            idx.load_dir(d)
        return idx

    def load_dir(self, rules_dir: str) -> int:
        """Scan rules_dir, parse mọi .yml file, populate index.

        Returns: số rule load được.
        """
        rules_dir = os.path.expanduser(rules_dir)
        if not os.path.isdir(rules_dir):
            logger.warning("SigmaRuleIndex: rules_dir không tồn tại: %s", rules_dir)
            return 0

        count = 0
        for root, _, files in os.walk(rules_dir):
            for f in files:
                if not f.endswith((".yml", ".yaml")):
                    continue
                full_path = os.path.join(root, f)
                try:
                    with open(full_path, encoding="utf-8") as fh:
                        raw_content = fh.read()
                    rule = yaml.safe_load(raw_content)
                    if not isinstance(rule, dict):
                        continue
                    title = rule.get("title")
                    sigma_id = rule.get("id", "")
                    if not title:
                        continue
                    normalized = normalize_title(title)
                    relpath = os.path.relpath(full_path, rules_dir)
                    description = rule.get("description", "")
                    level = rule.get("level", "")
                    raw_tags = rule.get("tags", [])
                    tags = [str(t) for t in raw_tags] if isinstance(raw_tags, list) else []
                    meta = SigmaRuleMeta(
                        filename=f,
                        relpath=relpath,
                        sigma_id=str(sigma_id),
                        title=title,
                        normalized=normalized,
                        description=description,
                        level=level,
                        tags=tags,
                        detection_yaml=raw_content,
                    )
                    # Có thể collide nếu 2 rule cùng title → giữ file đầu, log warning
                    if normalized in self._by_normalized:
                        existing = self._by_normalized[normalized]
                        if existing.filename != f:
                            logger.debug(
                                "Title collision: %s (existing=%s, new=%s) — giữ existing",
                                normalized, existing.filename, f,
                            )
                        continue
                    self._by_normalized[normalized] = meta
                    count += 1
                except Exception as e:
                    logger.debug("Skip %s: %s", full_path, e)

        self._loaded_dirs.append(rules_dir)
        logger.info("SigmaRuleIndex: loaded %d rules from %s (total %d)",
                    count, rules_dir, len(self._by_normalized))
        return count

    def lookup(self, internal_name: str) -> Optional[SigmaRuleMeta]:
        """Tra metadata theo internal_name (= key trong RED rule_models).

        Fallback chain:
          1. Exact match
          2. Variant '-' / '_' (legacy)
          3. PREFIX match — RED key có thể bị truncate ở 60 chars
        """
        if internal_name in self._by_normalized:
            return self._by_normalized[internal_name]

        # Variant
        variants = [
            internal_name.replace("_-_", "_"),
            internal_name.replace("-", ""),
        ]
        for v in variants:
            if v in self._by_normalized:
                return self._by_normalized[v]

        # Prefix match — RED có thể truncate key ở ~60 chars
        # Chỉ apply nếu internal_name đủ dài (>= 30 chars) để tránh false match
        if len(internal_name) >= 30:
            candidates = [
                norm for norm in self._by_normalized
                if norm.startswith(internal_name)
            ]
            if len(candidates) == 1:
                return self._by_normalized[candidates[0]]
            if len(candidates) > 1:
                # Multiple matches — chọn shortest (= closest to RED key length)
                best = min(candidates, key=len)
                logger.debug("Prefix match for %s → %d candidates, chose %s",
                             internal_name, len(candidates), best)
                return self._by_normalized[best]

        return None

    def lookup_dict(self, internal_name: str) -> dict:
        """Lookup, trả về dict (rỗng nếu không match) để inject thẳng vào alert."""
        meta = self.lookup(internal_name)
        return meta.to_dict() if meta else {
            "filename": "(not_found_in_rules_dir)",
            "sigma_id": "",
            "title": internal_name,
        }

    def __len__(self) -> int:
        return len(self._by_normalized)

    def __contains__(self, internal_name: str) -> bool:
        return self.lookup(internal_name) is not None
