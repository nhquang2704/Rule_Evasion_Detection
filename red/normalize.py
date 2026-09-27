"""Text normalization pipeline.

Normalizes raw samples (command lines, registry keys, URLs, etc.) through:
  1. Filter dummy characters (" ^ ` ')
  2. Lowercase
  3. Tokenize giữ cả PATH context (\\ / : . -) — token có path không bị split
     → "C:\\Windows\\sshd.exe" thành "c_windows_sshd_exe" thay vì ['c','windows','sshd','exe']
  4. Remove hex/numeric tokens longer than max_num_len
  5. Remove string tokens longer than max_str_len (bumped 30→60 cho path).
     Nếu merged token > max_str_len → FALLBACK SPLIT lại trên separator thành
     sub-tokens (đảm bảo registry path dài với SID vẫn sinh token, không bị skip).
  6. Sort tokens alphabetically, join with comma

Fix v2 (2026-05-20): mở rộng tokenizer giữ path/punct → RED ML có thể match
Sigma rule check `ParentImage|endswith: '\\sshd.exe'` (trước đó miss vì \\w+ tách path).
Fix v3 (2026-05-24): fallback split khi merged token > max_str_len → registry path
dài (HKU\\S-1-5-21-...\\Run\\xxx 124 chars) không còn bị filter empty.
Backward-compat: path ngắn (proc/ps) vẫn merge nguyên path → không cần retrain proc/ps.
"""

import re
from typing import List


class Normalizer:
    """Normalize a single text sample into a sorted, comma-separated token string."""

    def __init__(self, max_num_len: int = 3, max_str_len: int = 60):
        self._dummy_re = re.compile(r'["\^`\']')
        # Mở rộng tokenizer: word chars + path separators (\ /) + colon + dot + dash
        # → bắt nguyên path "C:\Windows\sshd.exe" thành 1 token
        self._word_re = re.compile(r"([\w\\/:.\-]+)")
        # Pattern để strip dấu phụ KHỎI token (giữ word chars + underscore)
        self._sep_re = re.compile(r"[\\/:.\-]+")
        # Matches hex (0x...) or pure hex-digit strings longer than max_num_len
        self._num_re = re.compile(
            r"^(?:0x)?[0-9a-f]{" + str(max_num_len + 1) + r",}$"
        )
        self._max_str_len = max_str_len

    def normalize(self, sample: str) -> str:
        """Normalize a raw text sample.

        Parameters
        ----------
        sample : str
            Raw text (command line, URL, registry key, etc.).

        Returns
        -------
        str
            Comma-separated sorted tokens, or empty string if nothing remains.
        """
        if not isinstance(sample, str):
            sample = str(sample)

        # 1. Filter dummy characters
        text = self._dummy_re.sub("", sample)
        # 2. Lowercase
        text = text.lower()
        # 3. Tokenize giữ path context
        raw_tokens = self._word_re.findall(text)
        # 4+5 combined: cho mỗi raw token, thử merge (path → 1 token) — nếu merged
        # token quá dài thì fallback split lại trên separator để giữ các segment.
        out_tokens: List[str] = []
        for raw in raw_tokens:
            merged = self._sep_re.sub("_", raw).strip("_")
            if not merged:
                continue
            if self._num_re.match(merged):
                continue
            if len(merged) <= self._max_str_len:
                out_tokens.append(merged)
            else:
                # Fallback split: registry path 124 chars với SID dài → tách
                # thành sub-tokens trên separator, drop hex/num + sub-token quá dài.
                for sub in self._sep_re.split(raw):
                    if not sub:
                        continue
                    if self._num_re.match(sub):
                        continue
                    if len(sub) <= self._max_str_len:
                        out_tokens.append(sub)
        # 6. Sort and join
        out_tokens.sort()
        return ",".join(out_tokens)


def normalize_samples(samples: List[str]) -> List[str]:
    """Normalize a list of samples, dropping any that become empty.

    Parameters
    ----------
    samples : list of str
        Raw text samples.

    Returns
    -------
    list of str
        Non-empty normalized samples.
    """
    normalizer = Normalizer()
    results = []
    for s in samples:
        n = normalizer.normalize(s)
        if n:
            results.append(n)
    return results
