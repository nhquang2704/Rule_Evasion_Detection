# Rule Evasion Detection (RED)

RED là hệ thống phát hiện hành vi né tránh luật Sigma trên log Windows/Linux và hỗ trợ điều tra alert bằng AI Agent SOC Triage.

Branch này được đóng gói theo hướng **runtime demo thực tế**: có code chạy live, model đã train, Sigma rule catalog, AI Agent, và bộ Velociraptor phục vụ forensic thật trong lab. Các script train/evaluate, report nghiên cứu, payload demo và dataset thô đã được loại khỏi bản nộp này để repo gọn hơn.

## Tổng Quan

RED xử lý log từ Elasticsearch theo pipeline nhiều lớp:

1. Stage 1 - ML Misuse Detection  
   Phân loại event benign/suspicious bằng model ML đã train trên đặc trưng text như command line, ScriptBlockText, registry path.

2. Stage 2 - Rule Attribution  
   Xếp hạng Sigma rule có khả năng bị né bằng cosine TF-IDF và metadata Sigma.

3. Stage 2 Live - Sigma Logic + Decode  
   Với alert suspicious, hệ thống chạy Sigma exact matching, decode payload obfuscation như base64/hex/charcode/gzip, rồi xác định:
   - `red.evasion_technique`: rule/kỹ thuật né bị kích hoạt.
   - `red.evaded_rule`: rule/ý đồ thật có thể đã bị né.
   - `red.confidence`: `high`, `medium`, `low`, hoặc `unknown`.

4. AI Agent SOC Triage  
   Agent đọc alert RED, điều tra thêm bằng Elasticsearch/Velociraptor, map MITRE, đề xuất response và ghi báo cáo tiếng Việt vào Elasticsearch.

## Thành Phần Chính

| Thành phần | Vai trò |
|---|---|
| `red/` | Core engine dùng chung cho Windows và Linux: normalize, load model, attribution, Sigma exact, Stage 2 live. |
| `scripts/detect_live.py` | Daemon Windows: poll Elasticsearch, chạy Stage 1/2, ghi alert về index RED. |
| `scripts/detect_batch.py` | Chạy detection offline trên JSONL, dùng để test nhanh event export. |
| `red_linux/scripts/detect_live_linux.py` | Daemon Linux/auditd: poll auditd ECS logs, chạy RED và ghi `red-alerts-linux`. |
| `agent/` | Multi-Agent SOC Triage: Supervisor, Triage, Forensic, Hunt, RED Analyst, MITRE, Response, Report. |
| `models/` | Model runtime đã train: Stage 1 portable và Stage 2 attribution. |
| `data/sigma/rules/` | Sigma rule catalog dùng cho attribution, metadata enrich và exact matching. |
| `config/` | Config field mapping, model path, rule path cho Windows/Linux event types. |
| `velociraptor/` | Binary/config/script cài Velociraptor để Forensic Agent query evidence thật. |
| `run/` | Script menu để chạy detector và AI Agent khi demo. |

## Cấu Trúc Thư Mục

```text
Rule_Evasion_Detection/
+-- red/                         # Core RED runtime
+-- scripts/
|   +-- detect_live.py            # Windows live detector
|   +-- detect_batch.py           # Offline JSONL detector
+-- red_linux/
|   +-- scripts/
|       +-- detect_live_linux.py  # Linux/auditd live detector
+-- agent/                        # AI Agent SOC Triage
|   +-- agents/                   # 8 specialized agents
|   +-- prompts/                  # System prompts
|   +-- daemon.py                 # Agent daemon đọc RED alerts
|   +-- run.py                    # Chạy một alert
|   +-- vr_client.py              # Velociraptor client wrapper
|   +-- vr_client_map.yaml        # Map host.name -> Velociraptor client_id
+-- config/
|   +-- process_creation.yaml
|   +-- powershell.yaml
|   +-- registry_event.yaml
|   +-- detect_live_linux.yml
|   +-- linux_atomic.yaml
|   +-- linux_process_creation.yaml
+-- models/
|   +-- process_creation/
|   +-- powershell/
|   +-- registry_event/
|   +-- linux_atomic/
|   +-- linux_process_creation/
+-- data/
|   +-- sigma/
|       +-- rules/                # Windows/Linux Sigma YAML catalog
+-- velociraptor/                 # Velociraptor runtime + installer files
+-- run/
|   +-- detect.sh                 # Menu chạy RED detector
|   +-- agent.sh                  # Menu chạy AI Agent
+-- requirements.txt
+-- README.md
```

## Model Và Rule Catalog

Các model runtime chính:

```text
models/process_creation/train_rslt_ensemble_portable.zip
models/process_creation/train_rslt_attr_ensemble.zip

models/powershell/train_rslt_ensemble_portable.zip
models/powershell/train_rslt_attr_ensemble.zip

models/registry_event/train_rslt_ensemble_portable.zip
models/registry_event/train_rslt_attr_ensemble.zip

models/linux_atomic/train_rslt_ensemble_atomic_portable.zip
models/linux_process_creation/train_rslt_attr_ensemble_portable.zip
```

Sigma rules nằm trong:

```text
data/sigma/rules/
```

Trong lab hiện tại, một số config vẫn trỏ về `~/data/sigma/rules/...`. Khi chạy trên máy mới, có hai lựa chọn:

1. Copy rule catalog từ repo sang đúng path `~/data/sigma/rules/`.
2. Hoặc sửa `rules_dir` / `sigma_rules_dirs` trong `config/*.yaml` sang `data/sigma/rules/...`.

Dataset train thô không bắt buộc để chạy runtime. Log thật được đọc trực tiếp từ Elasticsearch.

## Pipeline Chạy Thật

### Windows

```text
Elasticsearch logs-windows.*
        |
        v
scripts/detect_live.py
        |
        +-- Stage 1: ML score benign/suspicious
        +-- Stage 2 live: Sigma exact + decode + cosine attribution
        |
        v
red-alerts-v2-proc / red-alerts-v2-reg / red-alerts-v2-ps
```

Windows event types:

| Config | Event ID | Output index |
|---|---:|---|
| `config/process_creation.yaml` | 1 | `red-alerts-v2-proc` |
| `config/registry_event.yaml` | 13 | `red-alerts-v2-reg` |
| `config/powershell.yaml` | 4104 | `red-alerts-v2-ps` |

### Linux

```text
Elasticsearch logs-auditd_manager.auditd-*
        |
        v
red_linux/scripts/detect_live_linux.py
        |
        +-- Stage 1: Linux atomic portable model
        +-- Stage 2 live: Linux Sigma exact + attribution
        |
        v
red-alerts-linux
```

### AI Agent

```text
RED alert index
        |
        v
agent.daemon
        |
        +-- Triage
        +-- Forensic evidence via Velociraptor
        +-- Hunt / RED Analyst / MITRE
        +-- Response
        +-- Vietnamese report
        |
        v
ai-investigations
```

## Yêu Cầu

- Python 3.10+.
- Elasticsearch/Kibana đang nhận Windows/Linux logs.
- Windows endpoint có Sysmon, PowerShell Script Block Logging, Elastic Agent.
- Linux endpoint có Elastic Agent Auditd Manager.
- DeepSeek API key hoặc OpenAI-compatible API key cho AI Agent.
- Velociraptor server/client nếu muốn Forensic Agent lấy evidence thật.

## Cài Đặt

```bash
cd /path/to/Rule_Evasion_Detection

python3 -m venv ~/venvs/rule_evasion_env
source ~/venvs/rule_evasion_env/bin/activate

pip install -r requirements.txt
```

Nếu chạy Forensic Agent thật với Velociraptor:

```bash
pip install pyvelociraptor grpcio pyyaml
```

## Cấu Hình `.env`

Tạo file `.env` ở root repo:

```bash
nano .env
```

Ví dụ cấu hình lab:

```text
# Elasticsearch
ES_AUTH_HOST=https://elastic:YOUR_PASSWORD@192.168.10.10:9200
ES_HOST=https://192.168.10.10:9200
ES_USER=elastic
ES_PASSWORD=YOUR_PASSWORD
ES_VERIFY_SSL=false

# RED / AI Agent indices
ES_RED_INDEX=red-alerts-v2-*
ES_AI_INDEX=ai-investigations

# LLM
DEEPSEEK_API_KEY=sk-your-key
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-chat
AGENT_MAX_ITERATIONS=12
AGENT_TEMPERATURE=0.2
AGENT_LOG_LEVEL=INFO

# Velociraptor real forensic mode
VR_USE_REAL=1
VR_API_CONFIG=velociraptor/api.config.yaml
VR_CLIENT_MAP_FILE=agent/vr_client_map.yaml
VR_QUERY_TIMEOUT=60

# Optional: Kibana Cases
KIBANA_CASES_ENABLED=0
KIBANA_URL=http://192.168.10.10:5601
KIBANA_USER=elastic
KIBANA_PASSWORD=YOUR_PASSWORD
KIBANA_SPACE_ID=default
```

Lưu ý:

- `run/detect.sh` dùng `ES_AUTH_HOST`.
- `agent/` dùng `ES_HOST`, `ES_USER`, `ES_PASSWORD`, `ES_RED_INDEX`, `ES_AI_INDEX`.
- `agent/__init__.py` tự load `.env` với `override=True`, nên giá trị trong `.env` sẽ thắng biến shell.

## Chạy RED Detector

### Chạy bằng menu

```bash
source ~/venvs/rule_evasion_env/bin/activate
./run/detect.sh
```

Menu hỗ trợ:

```text
1) Windows live
2) Linux live
3) Windows + Linux live
4) Windows range
5) Linux range
6) Windows + Linux range
7) Stop detector
8) Đổi ngưỡng phát hiện
```

Chạy nhanh không cần menu:

```bash
./run/detect.sh win-live
./run/detect.sh linux-live
./run/detect.sh both-live
```

Log detector nằm ở:

```text
/tmp/red_demo_v2_logs/
```

## Chạy AI Agent SOC Triage

### Chạy bằng menu

```bash
source ~/venvs/rule_evasion_env/bin/activate
./run/agent.sh
```

Menu hỗ trợ:

```text
1) Investigate 1 Windows alert theo _id
2) Quét Windows alerts theo khoảng thời gian
3) Investigate 1 Linux alert theo _id
4) Quét Linux alerts theo khoảng thời gian
9) Stop agent.daemon
```

Script sẽ đếm alert trước, ước tính chi phí LLM, hỏi xác nhận rồi mới chạy.

Output chính:

```text
ai-investigations
```

Nếu bật Kibana Cases (`KIBANA_CASES_ENABLED=1`), Agent sẽ tạo case trong Kibana và lưu URL vào investigation document.

## Velociraptor Real Forensic Mode

Forensic Agent có thể chạy mock mode hoặc real mode.

Real mode cần:

```text
VR_USE_REAL=1
VR_API_CONFIG=velociraptor/api.config.yaml
VR_CLIENT_MAP_FILE=agent/vr_client_map.yaml
```

`agent/vr_client_map.yaml` map `host.name` trong RED alert sang Velociraptor `client_id`.

Ví dụ:

```yaml
DESKTOP-IQAM883: C.cd6bfbb23aee7979
linux-endpoint: C.xxxxxxxxxxxxxxxx
```

Các file cài đặt Velociraptor đi kèm:

```text
velociraptor/velociraptor
velociraptor/velociraptor-server-0.76.1.amd64.deb
velociraptor/velociraptor_client_0.76.1_amd64.deb
velociraptor/windows_client/*.exe
velociraptor/windows_client/*.msi
velociraptor/windows_client/install_velociraptor_client_windows.ps1
velociraptor/windows_client/install_velociraptor_client_windows.cmd
```

## Các Index Elasticsearch Thường Dùng

| Index | Mục đích |
|---|---|
| `logs-windows.*` | Windows logs từ Elastic Agent. |
| `logs-auditd_manager.auditd-*` | Linux auditd logs. |
| `red-alerts-v2-proc` | RED alerts cho Windows process creation. |
| `red-alerts-v2-reg` | RED alerts cho Windows registry. |
| `red-alerts-v2-ps` | RED alerts cho PowerShell. |
| `red-alerts-linux` | RED alerts cho Linux auditd. |
| `ai-investigations` | Báo cáo AI Agent. |

## Triển Khai Thật Cần Chú Ý

- Repo này có Velociraptor config và binary phục vụ lab thật. Nếu đưa lên GitHub public, nên cân nhắc tách secrets/config thật ra ngoài repo.
- Không commit `.env` chứa password/API key.
- `detect_live.py` không tự đọc `ES_USER`/`ES_PASSWORD`; truyền credential qua `--es-host`, ví dụ `https://elastic:PASSWORD@192.168.10.10:9200`.
- AI Agent có gọi LLM thật, sẽ phát sinh chi phí theo số alert điều tra.
- Nếu Elasticsearch dùng self-signed certificate, đặt `ES_VERIFY_SSL=false` cho Agent. Các detector live hiện đang gọi Elasticsearch với `verify=False`.
- Với Linux inference, nên giữ `RED_DISABLE_INTELEX=1` để tránh lỗi portable khi model SVM chạy trên CPU khác.
- Nếu chạy trên máy khác lab, kiểm tra lại:
  - `ES_AUTH_HOST`, `ES_HOST`, user/password Elasticsearch.
  - `rules_dir` và `sigma_rules_dirs` trong `config/*.yaml`.
  - model path trong `config/*.yaml`.
  - `VR_API_CONFIG` và `agent/vr_client_map.yaml`.
  - index pattern Windows/Linux có đúng với data stream thật không.

## Kiểm Tra Nhanh

Kiểm tra model/rules có đủ:

```bash
ls models/process_creation/train_rslt_ensemble_portable.zip
ls models/powershell/train_rslt_ensemble_portable.zip
ls models/registry_event/train_rslt_ensemble_portable.zip
ls models/linux_atomic/train_rslt_ensemble_atomic_portable.zip
find data/sigma/rules -name "*.yml" | wc -l
```

Kiểm tra decode engine:

```bash
python3 -m red.stage2_live
```

## Ghi Chú An Toàn

RED và các thành phần Velociraptor trong repo này dành cho môi trường lab/demo phòng thủ. Chỉ chạy detector, agent và forensic collection trên hệ thống mà bạn có quyền giám sát.
