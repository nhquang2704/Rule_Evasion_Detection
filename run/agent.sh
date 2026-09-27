#!/usr/bin/env bash
# run/agent.sh — Khoi chay RED Multi-Agent (SOC Triage 8 agents) bang menu chon so.
# Thay cho viec copy lenh tay tu demo/RUN_DEMO.md (Section 6 / 6L) khi demo.
#
# ⚠ Cac che do deu GOI LLM that → ton token (~$0.03-0.05/alert).
#   Script luon: dem truoc (khong ton token) → bao chi phi → hoi xac nhan → moi chay.
#
# Dung:
#   ./run/agent.sh             # hien menu, bam so de chon
#   ./run/agent.sh 1           # chay thang che do 1
#
# Che do: 1 win-id | 2 win-range | 3 linux-id | 4 linux-range | 9 stop | 0 exit

set -o pipefail

# ── Moi truong ──────────────────────────────────────────────────────────
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || { echo "✗ Khong vao duoc repo root: $REPO_ROOT"; exit 1; }

VENV="$HOME/venvs/rule_evasion_env"
[ -f "$VENV/bin/activate" ] && source "$VENV/bin/activate"
PY="$VENV/bin/python"; [ -x "$PY" ] || PY="python3"

if [ -f ./.env ]; then
  set -a; . ./.env; set +a
else
  echo "⚠ Khong thay ./.env trong $REPO_ROOT — ES_AUTH_HOST co the trong."
fi

LOGDIR="/tmp/red_demo_v2_logs"
mkdir -p "$LOGDIR"

ES="${ES_AUTH_HOST:-}"
[ -z "$ES" ] && echo "⚠ ES_AUTH_HOST chua set (kiem tra ./.env)."

WIN_INDEX="red-alerts-v2-*"
LINUX_INDEX="red-alerts-linux"
COST_PER_ALERT="0.04"   # uoc tinh trung binh (DeepSeek ~$0.03-0.05/alert)

# ── Helpers ─────────────────────────────────────────────────────────────
_valid_threshold() {  # $1 = gia tri; return 0 neu la so trong [0,1]
  [[ "$1" =~ ^[0-9]+(\.[0-9]+)?$ ]] && awk -v x="$1" 'BEGIN{exit !(x>=0 && x<=1)}'
}

confirm() {  # $1 = cau hoi; return 0 neu y/Y
  local ok; read -rp "  $1 [y/N]: " ok
  case "$ok" in [yY]*) return 0;; *) echo "  Da huy."; return 1;; esac
}

ask_time_range() {  # set START_UTC / END_UTC tu gio VN
  local sl el
  echo "  Nhap khoang thoi gian theo GIO VIET NAM (UTC+7):"
  read -rp "    Bat dau (vd 2026-06-29 14:00): " sl
  read -rp "    Ket thuc (vd 2026-06-29 14:30): " el
  START_UTC=$(date -u -d "$sl +07:00" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null) \
    || { echo "  ✗ Gio bat dau khong hop le."; return 1; }
  END_UTC=$(date -u -d "$el +07:00" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null) \
    || { echo "  ✗ Gio ket thuc khong hop le."; return 1; }
  echo "  → Quy doi UTC cho ES: $START_UTC  →  $END_UTC"
  confirm "Dung chua?" || return 1
  return 0
}

# Dem alert khop (range + score >= thr). thr=0 => khong loc score. Echo so dem.
count_alerts() {  # $1=idx $2=start $3=end $4=thr
  local idx="$1" s="$2" e="$3" thr="$4" scorefilter=""
  if awk -v x="$thr" 'BEGIN{exit (x>0)?0:1}'; then
    scorefilter=",{\"bool\":{\"should\":[{\"range\":{\"red.stage1_score\":{\"gte\":$thr}}},{\"range\":{\"red.detection_score\":{\"gte\":$thr}}}],\"minimum_should_match\":1}}"
  fi
  local q="{\"query\":{\"bool\":{\"filter\":[{\"range\":{\"@timestamp\":{\"gte\":\"$s\",\"lte\":\"$e\"}}}$scorefilter]}}}"
  curl -sk "$ES/$idx/_count" -H 'Content-Type: application/json' -d "$q" 2>/dev/null \
    | python3 -c "import json,sys; print(json.load(sys.stdin).get('count',0))" 2>/dev/null
}

# ── Mode: investigate 1 alert theo _id (Section 6.2 C1 / 6L B) ───────────
agent_by_id() {  # $1=idx $2=logfile
  local idx="$1" logf="$2" docid
  read -rp "  Dan DOC_ID (vd QSMfA58B90hxtQ-l68OZ): " docid
  docid="${docid//[$'\t\r\n ']/}"   # bo khoang trang
  docid="${docid//\"/}"             # bo nháy kep neu lo dan
  docid="${docid//\'/}"             # bo nháy don
  [ -z "$docid" ] && { echo "  ✗ DOC_ID rong."; return 1; }

  echo "  Kiem tra _id ton tai... (khong ton token)"
  local hits
  hits=$(curl -sk "$ES/$idx/_search" -H 'Content-Type: application/json' \
    -d "{\"query\":{\"query_string\":{\"query\":\"_id:\\\"$docid\\\"\"}}}" 2>/dev/null \
    | python3 -c "import json,sys; print(json.load(sys.stdin).get('hits',{}).get('total',{}).get('value',0))" 2>/dev/null)
  hits="${hits:-0}"
  if [ "$hits" = "0" ]; then
    echo "  ✗ Khong tim thay alert _id=$docid trong $idx."
    return 1
  fi
  echo "  ✓ Tim thay alert (hits=$hits)."
  echo "  Investigate 1 alert — uoc tinh ~\$$COST_PER_ALERT token."
  confirm "Chay?" || return 1

  local SINCE_AGENT; SINCE_AGENT=$(date -u -d '24 hour ago' +%Y-%m-%dT%H:%M:%SZ)
  echo "  ───────────────────────────────────────────"
  echo "  Investigate _id=$docid tren $idx ..."
  PYTHONUNBUFFERED=1 "$PY" -m agent.daemon \
    --red-index "$idx" \
    --max-iter 1 --batch-limit 1 --no-state \
    --since "$SINCE_AGENT" \
    --query-string "_id:\"$docid\"" \
    2>&1 | tee "$LOGDIR/$logf"
  echo "  ✓ Xong. Log: $LOGDIR/$logf"
}

# ── Mode: quet theo khoang thoi gian + tu nhap nguong (Section 6.2 D) ────
agent_by_range() {  # $1=idx $2=logfile
  local idx="$1" logf="$2" thr
  ask_time_range || return 1

  echo "  Nhap nguong score (0.0 - 1.0):"
  echo "    goi y: 0.0 = quet tat ca  ·  0.9 = chi diem cao"
  read -rp "  Nguong: " thr
  if ! _valid_threshold "$thr"; then
    echo "  ✗ '$thr' khong phai so trong khoang 0.0 - 1.0."
    return 1
  fi

  echo "  Dang dem alert khop... (khong ton token)"
  local count; count=$(count_alerts "$idx" "$START_UTC" "$END_UTC" "$thr")
  count="${count:-0}"
  if [ "$count" = "0" ]; then
    echo "  → Tim thay 0 alert co score ≥ $thr trong khoang nay."
    echo "  (Khong co gi de investigate — thu ha nguong hoac doi khoang thoi gian.)"
    return 0
  fi

  local cost; cost=$(awk -v n="$count" -v c="$COST_PER_ALERT" 'BEGIN{printf "%.2f", n*c}')
  echo "  → Tim thay $count alert co score ≥ $thr."
  echo "  → Uoc tinh chi phi: ~\$$cost  ($count × \$$COST_PER_ALERT)"
  confirm "Chay investigate $count alert?" || return 1

  local batch=10
  local maxiter=$(( count / batch + 3 ))   # du de quet het roi tu dung
  echo "  ───────────────────────────────────────────"
  echo "  Chay agent.daemon ($idx, score ≥ $thr, $count alert)..."
  PYTHONUNBUFFERED=1 "$PY" -m agent.daemon \
    --red-index "$idx" \
    --since "$START_UTC" --until "$END_UTC" \
    --score-threshold "$thr" \
    --batch-limit "$batch" --max-iter "$maxiter" --interval 2 --no-state \
    2>&1 | tee "$LOGDIR/$logf"
  echo "  ✓ Hoan tat. Log: $LOGDIR/$logf"
}

# ── Stop ────────────────────────────────────────────────────────────────
agent_stop() {
  pkill -f "agent.daemon" 2>/dev/null && echo "  ✓ Da gui tin hieu dung agent.daemon" \
    || echo "  (khong co agent.daemon nao dang chay)"
  sleep 1
  echo "  Tien trinh con lai:"
  pgrep -af "agent.daemon" || echo "    (khong con)"
}

# ── Menu + dispatch ─────────────────────────────────────────────────────
show_menu() {
  cat <<'EOF'

  ================================================
   RED Multi-Agent — SOC Triage (8 agents)
   (Ton token that ~$0.03-0.05/alert — se hoi xac nhan)
  ================================================
   Windows (red-alerts-v2-*):
     1) Investigate 1 alert theo _id
     2) Quet theo khoang thoi gian (tu nhap nguong)

   Linux (red-alerts-linux):
     3) Investigate 1 alert theo _id
     4) Quet theo khoang thoi gian (tu nhap nguong)

     9) Stop  — tat agent.daemon
     0) Thoat
  ================================================
EOF
}

run_choice() {
  case "$1" in
    1|win-id)      agent_by_id    "$WIN_INDEX"   "agent_win_id.log" ;;
    2|win-range)   agent_by_range "$WIN_INDEX"   "agent_win_range.log" ;;
    3|linux-id)    agent_by_id    "$LINUX_INDEX" "agent_linux_id.log" ;;
    4|linux-range) agent_by_range "$LINUX_INDEX" "agent_linux_range.log" ;;
    9|stop)        agent_stop ;;
    0|exit|quit|q) return 9 ;;
    *) echo "  ✗ Lua chon khong hop le: $1" ;;
  esac
}

# Goi truc tiep voi tham so (che do nhanh) → chay 1 lan roi thoat
if [ $# -gt 0 ]; then
  run_choice "$1"
  exit $?
fi

# Mac dinh: menu lap
while true; do
  show_menu
  read -rp "  Chon [0-9]: " choice
  run_choice "$choice"; rc=$?
  [ "$rc" = 9 ] && { echo "  Thoat."; break; }
  echo
  read -rp "  [Enter] de ve menu..." _
done
