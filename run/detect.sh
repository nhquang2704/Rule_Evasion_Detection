#!/usr/bin/env bash
# run/detect.sh — Khoi chay RED detector (Stage 1 ML + Stage 2 attribution) bang menu chon so.
# Thay cho viec copy lenh tay tu demo/RUN_DEMO.md khi demo truc tiep.
#
# Dung:
#   ./run/detect.sh            # hien menu, bam so de chon
#   ./run/detect.sh 1          # chay thang che do 1 (Windows live)
#   ./run/detect.sh win-live   # hoac goi theo ten che do
#
# Cac che do: 1 win-live | 2 linux-live | 3 both-live
#             4 win-range | 5 linux-range | 6 both-range | 7 stop | 0 exit

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

# Nguong phat hien Stage 1 (score >= nguong => suspicious => vao Stage 2).
# Mac dinh 0.5 cho ca Windows lan Linux. Doi qua menu (che do 8).
WIN_THRESHOLD="0.5"
LINUX_THRESHOLD="0.5"

# 3 detector Windows: config:out-index:event-id:tag
WIN_TARGETS=(
  "process_creation:red-alerts-v2-proc:1:proc"
  "registry_event:red-alerts-v2-reg:13:reg"
  "powershell:red-alerts-v2-ps:4104:ps"
)

RANGE_PIDS=()

# ── Helper: nhap khoang thoi gian (gio VN) → START_UTC/END_UTC ───────────
ask_time_range() {
  local sl el
  echo "  Nhap khoang thoi gian theo GIO VIET NAM (UTC+7):"
  read -rp "    Bat dau (vd 2026-06-29 14:00): " sl
  read -rp "    Ket thuc (vd 2026-06-29 14:30): " el
  START_UTC=$(date -u -d "$sl +07:00" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null) \
    || { echo "  ✗ Gio bat dau khong hop le."; return 1; }
  END_UTC=$(date -u -d "$el +07:00" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null) \
    || { echo "  ✗ Gio ket thuc khong hop le."; return 1; }
  echo "  → Quy doi UTC cho ES: $START_UTC  →  $END_UTC"
  local ok; read -rp "  Dung chua? [Y/n]: " ok
  case "$ok" in [nN]*) echo "  Da huy."; return 1;; esac
  return 0
}

# ── Windows LIVE (Section 3): 3 detector song song, quet lui 5 phut ──────
win_live() {
  local SINCE; SINCE=$(date -u -d '5 minutes ago' +%Y-%m-%dT%H:%M:%S.000Z)
  echo "  [Windows LIVE] quet lui tu $SINCE — interval 15s — 3 detector:"
  local t cfg out eid tag
  for t in "${WIN_TARGETS[@]}"; do
    IFS=: read -r cfg out eid tag <<< "$t"
    "$PY" scripts/detect_live.py \
      --config "config/$cfg.yaml" \
      --es-host "$ES" --es-index "logs-windows.*" \
      --out-index "$out" --event-id "$eid" \
      --threshold "$WIN_THRESHOLD" --method cosine --top-k 5 --timestamp-field @timestamp \
      --interval 15 --state-file "/tmp/.state_v2_$tag.json" --since "$SINCE" \
      --exact-sigma \
      > "$LOGDIR/detect_$tag.log" 2>&1 &
    echo "    → $cfg (EID $eid) → $out  PID=$!  log=$LOGDIR/detect_$tag.log"
  done
  echo "  (dang chay nen — dung menu 7 de tat)"
}

# ── Linux LIVE (Section 3L): auditd, quet lui 5 phut ────────────────────
linux_live() {
  local SINCE; SINCE=$(date -u -d '5 minutes ago' +%Y-%m-%dT%H:%M:%S.000Z)
  echo "  [Linux LIVE] quet lui tu $SINCE — interval 15s — auditd:"
  RED_DISABLE_INTELEX=1 "$PY" red_linux/scripts/detect_live_linux.py \
    --config config/detect_live_linux.yml \
    --es-host "$ES" --es-index "logs-auditd_manager.auditd-*" \
    --out-index red-alerts-linux \
    --threshold "$LINUX_THRESHOLD" --method cosine --top-k 5 \
    --interval 15 --state-file /tmp/.state_linux.json --since "$SINCE" \
    > "$LOGDIR/detect_linux.log" 2>&1 &
  echo "    → Linux detector → red-alerts-linux  PID=$!  log=$LOGDIR/detect_linux.log"
  echo "  (dang chay nen — dung menu 7 de tat)"
}

# ── Windows RANGE (Section 4): quet 1 khoang, bounded (max-iter 5) ───────
_win_range_run() {
  local t cfg out eid tag
  echo "  [Windows RANGE] $START_UTC → $END_UTC — 3 detector:"
  for t in "${WIN_TARGETS[@]}"; do
    IFS=: read -r cfg out eid tag <<< "$t"
    "$PY" scripts/detect_live.py \
      --config "config/$cfg.yaml" \
      --es-host "$ES" --es-index "logs-windows.*" \
      --out-index "$out" --event-id "$eid" \
      --threshold "$WIN_THRESHOLD" --method cosine --top-k 5 --timestamp-field @timestamp \
      --since "$START_UTC" --until "$END_UTC" \
      --interval 1 --batch-size 5000 --max-iter 5 --no-state \
      --exact-sigma \
      > "$LOGDIR/range_$tag.log" 2>&1 &
    RANGE_PIDS+=($!)
    echo "    → $cfg (EID $eid) → $out  PID=$!  log=$LOGDIR/range_$tag.log"
  done
}

# ── Linux RANGE (Section 4L): quet 1 khoang, bounded (max-iter 10) ───────
_linux_range_run() {
  echo "  [Linux RANGE] $START_UTC → $END_UTC:"
  RED_DISABLE_INTELEX=1 "$PY" red_linux/scripts/detect_live_linux.py \
    --config config/detect_live_linux.yml \
    --es-host "$ES" --es-index "logs-auditd_manager.auditd-*" \
    --out-index red-alerts-linux \
    --threshold "$LINUX_THRESHOLD" --method cosine --top-k 5 \
    --since "$START_UTC" --until "$END_UTC" \
    --interval 1 --batch-size 2000 --max-iter 10 --no-state \
    > "$LOGDIR/range_linux.log" 2>&1 &
  RANGE_PIDS+=($!)
  echo "    → Linux detector → red-alerts-linux  PID=$!  log=$LOGDIR/range_linux.log"
}

wait_ranges() {
  [ ${#RANGE_PIDS[@]} -eq 0 ] && return
  echo "  Dang quet... (cho hoan tat, khong tat terminal)"
  wait "${RANGE_PIDS[@]}" 2>/dev/null
  echo "  ✓ Quet xong. Xem ket qua: $LOGDIR/range_*.log"
}

# ── Stop ────────────────────────────────────────────────────────────────
detect_stop() {
  pkill -f "scripts/detect_live.py"      2>/dev/null && echo "  ✓ Da dung detector Windows" || echo "  (khong co detector Windows nao chay)"
  pkill -f "detect_live_linux.py"        2>/dev/null && echo "  ✓ Da dung detector Linux"   || echo "  (khong co detector Linux nao chay)"
  sleep 1
  echo "  Tien trinh con lai:"
  pgrep -af "detect_live" || echo "    (khong con)"
}

# ── Doi nguong phat hien (che do 8) ─────────────────────────────────────
_valid_threshold() {  # $1 = gia tri; return 0 neu la so trong [0,1]
  [[ "$1" =~ ^[0-9]+(\.[0-9]+)?$ ]] && awk -v x="$1" 'BEGIN{exit !(x>=0 && x<=1)}'
}

set_threshold() {
  local which val
  echo "  Doi nguong cho:  1) Windows   2) Linux   3) Ca hai"
  read -rp "  Chon [1-3]: " which
  case "$which" in
    1|2|3) ;;
    *) echo "  ✗ Lua chon khong hop le."; return 1 ;;
  esac
  read -rp "  Nguong moi (0.0 - 1.0): " val
  if ! _valid_threshold "$val"; then
    echo "  ✗ '$val' khong phai so trong khoang 0.0 - 1.0."; return 1
  fi
  case "$which" in
    1) WIN_THRESHOLD="$val";   echo "  ✓ Windows = $WIN_THRESHOLD" ;;
    2) LINUX_THRESHOLD="$val"; echo "  ✓ Linux = $LINUX_THRESHOLD" ;;
    3) WIN_THRESHOLD="$val"; LINUX_THRESHOLD="$val"; echo "  ✓ Windows = Linux = $val" ;;
  esac
}

# ── Menu + dispatch ─────────────────────────────────────────────────────
show_menu() {
  cat <<'EOF'

  ================================================
   RED Detector — Stage 1 (ML) + Stage 2
EOF
  echo "   (Nguong hien tai: Windows=$WIN_THRESHOLD  Linux=$LINUX_THRESHOLD)"
  cat <<'EOF'
  ================================================
   LIVE  (chay lien tuc, quet lui 5 phut):
     1) Windows   (proc + reg + ps)
     2) Linux     (auditd)
     3) Ca hai    (Windows + Linux)

   RANGE (quet 1 khoang thoi gian cu the):
     4) Windows
     5) Linux
     6) Ca hai

     8) Doi nguong phat hien
     7) Stop  — tat tat ca detector
     0) Thoat
  ================================================
EOF
}

run_choice() {
  case "$1" in
    1|win-live)    win_live ;;
    2|linux-live)  linux_live ;;
    3|both-live)   echo "  [CA HAI LIVE]"; win_live; linux_live ;;
    4|win-range)   if ask_time_range; then RANGE_PIDS=(); _win_range_run; wait_ranges; fi ;;
    5|linux-range) if ask_time_range; then RANGE_PIDS=(); _linux_range_run; wait_ranges; fi ;;
    6|both-range)  if ask_time_range; then RANGE_PIDS=(); _win_range_run; _linux_range_run; wait_ranges; fi ;;
    8|set-threshold) set_threshold ;;
    7|stop)        detect_stop ;;
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
  read -rp "  Chon [0-8]: " choice
  run_choice "$choice"; rc=$?
  [ "$rc" = 9 ] && { echo "  Thoat. (detector live neu dang chay van tiep tuc nen)"; break; }
  echo
  read -rp "  [Enter] de ve menu..." _
done
