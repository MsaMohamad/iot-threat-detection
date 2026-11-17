#!/usr/bin/env bash
# demo_mixed.sh - interleaved ATTACK + NORMAL traffic demo (AUTHORIZED LAB USE ONLY).
# Runs: attack -> normal -> attack -> normal ... cycling all 4 attack types across
# both ESP32 nodes, so you can watch the dashboard separate threats (red + auto-block)
# from legitimate traffic (stays green). Good for a live false-positive/negative demo.
#
# Usage:
#   ./demo_mixed.sh [ROUNDS] [GAP_SECONDS]
#     ROUNDS        times through the 4 attack types   (default 3 -> 3x4 = 12 attacks + 12 normal)
#     GAP_SECONDS   pause after each step               (default 15)
set -u

NODE_A='192.168.0.136'      # ESP32 Node A (static IP)
NODE_B='192.168.0.137'      # ESP32 Node B (static IP)
LOGIN_PATH='/login'
ROUNDS="${1:-3}"
GAP="${2:-15}"
LOG="$HOME/demo_mixed.log"

C='\033[1;36m'; G='\033[1;32m'; Y='\033[1;33m'; R='\033[1;31m'; X='\033[0m'
log(){ printf "[%s] %b\n" "$(date '+%F %T')" "$*" | tee -a "$LOG"; }
priv_ip(){ [[ "$1" =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)[0-9.]+$ ]]; }
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

# --- normal (benign) traffic: a few light HTTP requests ---
t_normal(){ local i; for i in 1 2 3; do
  curl -s -o /dev/null -m5 "http://$1/" >/dev/null 2>&1 || true; sleep 1; done; }

ATTACKS=(a_portscan a_ddos a_brute a_usb)
NAMES=(PortScan DDoS BruteForce USB)
TOTAL=$(( ROUNDS * ${#ATTACKS[@]} ))

log "${C}START mixed demo${X}: ${TOTAL} attacks + ${TOTAL} normal, gap ${GAP}s"
n=0
for ((round=1; round<=ROUNDS; round++)); do
  for idx in "${!ATTACKS[@]}"; do
    if (( n % 2 == 0 )); then T="$NODE_A"; L="A"; else T="$NODE_B"; L="B"; fi
    n=$((n+1))
    log "${R}ATTACK${X} ${NAMES[$idx]} -> Node ${L} (${T})   [dashboard: expect RED + auto-block]"
    "${ATTACKS[$idx]}" "$T"
    sleep "$GAP"
    log "${G}NORMAL${X} traffic -> Node ${L} (${T})         [dashboard: expect STAYS GREEN]"
    t_normal "$T"
    sleep "$GAP"
  done
done
log "${C}DONE mixed demo${X}: ${TOTAL} attack + ${TOTAL} normal cycles complete."
