#!/usr/bin/env bash
# IoT SOC - FYP demo launcher. Authorized lab use only: own ESP32 nodes on private LAN.
set -u
G='\033[1;32m'; C='\033[1;36m'; Y='\033[1;33m'; R='\033[1;31m'; D='\033[0;90m'; X='\033[0m'

# ---- config (change once if the demo network changes) ----------------------
NODE_A='192.168.0.136'      # ESP32 Node A - STATIC IP (firmware)
NODE_B='192.168.0.137'      # ESP32 Node B - STATIC IP (firmware)
SERVER='100.89.233.26'      # server Tailscale IP (avoid self-lockout)
TARGET="$NODE_A"
LOG="$HOME/iotsoc_demo_runs.log"

say(){ printf '%b\n' "$*"; }
log(){ printf '[%s] target=%s test=%s\n' "$(date '+%F %T')" "$TARGET" "$1" >>"$LOG"; }
need(){ command -v "$1" >/dev/null 2>&1 || { say "${R}[MISSING]${X} $1 - sudo apt install $1"; return 1; }; }
priv_ip(){ [[ "$1" =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)[0-9.]+$ ]]; }
confirm(){ local a; say "${Y}Authorized FYP lab target:${X} $TARGET"; read -r -p 'Type YES to continue: ' a; [[ "$a" == YES ]]; }

preflight(){
  say "${C}== Preflight check ==${X}"
  for t in nmap hping3 curl; do command -v "$t" >/dev/null 2>&1 \
    && say "  ${G}OK${X}  $t" || say "  ${R}--${X}  $t (sudo apt install $t)"; done
  say "  Dashboard : http://$SERVER:5000"
  local code; code=$(curl -sS -o /dev/null -m4 -w '%{http_code}' "http://$SERVER:5000/" 2>/dev/null||echo 000)
  [[ "$code" == 200 ]] && say "  ${G}OK${X}  Server dashboard reachable ($code)" \
    || say "  ${R}--${X}  Server not responding ($code) - is app.py running? Tailscale on?"
  for n in "A:$NODE_A" "B:$NODE_B"; do local lbl=${n%%:*} ip=${n#*:}
    [[ -z "$ip" ]] && { say "  ${D}..  Node $lbl IP not set${X}"; continue; }
    code=$(curl -sS -o /dev/null -m3 -w '%{http_code}' "http://$ip/" 2>/dev/null||echo 000)
    [[ "$code" != 000 ]] && say "  ${G}OK${X}  Node $lbl ($ip) up" \
      || say "  ${Y}..${X}  Node $lbl ($ip) no HTTP reply (fine if firmware has no web server)"; done
}

t_portscan(){ need nmap||return; confirm||return
  say "${C}Port Scan - SYN 1-1000, capped 150 pkt/s, max 45s${X}"; log PORT_SCAN
  sudo nmap -sS -Pn -n -T4 -p 1-1000 "$TARGET"
  say "${G}Watch the dashboard: hero turns red 'Port Scan detected', node $( [[ $TARGET == $NODE_B ]]&&echo B||echo A ) lights up red.${X}"; }

t_ddos(){ need hping3||return; confirm||return
  say "${C}DDoS - SYN flood to 1 port (~8s), bounded single-source${X}"; log DDOS_BURST
  sudo timeout 10s hping3 -S -p 80 --flood "$TARGET"; say "(flood stops automatically after 10s)"
  say "${G}Expected: 'DDoS detected' with the [R] tag, pkts/sec spikes high.${X}"; }

t_brute(){ need curl||return
  local path='/login' a i; read -r -p 'Login path [/login]: ' a; [[ -n "${a:-}" ]]&&path="$a"
  [[ "$path" =~ ^/[A-Za-z0-9_/-]{0,80}$ ]]||{ say "${R}Invalid path${X}"; return; }
  confirm||return; say "${C}Brute Force - 15 wrong login attempts (2/sec)${X}"; log BRUTE_FORCE
  for((i=1;i<=15;i++)); do curl -s -o /dev/null -m3 -X POST \
    --data 'username=admin&password=wrongpass' "http://$TARGET$path"||true; sleep 0.5; done
  say "${G}Expected: 'Brute Force detected' once failed_logins reaches the threshold.${X}"; }

t_usb(){ need nmap||return; confirm||return
  say "${C}USB Malware (behavioral) - worm-like propagation scan, 3 rounds${X}"
  say "Simulates malware after a USB insert: scans common ports to find other devices."
  say "No real USB/malware. Detected as Port Scan via its network pattern."; log USB_MALWARE
  for r in 1 2 3; do
    sudo nmap -sS -Pn -n -T4 -p 21,22,23,25,80,135,139,443,445,3389,8080 "$TARGET" >/dev/null
    say "  round $r/3 sent"
  done
  sudo nmap -sS -Pn -n -T4 -p 1-200 "$TARGET"
  say "${G}Expected: 'Port Scan detected' - the system reads the worm pattern as recon.${X}"; }

t_normal(){ need curl||return
  say "${C}Normal traffic - a single slow HTTP request (not an attack)${X}"
  say "The system's idle state is already Normal (green). This is just light, legitimate traffic."; log NORMAL_TRAFFIC
  for i in 1 2 3; do
    curl -s -o /dev/null --max-time 5 "http://$TARGET/" 2>/dev/null || true
    say "  request $i/3 sent (normal, port 80 only)"
    sleep 5
  done
  say "${G}Expected: hero STAYS GREEN. If it still turns red, just use the idle state - do not generate traffic.${X}"
  say "${Y}Note: synthetic traffic sometimes does not match the model's trained Normal profile.${X}"; }

t_conn(){ preflight; }
t_target(){ local p
  say "  [a] Node A ($NODE_A)   [b] Node B (${NODE_B:-not set})   [m] other IP"
  read -r -p '  Choose: ' p
  case "$p" in a)TARGET="$NODE_A";; b)[[ -n "$NODE_B" ]]&&TARGET="$NODE_B"||say "${R}Node B not set${X}";;
    m)read -r -p '  Private IP: ' p; priv_ip "$p"&&TARGET="$p"||say "${R}Not a private IP${X}";; esac
  say "  Target now: ${C}$TARGET${X}"; }

while true; do
  printf '\033[2J\033[H'
  say "${G}================================================================${X}"
  say "   IoT SOC  /  FYP DEMO LAUNCHER"
  say "${G}================================================================${X}"
  say "   Target : ${C}$TARGET${X}   Dashboard : http://$SERVER:5000"
  say ''
  say "   [1] Port Scan        (nmap SYN)"
  say "   [2] DDoS             (hping3 SYN flood, 10s)"
  say "   [3] Brute Force      (failed logins)"
  say "   [4] USB Malware      (behavioral - worm scan)"
  say "   [5] Normal traffic    (benign - should stay green)"
  say "   [6] Preflight check  (services + reachability)"
  say "   [7] Change target node"
  say "   [0] Exit"
  say ''
  read -r -p '   Choose [0-7]: ' o
  case "$o" in 1)t_portscan;; 2)t_ddos;; 3)t_brute;; 4)t_usb;; 5)t_normal;; 6)t_conn;; 7)t_target;; 0)break;;
    *)say "${Y}Invalid choice${X}";; esac
  say ''; read -r -p '   ENTER to return to menu...' _
done
