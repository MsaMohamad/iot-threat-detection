#!/usr/bin/env bash
# IoT SOC - start the dashboard backend cleanly. Run on the server: ./start_server.sh
set -u
G='\033[1;32m'; C='\033[1;36m'; Y='\033[1;33m'; R='\033[1;31m'; X='\033[0m'
ok(){ printf "  ${G}OK${X}  %b\n" "$1"; }
warn(){ printf "  ${Y}..${X}  %b\n" "$1"; }
err(){ printf "  ${R}--${X}  %b\n" "$1"; }

FYP="$HOME/fyp"; VENV="$FYP/venv"; DASH="$FYP/dashboard"
printf "${C}== IoT SOC server startup ==${X}\n"

# 1. venv
if [[ -f "$VENV/bin/activate" ]]; then . "$VENV/bin/activate"; ok "venv activated"
else err "venv not found at $VENV - run: python3 -m venv ~/fyp/venv && install requirements"; exit 1; fi

# 2. kill proses app.py lama
if pgrep -f "app.py" >/dev/null; then pkill -9 -f "app.py"; sleep 1; ok "proses app.py lama dibunuh"
else ok "takde proses app.py lama"; fi

# 3. port 5000 kosong?
if command -v lsof >/dev/null && sudo lsof -i :5000 >/dev/null 2>&1; then
  warn "port 5000 still in use - wait a moment / pkill manually"; else ok "port 5000 free"; fi

# 4. Mosquitto broker
if systemctl is-active --quiet mosquitto 2>/dev/null; then ok "Mosquitto broker running"
else warn "Mosquitto not active - trying to start"; sudo systemctl start mosquitto 2>/dev/null \
  && ok "Mosquitto started" || err "Mosquitto failed to start - check /etc/mosquitto/conf.d/default.conf"; fi

# 5. model files
[[ -f "$FYP/models_output/model.pkl" && -f "$FYP/models_output/scaler.pkl" ]] \
  && ok "model.pkl + scaler.pkl ada" || err "model/scaler hilang di ~/fyp/models_output"

# 6. timezone (demo ingin MYT)
tz=$(timedatectl show -p Timezone --value 2>/dev/null || echo '?')
[[ "$tz" == "Asia/Kuala_Lumpur" ]] && ok "timezone $tz" || warn "timezone $tz (set: sudo timedatectl set-timezone Asia/Kuala_Lumpur)"

# 7. IP info - makes it easy to know what to put in the Kali launcher
printf "${C}-- Access info --${X}\n"
ipv4=$(hostname -I 2>/dev/null | awk '{print $1}')
printf "   LAN dashboard  : http://%s:5000\n" "${ipv4:-?}"
command -v tailscale >/dev/null && printf "   Tailscale IP   : %s\n" "$(tailscale ip -4 2>/dev/null | head -1)"

printf "${C}== Starting app.py (Ctrl+C to stop) ==${X}\n\n"
cd "$DASH" || { err "$DASH not found"; exit 1; }
exec python3 app.py
