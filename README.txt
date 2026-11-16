FYP FINAL CODE - Automated IoT Network Threat Detection & Mitigation (Decision Tree)
Muhammad Syahmi Aiman bin Mohamad | 51221124173 | BTET UniKL BMI

Only the code used in the real system. Old drafts/versions are NOT included.

FINAL_CODE/
  esp32_firmware/
    fyp_firmware_nodeA/fyp_firmware_nodeA.ino   Node A (firmware v5) -> topic iot/esp32_1/data
    fyp_firmware_nodeB/fyp_firmware_nodeB.ino   Node B (copy v5)  -> topic iot/esp32_2/data
       v5 = raw socket TCP monitoring + port diversity + login form (brute force)
            + source IP tracking + MQTT buffer 512
       Beza Node B: client ID ESP32_FYP_NodeB, device esp32_2, topic esp32_2
  server/  (copy from fyp-server: /home/fyp_syaman/fyp/)
    dashboard/app.py            Flask + SocketIO + MQTT + ML + iptables + SQLite + Telegram
    dashboard/templates/        index.html (dashboard), ml_model.html (ML page)
    dashboard/upgrade_dashboard.py   patch v2 (dual node, DB, Telegram, countdown)
    models_output/              model.pkl, scaler.pkl (Decision Tree 96.79%)
    *.py                        train_model.py, live_predictor.py, extract_*.py, combine_datasets.py

Server: Ubuntu 24.04 VM (Proxmox) 192.168.0.101 / Tailscale 100.89.233.26
Run: source ~/fyp/venv/bin/activate && cd ~/fyp/dashboard && python3 app.py
Dashboard: http://<server>:5000   CSV export: http://<server>:5000/export.csv
Firmware: WiFi + mqtt_server hardcoded (lines 7-9) - change to match the demo network.
