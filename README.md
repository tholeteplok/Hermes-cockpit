# Hermes Cockpit 🚀

A lightweight, standalone web dashboard and Progressive Web App (PWA) for **Hermes Agent**, built entirely with Python standard library (no third-party dependencies required).

## Features ✨

- **Dual-Agent Cockpit Scene:** Interactive SVG mascot display tracking both PC Agent actions (typing, searching, asking, error, idle) and Telegram bot interactions.
- **Real-Time Health Monitoring:** Gateway heartbeat detection, memory usage, system platform status, and live liveness indicators.
- **Activity & Alerts Feed:** Real-time log of tool executions, scheduled task alerts, and Telegram inbound/outbound events with automatic secret redaction.
- **Cron Jobs Control:** Inspect, trigger, pause, and resume scheduled cron tasks directly from the UI.
- **PWA & Mobile-First:** Responsive layout with dark/light theme support, home screen installation (manifest & icons), and push notifications.
- **Secure by Default:** Token-based authentication, optional Tailscale automatic IP binding, and TLS/HTTPS support.

## Getting Started 🛠️

### Prerequisites

- Python 3.10+
- A running [Hermes Agent](https://github.com/NousResearch/hermes-agent) instance

### Running Cockpit

Run directly with Python:

```bash
python3 cockpit_v2_standalone.py
```

By default, Cockpit automatically detects your Tailscale IP (or falls back to `127.0.0.1`) on port `8080`.

### CLI Options

```text
--port PORT          Port to bind (default: 8080)
--host HOST          Host IP to bind (e.g. 0.0.0.0, Tailscale IP, or 127.0.0.1)
--token TOKEN        Access token (generated and saved to .cockpit_token if omitted)
--ssl-cert CERT      Path to SSL certificate (.crt)
--ssl-key KEY        Path to SSL private key (.key)
```

### Systemd Service (Optional)

To run as a systemd user service:

```ini
[Unit]
Description=Hermes Dashboard Cockpit
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /path/to/cockpit_v2_standalone.py
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
```

## Security Note 🔒

- Never commit SSL certificates, private keys, or `.cockpit_token` to version control.
- Logs and executions are filtered with secret redaction patterns to prevent leaking sensitive API keys.

## License

MIT
