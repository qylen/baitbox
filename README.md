
# 🪤 BaitBox

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen)](#)

> **BaitBox** is a zero-config, multi-protocol honeypot for homelabbers and security researchers. Drop attackers into a stateful fake filesystem, watch them try to pivot, and get real-time alerts — all from a beautiful cyber command-center dashboard.

<img width="1280" height="720" alt="y" src="https://github.com/user-attachments/assets/6ef378cd-ddf3-40c8-808e-423c1ccb95fd" />

## 🚀 Features

- **🛡️ Multi-Protocol Honeypot:** Simultaneously traps SSH, HTTP, and Telnet attackers.
- **🎭 Stateful Fake Filesystem (VFS):** SSH attackers are dropped into a convincing virtual Linux machine with realistic files: `~/.bash_history`, `~/.bashrc` (with fake DB passwords), `~/.ssh/authorized_keys`, `/var/www/html/.env`, `/etc/shadow`, `/etc/crontab`, Nginx config, MySQL dumps, auth logs, and more.
- **💻 50+ Fake Shell Commands:** Full interactive shell with `ls -la` (hidden files), `cd ~`, `cat`, `grep`, `find`, `ps aux`, `netstat`, `ifconfig`/`ip`, `who`, `last`, `df`, `free`, `top`, `crontab -l`, `python3 -c`, `mysql`, `git log`, `systemctl status`, `nmap`, `wget`/`curl`, `ping`, `vi`/`nano`, `echo` with redirection, shell script execution, history navigation (↑ arrow), Ctrl+C, Ctrl+D.
- **📡 Telnet Honeypot:** An asyncio-powered Telnet server on port 2323 that captures credentials and commands.
- **📊 Premium Dashboard:** A stunning, pure-vanilla-CSS cyber command center with:
  - **Live GeoIP Attack Map** (server-side resolution, cached, no API key needed)
  - **Threat Score Indicators** (🔴 HIGH / 🟡 MED / 🟢 LOW per attacker)
  - **24-Hour Event Timeline** chart
  - **Protocol Split** donut chart
  - **Real-time event stream** with pause/resume
  - **IP Block/Unblock** controls — one click blocks an IP and terminates their sessions
  - **Top Offending IPs, Top Passwords, Top HTTP Paths** leaderboards
  - **Active Intruder Controller** — live session view with BOOT/BLOCK/MAP buttons
- **🔔 Webhook Notifications:** Discord and Slack alerts for auth attempts, commands, and decoy hits.
- **🚫 IP Rate Limiting & Block List:** Automatic connection tracking; manually block IPs from the dashboard.
- **🐳 Zero-Config Docker:** Full honeypot + dashboard in 5 seconds.

## ⚡ Quickstart

### Docker (Recommended)

```bash
docker run -d \
  --name baitbox \
  -p 2222:2222 \
  -p 2323:2323 \
  -p 8000:8000 \
  ghcr.io/qylen/baitbox:latest
```

Open **http://localhost:8000** to see the dashboard.

### Python

```bash
git clone https://github.com/qylen/baitbox.git
cd baitbox
pip install -r requirements.txt
python -m baitbox.main
```

## 🧪 Test It

**SSH Honeypot:**
```bash
ssh root@localhost -p 2222
# Enter any password (e.g. admin123)
# Try: ls -la, cat /root/secrets.txt, cat /var/www/html/.env, grep DB_PASS /root/.bashrc
```

**Telnet Honeypot:**
```bash
telnet localhost 2323
# Enter any username/password
```

**HTTP Decoys:**
```bash
curl http://localhost:8000/wp-admin
curl http://localhost:8000/.env
curl http://localhost:8000/.git/config
```

Then open **http://localhost:8000** and watch your actions appear on the dashboard in real-time.

## ⚙️ Configuration

All settings are via environment variables:

| Variable | Default | Description |
|---|---|---|
| `BAITBOX_SSH_HOST` | `0.0.0.0` | SSH honeypot bind address |
| `BAITBOX_SSH_PORT` | `2222` | SSH honeypot port |
| `BAITBOX_DASHBOARD_HOST` | `0.0.0.0` | Dashboard bind address |
| `BAITBOX_DASHBOARD_PORT` | `8000` | Dashboard port |
| `BAITBOX_TELNET_PORT` | `2323` | Telnet honeypot port |
| `BAITBOX_TELNET_ENABLED` | `1` | Set to `0` to disable Telnet |
| `BAITBOX_DB` | `baitbox.db` | SQLite database path |
| `BAITBOX_MAX_EVENTS` | `100` | Max events kept client-side |
| `BAITBOX_SSH_HOST_KEY` | _(empty)_ | Path to RSA host key (auto-generated if empty) |
| `BAITBOX_SSH_BACKLOG` | `100` | TCP listen backlog |
| `BAITBOX_SSH_CHANNEL_TIMEOUT` | `20` | SSH channel idle timeout (seconds) |
| `BAITBOX_SSH_HOSTNAME` | `web-prod-01` | Fake hostname shown in SSH banner/prompt |
| `BAITBOX_GEOIP_ENABLED` | `1` | Set to `0` to disable server-side GeoIP lookups |
| `BAITBOX_WEBHOOK_URL` | _(empty)_ | Discord/Slack webhook URL |
| `BAITBOX_WEBHOOK_TYPE` | `discord` | Webhook format: `discord`, `slack`, or `generic` |

## 🌐 API Endpoints

| Endpoint | Description |
|---|---|
| `GET /api/events?limit=100` | Recent events (oldest-to-newest) with server-side GeoIP enrichment |
| `GET /api/stats` | Aggregate stats: totals, protocol splits, top IPs, passwords, HTTP paths, hourly timeline, blocked IPs |
| `GET /api/sessions` | Active SSH sessions with GeoIP data |
| `POST /api/sessions/{id}/kill` | Terminate an SSH session |
| `POST /api/block/{ip}` | Block an IP and terminate all its sessions |
| `POST /api/unblock/{ip}` | Unblock an IP |
| `GET /api/geoip/{ip}` | Server-side GeoIP lookup with threat scoring (cached 1h) |
| `WS /ws/feed` | Real-time event WebSocket feed with GeoIP enrichment |

## 🏗️ Project Structure

```text
baitbox/
├── baitbox/
│   ├── config.py          # Settings from environment variables
│   ├── db.py              # SQLite persistence
│   ├── geoip.py           # Server-side GeoIP with threat scoring
│   ├── main.py            # Entry point (starts all servers)
│   ├── pubsub.py          # Asyncio pub/sub for WebSocket broadcasting
│   ├── ratelimit.py       # IP rate limiting and block list
│   ├── sessions.py        # Active SSH session manager
│   ├── vfs.py             # Virtual filesystem for SSH honeypot
│   ├── webhooks.py        # Discord/Slack/generic webhook notifications
│   ├── servers/
│   │   ├── http_server.py # FastAPI dashboard + HTTP honeypot
│   │   ├── ssh_server.py  # Paramiko SSH honeypot (50+ commands)
│   │   └── telnet_server.py # Asyncio Telnet honeypot
│   └── static/
│       └── index.html     # Premium single-page dashboard
├── tests/
│   ├── test_db.py
│   ├── test_ratelimit.py  # NEW: Rate limiter tests
│   ├── test_ssh_server.py # 40+ SSH command tests
│   └── test_vfs.py        # 50+ VFS tests
├── Dockerfile
├── requirements.txt
└── README.md
```

## ⚠️ Disclaimer

BaitBox is intended for **educational and research purposes only**. Deploy only on isolated machines or behind a strict firewall. The maintainers are not responsible for any misuse or damage. Ensure you comply with all applicable laws in your jurisdiction.

## 📄 License

MIT — see `LICENSE` for details.
