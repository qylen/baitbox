
# 🪤 BaitBox

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/docker/pulls/baitbox/baitbox.svg)](https://hub.docker.com/r/baitbox/baitbox)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub Stars](https://img.shields.io/github/stars/yourusername/baitbox?style=social)](https://github.com/yourusername/baitbox)

> A lightweight, zero-config honeypot for homelabbers. Trap attackers in a fake filesystem and watch them struggle in real-time.

![BaitBox Dashboard Demo](https://via.placeholder.com/1200x400/0f172a/ffffff?text=BaitBox+Real-Time+Dashboard+GIF+Here)
*(Replace this with a GIF of your dashboard intercepting an SSH attack)*

## 🚀 Features

- **🛡️ Multi-Protocol:** Simulates SSH and HTTP endpoints.
- **🎭 Fake Filesystem:** Drops SSH attackers into a trap shell with a fake Linux filesystem. They think they have root, but they're going nowhere.
- **📊 Real-time Dashboard:** A beautiful, dark-mode web UI showing live attacks, geolocation, and charts of top brute-forced passwords.
- **🐳 Zero-Config Docker:** Spin up a full honeypot + dashboard in 5 seconds. No external databases needed.

## ⚡ Quickstart

The fastest way to deploy BaitBox is via Docker. 

```bash
docker run -d \
  --name baitbox \
  -p 2222:2222 \
  -p 8000:8000 \
  yourusername/baitbox:latest
```

**You're live!** 
- **SSH Honeypot:** Exposed on port `2222`
- **Dashboard + HTTP Honeypot:** Open your browser to `http://localhost:8000`

Watch the dashboard light up as bots start knocking on your door within minutes.


### How to Run and Test It

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run BaitBox:**
   ```bash
   python -m baitbox.main
   ```

3. **Test the HTTP Honeypot:**
   Open your browser to `http://localhost:8000`. You will see the Dashboard.
   Open a new tab to `http://localhost:8000/wp-admin`. You will see the fake admin login page. Go back to your dashboard tab, and you will see your IP logged trying to access `/wp-admin`.

4. **Test the SSH Honeypot:**
   Open a terminal and SSH into the honeypot:
   ```bash
   ssh root@localhost -p 2222
   ```
   - It will ask for a password. Type anything (e.g., `admin123`).
   - You will drop into a fake shell. Type `ls`, `whoami`, or `cat secrets.txt`.
   - Open the dashboard in your browser, and watch your commands appear in real-time on the web UI.

## 🖥️ Local Development

Want to contribute or run it without Docker? 

1. Clone the repo:
   ```bash
   git clone https://github.com/qylen/baitbox.git
   cd baitbox
   ```
2. Install dependencies (using `uv` or `pip`):
   ```bash
   pip install -r requirements.txt
   ```
3. Run BaitBox:
   ```bash
   python -m baitbox.main
   ```

## ⚙️ How It Works

### The SSH Trap
When an attacker connects to port `2222`, BaitBox accepts any username/password combination using `paramiko`. 
Instead of rejecting them, it drops them into a fake Python-based shell. 
- If they type `ls`, they see fake web files.
- If they type `cat /etc/passwd`, they see fake users.
- If they type `wget malicious.sh`, BaitBox logs the URL but fakes a successful download.
**Every single command is streamed to your dashboard.**

### The HTTP Trap
BaitBox serves fake login pages for common paths (`/wp-admin`, `/admin`, `/phpmyadmin`, and more). Requests and submitted payloads are logged to SQLite and streamed to the dashboard over WebSockets.

### Configuration
BaitBox can be configured with environment variables:

| Variable | Default | Description |
| --- | --- | --- |
| `BAITBOX_SSH_HOST` | `0.0.0.0` | SSH honeypot bind address. |
| `BAITBOX_SSH_PORT` | `2222` | SSH honeypot port. |
| `BAITBOX_DASHBOARD_HOST` | `0.0.0.0` | Dashboard/HTTP honeypot bind address. |
| `BAITBOX_DASHBOARD_PORT` | `8000` | Dashboard/HTTP honeypot port. |
| `BAITBOX_DB` | `baitbox.db` | SQLite database path. |

## 📸 Screenshots

| Live Attack Feed | Attacker Geography |
| :---: | :---: |
| ![Feed](https://via.placeholder.com/600x300/1e293b/e2e8f0?text=Live+Terminal+Feed) | ![Map](https://via.placeholder.com/600x300/1e293b/e2e8f0?text=GeoIP+Attack+Map) |

## 🤝 Contributing

Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

*Ideas for contributions: RDP honeypot, Redis honeypot, Discord webhook integration for instant alerts.*
Project Structure
```text
baitbox/
├── baitbox/
│   ├── __init__.py
│   ├── main.py
│   ├── db.py
│   ├── pubsub.py
│   ├── servers/
│   │   ├── __init__.py
│   │   ├── ssh_server.py
│   │   └── http_server.py
│   └── static/
│       └── index.html
├── Dockerfile
├── tests/
├── requirements.txt
└── README.md
```
## ⚠️ Disclaimer

BaitBox is intended for educational and research purposes only. By deploying a honeypot, you are intentionally inviting malicious traffic to your network. Ensure you are running this on an isolated machine or behind a strict firewall. The maintainers are not responsible for any damage to your systems.

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.
```

---

### Post-Launch Strategy for GitHub Trending
1. **Record a 30-second Loom/GIF:** Record your terminal as an attacker SSHes in, types `ls`, and then switch tabs to show the dashboard lighting up with their commands instantly. Put this at the top of the README.
2. **Seed the Honeypot:** Before launching, run BaitBox on a public cloud VM (DigitalOcean/AWS) for 24 hours. Take screenshots of the dashboard *already full of attacks* so the repo looks active and proven.
3. **Launch Day:** Post to `r/selfhosted`, `r/cybersecurity`, `r/homelab`, and Hacker News. Title: *"Show HN: BaitBox – A zero-config Python honeypot with a real-time dashboard"*.
