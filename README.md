# NetSniff — Network Packet Analyzer

A cyberpunk-themed, real-time network packet analyzer with a Python/FastAPI
backend and a single-page browser frontend. Built for portfolio demonstration.

```
┌─────────────────────────────────────────────────────────┐
│  ◈ NETSNIFF  v1.0 // PACKET ANALYZER        ● CAPTURING │
├──────────┬──────────┬──────────┬─────────┬──────┬───────┤
│  TOTAL   │   TCP    │   UDP    │  ICMP   │OTHER │ ⚠ WARN│
│  1 204   │   873    │   298    │    11   │  22  │    4  │
├──────────┴──────────┴──────────┴─────────┴──────┴───────┤
│ #   Time        Source         Dest       Proto  Size   │
│ 1   12:01:04   192.168.1.5 → 93.184.216  TCP    64B    │
│ 2   12:01:04   10.0.0.1    → 10.0.0.255  UDP    128B   │
│ 3   12:01:05   192.168.1.5 → 104.16.0.1  TCP    52B  ⚠ │
└─────────────────────────────────────────────────────────┘
```

## Tech Stack

| Layer     | Technology                            |
|-----------|---------------------------------------|
| Backend   | Python 3.11+, FastAPI, Scapy, Uvicorn |
| Frontend  | HTML5, CSS3 (custom), Vanilla JS      |
| Streaming | Server-Sent Events (SSE)              |
| Fonts     | Rajdhani (display), Share Tech Mono  |

## Quick Start

### 1 — Install dependencies

```bash
pip install -r requirements.txt
```

> **Windows extra step:** Install [Npcap](https://npcap.com/#download) (the
> WinPcap-compatible driver that Scapy needs on Windows).

### 2 — Run the backend (elevated privileges required)

**Linux / macOS**
```bash
sudo python app.py
```

**Windows** (Run your terminal as Administrator, then)
```cmd
python app.py
```

> **Why sudo?** Packet sniffing opens a raw socket that reads every frame
> passing through your NIC — an OS-level privilege. Without root/admin the
> Scapy `sniff()` call will raise a `PermissionError`.

### 3 — Open the frontend

Navigate to **http://127.0.0.1:8000** in your browser.

Hit **▶ Start**, and packets will begin streaming in real-time.

## Project Structure

```
netsniff/
├── app.py                  # FastAPI backend + Scapy sniffer
├── index updated.html      # Main single-file frontend (HTML + CSS + JS)
├── requirements.txt        # pip dependencies
├── README.md
└── static/                 # Static assets folder
```

The backend serves the updated frontend directly from the root-level file named "index updated.html".

## Security Alerts

Any packet whose source or destination port matches one of the following
is flagged with an amber ⚠ badge:

| Port | Service  |
|------|----------|
| 21   | FTP      |
| 23   | Telnet   |
| 80   | HTTP     |
| 8080 | HTTP-Alt |

## Customisation

* **Sniff a specific interface** — call `/api/start?iface=eth0`
* **Add more unencrypted ports** — edit `UNENCRYPTED_PORTS` in `app.py`
* **Change max visible rows** — edit `MAX_ROWS` in `index.html`
