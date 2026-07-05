"""
NetSniff - Network Packet Analyzer Backend
==========================================
Uses Scapy to capture live network packets and streams them to the
frontend via Server-Sent Events (SSE). FastAPI handles the HTTP layer.

PERMISSION NOTE:
  Packet sniffing requires raw socket access.
  - Linux/macOS: Run with `sudo python app.py`
  - Windows:     Run as Administrator, and install Npcap (https://npcap.com)
"""

import asyncio
import json
import os
import queue
import threading
import time
from datetime import datetime
from typing import AsyncGenerator

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from scapy.all import IP, TCP, UDP, ICMP, sniff, conf

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Ports that indicate unencrypted / sensitive traffic
UNENCRYPTED_PORTS = {
    21: "FTP",
    23: "Telnet",
    80: "HTTP",
    8080: "HTTP-Alt",
}

app = FastAPI(title="NetSniff API")

# Allow the HTML frontend (served from disk or a dev server) to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Shared state (thread-safe via a queue)
# ---------------------------------------------------------------------------

# Packets produced by the Scapy thread are placed here;
# the SSE generator drains this queue and sends events to the browser.
packet_queue: queue.Queue = queue.Queue(maxsize=500)

# Simple flag object to signal the sniffer thread to stop
class SnifferState:
    def __init__(self):
        self.running = False
        self._thread: threading.Thread | None = None
        self.stats = {"total": 0, "tcp": 0, "udp": 0, "icmp": 0, "other": 0, "warnings": 0}

    def reset_stats(self):
        self.stats = {"total": 0, "tcp": 0, "udp": 0, "icmp": 0, "other": 0, "warnings": 0}

state = SnifferState()

# ---------------------------------------------------------------------------
# Scapy packet processing
# ---------------------------------------------------------------------------

def classify_protocol(pkt) -> str:
    """Return a human-readable protocol name for a Scapy packet."""
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    return "Other"


def check_warning(pkt, proto: str) -> dict | None:
    """
    Return a warning dict if the packet uses a known unencrypted port,
    otherwise return None.
    """
    if proto not in ("TCP", "UDP"):
        return None

    layer = pkt.getlayer(TCP) or pkt.getlayer(UDP)
    if layer is None:
        return None

    for port in (layer.sport, layer.dport):
        if port in UNENCRYPTED_PORTS:
            return {"port": port, "service": UNENCRYPTED_PORTS[port]}
    return None


def process_packet(pkt):
    """
    Scapy calls this callback for every captured packet.
    We extract the fields we care about and push a dict onto the queue.
    """
    # We only analyse IP packets; skip ARP, etc.
    if not pkt.haslayer(IP):
        return

    ip_layer = pkt[IP]
    proto = classify_protocol(pkt)
    warning = check_warning(pkt, proto)
    size = len(pkt)

    # Update in-memory stats
    state.stats["total"] += 1
    state.stats[proto.lower()] = state.stats.get(proto.lower(), 0) + 1
    if warning:
        state.stats["warnings"] += 1

    packet_data = {
        "id": state.stats["total"],
        "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "src": ip_layer.src,
        "dst": ip_layer.dst,
        "proto": proto,
        "size": size,
        "warning": warning,   # None or {"port": int, "service": str}
        "stats": dict(state.stats),  # snapshot of current counters
    }

    # Drop silently if the queue is full (avoids blocking the sniffer thread)
    try:
        packet_queue.put_nowait(packet_data)
    except queue.Full:
        pass


def _sniff_worker(iface: str | None, proto_filter: str):
    """
    Runs in a background thread. Scapy's sniff() blocks until stop_filter
    returns True (i.e., state.running becomes False).
    
    `iface=None` tells Scapy to sniff on the default interface.
    The BPF filter string is OS-level and very efficient.
    """
    # Map our UI protocol names to BPF filter strings
    bpf_map = {
        "all":  "ip",
        "tcp":  "tcp",
        "udp":  "udp",
        "icmp": "icmp",
    }
    bpf = bpf_map.get(proto_filter, "ip")

    sniff(
        iface=iface,
        filter=bpf,
        prn=process_packet,                         # called for every packet
        stop_filter=lambda _: not state.running,    # stop when flag clears
        store=False,                                # don't keep packets in RAM
    )

# ---------------------------------------------------------------------------
# REST endpoints — Start / Stop
# ---------------------------------------------------------------------------

@app.post("/api/start")
def start_sniffer(iface: str | None = None, proto_filter: str = "all"):
    """Start the packet sniffer in a background thread."""
    if state.running:
        return {"status": "already_running"}

    # Flush stale packets from a previous session
    while not packet_queue.empty():
        packet_queue.get_nowait()

    state.reset_stats()
    state.running = True

    state._thread = threading.Thread(
        target=_sniff_worker,
        args=(iface, proto_filter),
        daemon=True,   # dies automatically when the main process exits
    )
    state._thread.start()
    return {"status": "started", "iface": iface or "default", "filter": proto_filter}


@app.post("/api/stop")
def stop_sniffer():
    """Signal the sniffer thread to stop."""
    state.running = False
    return {"status": "stopped", "final_stats": state.stats}


@app.get("/api/status")
def get_status():
    return {"running": state.running, "stats": state.stats}

# ---------------------------------------------------------------------------
# Server-Sent Events stream — pushes packets to the browser
# ---------------------------------------------------------------------------

async def event_generator() -> AsyncGenerator[str, None]:
    """
    Async generator that converts the thread-safe queue into SSE events.
    The browser keeps this connection open and receives a message each time
    a new packet arrives.
    """
    # Send an initial heartbeat so the browser knows the stream is alive
    yield "data: {\"type\":\"connected\"}\n\n"

    while True:
        try:
            # Poll the queue without blocking the event loop
            packet = packet_queue.get_nowait()
            payload = json.dumps({"type": "packet", "data": packet})
            yield f"data: {payload}\n\n"
        except queue.Empty:
            # Nothing yet — yield a small heartbeat comment to keep the
            # connection alive through proxies, then yield control back
            yield ": heartbeat\n\n"
            await asyncio.sleep(0.05)   # ~20 polls per second max


@app.get("/api/stream")
async def stream_packets():
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",   # disable nginx buffering if behind a proxy
        },
    )

# ---------------------------------------------------------------------------
# Serve the frontend
# ---------------------------------------------------------------------------

# Mount static assets (CSS, JS if split out); the HTML is served below
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/", response_class=HTMLResponse)
def serve_frontend():
    frontend_path = "index updated.html"
    if not os.path.exists(frontend_path):
        frontend_path = "static/index.html"

    with open(frontend_path, "r", encoding="utf-8") as f:
        return f.read()


if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=False)

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Suppress Scapy's verbose startup banner
    conf.verb = 0
    print("=" * 60)
    print("  NetSniff — Network Packet Analyzer")
    print("=" * 60)
    print("  Backend: http://127.0.0.1:8000")
    print()
    print("  ⚠  Packet sniffing needs elevated privileges:")
    print("     Linux/macOS → sudo python app.py")
    print("     Windows     → Run terminal as Administrator")
    print("=" * 60)
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning")
