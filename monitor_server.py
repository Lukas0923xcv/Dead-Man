#!/usr/bin/env python3
"""
SecureVault Status & Dead Man's Switch Monitor Server.
Runs on a secondary port (default: 8081) and provides a clean, real-time overview of:
- 8-digit Short Code
- Mode (Normal vs. Inherited)
- Time Left until Dead Man's Switch triggers
"""

import argparse
import datetime
import json
import os
import signal
import sys
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import storage

DEFAULT_MONITOR_PORT = int(os.getenv("MONITOR_PORT", "8081"))
DEFAULT_INACTIVITY_DAYS = int(os.getenv("INACTIVITY_DAYS", "30"))
MONITOR_VERSION = "1.0.0"

MONITOR_HTML = """<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SecureVault — Dead Man's Switch Monitor</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@500;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #09090b;
      --card-bg: #141417;
      --card-subtle: #1c1c21;
      --border: #27272a;
      --border-focus: #6366f1;
      --text: #a1a1aa;
      --text-bright: #f4f4f5;
      --text-muted: #71717a;
      --accent: #6366f1;
      --normal-badge-bg: rgba(37, 99, 235, 0.15);
      --normal-badge-text: #60a5fa;
      --normal-badge-border: rgba(96, 165, 250, 0.3);
      --inherited-badge-bg: rgba(168, 85, 247, 0.15);
      --inherited-badge-text: #c084fc;
      --inherited-badge-border: rgba(192, 132, 252, 0.3);
      --urgent-badge-bg: rgba(239, 68, 68, 0.15);
      --urgent-badge-text: #f87171;
      --urgent-badge-border: rgba(248, 113, 113, 0.3);
      --success: #10b981;
    }

    [data-theme="light"] {
      --bg: #f4f5f7;
      --card-bg: #ffffff;
      --card-subtle: #f8fafc;
      --border: #e2e8f0;
      --border-focus: #4f46e5;
      --text: #475569;
      --text-bright: #0f172a;
      --text-muted: #94a3b8;
      --accent: #4f46e5;
      --normal-badge-bg: #eff6ff;
      --normal-badge-text: #1d4ed8;
      --normal-badge-border: #bfdbfe;
      --inherited-badge-bg: #faf5ff;
      --inherited-badge-text: #7e22ce;
      --inherited-badge-border: #e9d5ff;
      --urgent-badge-bg: #fef2f2;
      --urgent-badge-text: #b91c1c;
      --urgent-badge-border: #fecaca;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg);
      color: var(--text);
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      min-height: 100vh;
      padding: 32px 16px;
      display: flex;
      flex-direction: column;
      align-items: center;
    }

    .container {
      width: 100%;
      max-width: 920px;
    }

    /* Header */
    .header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--border);
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .brand-icon {
      width: 38px;
      height: 38px;
      background: linear-gradient(135deg, #6366f1, #3b82f6);
      border-radius: 10px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 20px;
      color: white;
      box-shadow: 0 4px 12px rgba(99, 102, 241, 0.35);
    }
    .brand-title {
      font-size: 18px;
      font-weight: 700;
      color: var(--text-bright);
      letter-spacing: -0.3px;
    }
    .brand-subtitle {
      font-size: 12px;
      color: var(--text-muted);
    }

    .header-controls {
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .btn {
      background: var(--card-subtle);
      color: var(--text-bright);
      border: 1px solid var(--border);
      padding: 8px 14px;
      border-radius: 8px;
      font-size: 13px;
      font-weight: 500;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      transition: all 0.15s ease;
    }
    .btn:hover {
      border-color: var(--accent);
      background: var(--card-bg);
    }

    /* Stats Grid */
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
      margin-bottom: 24px;
    }
    .stat-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 16px 18px;
    }
    .stat-label {
      font-size: 12px;
      color: var(--text-muted);
      margin-bottom: 6px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      font-weight: 600;
    }
    .stat-value {
      font-size: 24px;
      font-weight: 700;
      color: var(--text-bright);
      font-family: 'JetBrains Mono', monospace;
    }

    /* Search & Filter Bar */
    .filter-bar {
      display: flex;
      gap: 10px;
      margin-bottom: 16px;
    }
    .search-input {
      flex: 1;
      background: var(--card-bg);
      border: 1px solid var(--border);
      color: var(--text-bright);
      padding: 10px 14px;
      border-radius: 8px;
      font-size: 14px;
      font-family: inherit;
      outline: none;
      transition: border-color 0.15s ease;
    }
    .search-input:focus {
      border-color: var(--border-focus);
    }
    .select-filter {
      background: var(--card-bg);
      border: 1px solid var(--border);
      color: var(--text-bright);
      padding: 10px 14px;
      border-radius: 8px;
      font-size: 14px;
      font-family: inherit;
      outline: none;
      cursor: pointer;
    }

    /* Records List / Table */
    .table-container {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      overflow: hidden;
      box-shadow: 0 4px 20px rgba(0,0,0,0.15);
    }
    table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
    }
    th {
      background: var(--card-subtle);
      color: var(--text-muted);
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.6px;
      padding: 12px 18px;
      border-bottom: 1px solid var(--border);
    }
    td {
      padding: 14px 18px;
      border-bottom: 1px solid var(--border);
      font-size: 13px;
      vertical-align: middle;
    }
    tr:last-child td {
      border-bottom: none;
    }
    tr:hover td {
      background-color: var(--card-subtle);
    }

    /* Code Pill */
    .code-badge {
      font-family: 'JetBrains Mono', monospace;
      font-size: 15px;
      font-weight: 700;
      color: var(--text-bright);
      background: var(--card-subtle);
      padding: 4px 10px;
      border-radius: 6px;
      border: 1px solid var(--border);
      display: inline-flex;
      align-items: center;
      gap: 6px;
      letter-spacing: 1px;
    }

    /* Mode Badges */
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      padding: 4px 10px;
      border-radius: 20px;
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .badge-normal {
      background: var(--normal-badge-bg);
      color: var(--normal-badge-text);
      border: 1px solid var(--normal-badge-border);
    }
    .badge-inherited {
      background: var(--inherited-badge-bg);
      color: var(--inherited-badge-text);
      border: 1px solid var(--inherited-badge-border);
    }
    .badge-dot {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: currentColor;
    }

    /* Countdown display */
    .countdown {
      font-family: 'JetBrains Mono', monospace;
      font-size: 14px;
      font-weight: 600;
      color: var(--text-bright);
    }
    .countdown.urgent {
      color: var(--urgent-badge-text);
    }
    .countdown.inherited {
      color: var(--inherited-badge-text);
    }
    .time-subtext {
      font-size: 11px;
      color: var(--text-muted);
      margin-top: 3px;
    }

    .empty-state {
      padding: 48px 16px;
      text-align: center;
      color: var(--text-muted);
    }
    .empty-icon {
      font-size: 32px;
      margin-bottom: 12px;
    }

    .copy-btn {
      background: transparent;
      border: none;
      color: var(--text-muted);
      cursor: pointer;
      font-size: 12px;
      padding: 2px 4px;
      border-radius: 4px;
      transition: color 0.15s;
    }
    .copy-btn:hover {
      color: var(--text-bright);
    }

    /* Footer */
    .footer {
      margin-top: 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 12px;
      color: var(--text-muted);
      width: 100%;
    }

    @media (max-width: 640px) {
      .table-container {
        border-radius: 8px;
      }
      th, td {
        padding: 10px 12px;
      }
      .hide-mobile {
        display: none;
      }
    }
  </style>
</head>
<body>
  <div class="container">
    <!-- Header -->
    <header class="header">
      <div class="brand">
        <div class="brand-icon">⏱</div>
        <div>
          <h1 class="brand-title">SecureVault Monitor</h1>
          <p class="brand-subtitle">Real-Time Dead Man's Switch Status Dashboard</p>
        </div>
      </div>
      <div class="header-controls">
        <button class="btn" id="refresh-btn" onclick="fetchStatus()">
          <span id="refresh-icon">🔄</span> Refresh
        </button>
        <button class="btn" id="theme-btn" onclick="toggleTheme()">☀️</button>
      </div>
    </header>

    <!-- Stats Counter Cards -->
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-label">Total Records</div>
        <div class="stat-value" id="stat-total">0</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Normal (Armed)</div>
        <div class="stat-value" id="stat-normal" style="color: var(--normal-badge-text);">0</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Inherited (Triggered)</div>
        <div class="stat-value" id="stat-inherited" style="color: var(--inherited-badge-text);">0</div>
      </div>
      <div class="stat-card hide-mobile">
        <div class="stat-label">Inactivity Window</div>
        <div class="stat-value" id="stat-window">30d</div>
      </div>
    </div>

    <!-- Search & Filter Controls -->
    <div class="filter-bar">
      <input type="text" id="search-box" class="search-input" placeholder="Filter by 8-digit code..." oninput="renderTable()">
      <select id="mode-filter" class="select-filter" onchange="renderTable()">
        <option value="all">All Modes</option>
        <option value="normal">Normal Mode</option>
        <option value="inherited">Inherited Mode</option>
      </select>
    </div>

    <!-- Main Table -->
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>8-Digit Short Code</th>
            <th>Mode</th>
            <th>Time Left (Dead Man's Switch)</th>
            <th class="hide-mobile">Last Activity / Created</th>
          </tr>
        </thead>
        <tbody id="records-tbody">
          <tr>
            <td colspan="4" class="empty-state">
              <div class="empty-icon">⏳</div>
              <div>Loading records...</div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- Footer -->
    <div class="footer">
      <span id="last-updated-text">Last updated: Just now</span>
      <span>SecureVault Monitor v1.0.0</span>
    </div>
  </div>

  <script>
    let recordsData = [];
    let timerInterval = null;

    function initTheme() {
      const saved = localStorage.getItem('sv_monitor_theme');
      if (saved) {
        document.documentElement.setAttribute('data-theme', saved);
        document.getElementById('theme-btn').textContent = saved === 'dark' ? '☀️' : '🌙';
      }
    }

    function toggleTheme() {
      const current = document.documentElement.getAttribute('data-theme') || 'dark';
      const next = current === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      localStorage.setItem('sv_monitor_theme', next);
      document.getElementById('theme-btn').textContent = next === 'dark' ? '☀️' : '🌙';
    }

    async function fetchStatus() {
      const icon = document.getElementById('refresh-icon');
      if (icon) icon.style.transform = 'rotate(180deg)';
      try {
        const res = await fetch('/api/status');
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        recordsData = data.records || [];
        
        document.getElementById('stat-total').textContent = data.total_count || recordsData.length;
        document.getElementById('stat-normal').textContent = data.normal_count || 0;
        document.getElementById('stat-inherited').textContent = data.inherited_count || 0;
        if (data.inactivity_days) {
          document.getElementById('stat-window').textContent = data.inactivity_days + 'd';
        }

        renderTable();
        document.getElementById('last-updated-text').textContent = 'Last updated: ' + new Date().toLocaleTimeString();
      } catch (err) {
        console.error('Failed fetching monitor status:', err);
      } finally {
        if (icon) {
          setTimeout(() => { icon.style.transform = 'none'; }, 300);
        }
      }
    }

    function formatTimeRemaining(seconds) {
      if (seconds <= 0) return 'Expired (Pending Trigger)';
      const s = Math.floor(seconds);
      const days = Math.floor(s / 86400);
      const hours = Math.floor((s % 86400) / 3600);
      const minutes = Math.floor((s % 3600) / 60);
      const secs = s % 60;
      
      const parts = [];
      if (days > 0) parts.push(days + 'd');
      if (hours > 0 || days > 0) parts.push(hours + 'h');
      if (minutes > 0 || hours > 0 || days > 0) parts.push(minutes + 'm');
      parts.push(secs + 's');
      return parts.join(' ');
    }

    function renderTable() {
      const tbody = document.getElementById('records-tbody');
      const search = (document.getElementById('search-box').value || '').trim().toLowerCase();
      const modeFilter = document.getElementById('mode-filter').value;
      const now = Date.now();

      const filtered = recordsData.filter(r => {
        if (search && !r.code.toLowerCase().includes(search)) return false;
        if (modeFilter !== 'all' && r.mode !== modeFilter) return false;
        return true;
      });

      if (filtered.length === 0) {
        tbody.innerHTML = `
          <tr>
            <td colspan="4" class="empty-state">
              <div class="empty-icon">📭</div>
              <div>${recordsData.length === 0 ? 'No encrypted vault records found in storage.' : 'No records match the filter criteria.'}</div>
            </td>
          </tr>
        `;
        return;
      }

      let html = '';
      for (const r of filtered) {
        const isNormal = r.mode === 'normal';
        let countdownStr = 'N/A (Inherited)';
        let isUrgent = false;

        if (isNormal) {
          if (r.deadline_at) {
            const deadlineMs = new Date(r.deadline_at).getTime();
            const diffSec = (deadlineMs - now) / 1000;
            countdownStr = formatTimeRemaining(diffSec);
            if (diffSec < 86400) isUrgent = true; // less than 24h
          } else {
            countdownStr = r.time_left_formatted || 'Active';
          }
        } else {
          countdownStr = 'Triggered (Inherited)';
        }

        const modeBadge = isNormal
          ? `<span class="badge badge-normal"><span class="badge-dot"></span>Normal</span>`
          : `<span class="badge badge-inherited"><span class="badge-dot"></span>Inherited</span>`;

        const countdownClass = !isNormal ? 'inherited' : (isUrgent ? 'urgent' : '');

        let dateDisplay = '-';
        if (r.last_active_at) {
          dateDisplay = new Date(r.last_active_at).toLocaleString();
        } else if (r.created_at) {
          dateDisplay = new Date(r.created_at).toLocaleString();
        }

        html += `
          <tr>
            <td>
              <span class="code-badge">
                ${r.code}
                <button class="copy-btn" title="Copy code" onclick="copyCode('${r.code}', this)">📋</button>
              </span>
            </td>
            <td>${modeBadge}</td>
            <td>
              <div class="countdown ${countdownClass}">${countdownStr}</div>
              <div class="time-subtext">${isNormal ? (r.deadline_at ? 'Trigger Deadline: ' + new Date(r.deadline_at).toLocaleDateString() : '') : (r.inherited_at ? 'Triggered at: ' + new Date(r.inherited_at).toLocaleDateString() : 'Key B Dispatched')}</div>
            </td>
            <td class="hide-mobile">
              <span style="color: var(--text-muted); font-size: 12px;">${dateDisplay}</span>
            </td>
          </tr>
        `;
      }
      tbody.innerHTML = html;
    }

    function copyCode(code, btn) {
      navigator.clipboard.writeText(code).then(() => {
        const orig = btn.textContent;
        btn.textContent = '✓';
        setTimeout(() => { btn.textContent = orig; }, 1200);
      });
    }

    // Live continuous countdown tick
    function startCountdownTicker() {
      if (timerInterval) clearInterval(timerInterval);
      timerInterval = setInterval(() => {
        renderTable();
      }, 1000);
    }

    // Periodic polling for new records / mode changes
    setInterval(fetchStatus, 5000);

    // Initial boot
    initTheme();
    fetchStatus();
    startCountdownTicker();
  </script>
</body>
</html>
"""


class MonitorRequestHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler for Status & Dead Man's Switch Monitoring."""

    server_version = f"SecureVaultMonitor/{MONITOR_VERSION}"

    def do_OPTIONS(self) -> None:
        """Handle CORS pre-flight."""
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:
        """Handle GET requests on the monitoring website."""
        parsed_url = urlparse(self.path)
        path = parsed_url.path.rstrip("/")

        # Route: Dashboard UI
        if path in ("", "/status", "/dashboard", "/monitor"):
            self.send_html_response(MONITOR_HTML)
            return

        # Route: JSON API
        if path in ("/api/status", "/api/records", "/json", "/status.json"):
            inactivity_days = getattr(self.server, "inactivity_days", DEFAULT_INACTIVITY_DAYS)
            storage_dir = getattr(self.server, "storage_dir", storage.DEFAULT_STORAGE_DIR)

            records = storage.get_all_vault_statuses(
                inactivity_days=inactivity_days, storage_dir=storage_dir
            )
            normal_count = sum(1 for r in records if r.get("mode") == "normal")
            inherited_count = sum(1 for r in records if r.get("mode") == "inherited")

            payload = {
                "status": "ok",
                "service": "SecureVault Dead Man's Switch Monitor",
                "version": MONITOR_VERSION,
                "inactivity_days": inactivity_days,
                "total_count": len(records),
                "normal_count": normal_count,
                "inherited_count": inherited_count,
                "records": records,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            }
            self.send_json_response(HTTPStatus.OK, payload)
            return

        # Route: Healthcheck
        if path == "/health":
            self.send_json_response(
                HTTPStatus.OK,
                {
                    "status": "healthy",
                    "service": "SecureVault Monitor",
                    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                },
            )
            return

        # 404
        self.send_json_response(
            HTTPStatus.NOT_FOUND,
            {"error": f"Endpoint '{self.path}' not found. Available endpoints: /, /status, /api/status, /health"},
        )

    def send_html_response(self, html_content: str) -> None:
        """Send an HTML response."""
        body = html_content.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def send_json_response(self, status: HTTPStatus, data: dict) -> None:
        """Send a JSON formatted response."""
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:
        """Quiet logging for monitor polling."""
        pass


class MonitorServer(ThreadingHTTPServer):
    """Custom ThreadingHTTPServer for the Monitor Site."""

    allow_reuse_address = True

    def __init__(
        self,
        server_address,
        RequestHandlerClass,
        storage_dir: str = storage.DEFAULT_STORAGE_DIR,
        inactivity_days: int = DEFAULT_INACTIVITY_DAYS,
    ):
        super().__init__(server_address, RequestHandlerClass)
        self.storage_dir = storage_dir
        self.inactivity_days = inactivity_days
        storage.ensure_storage_dir(self.storage_dir)


def start_monitor_server_thread(
    host: str = "0.0.0.0",
    port: int = DEFAULT_MONITOR_PORT,
    storage_dir: str = storage.DEFAULT_STORAGE_DIR,
    inactivity_days: int = DEFAULT_INACTIVITY_DAYS,
) -> Tuple[MonitorServer, threading.Thread]:
    """Start monitor server in a background daemon thread."""
    server_address = (host, port)
    monitor_httpd = MonitorServer(
        server_address,
        MonitorRequestHandler,
        storage_dir=storage_dir,
        inactivity_days=inactivity_days,
    )

    thread = threading.Thread(target=monitor_httpd.serve_forever, daemon=True)
    thread.start()
    return monitor_httpd, thread


def parse_arguments() -> argparse.Namespace:
    """Parse CLI arguments for standalone execution."""
    parser = argparse.ArgumentParser(
        description="SecureVault Dead Man's Switch Monitor Website"
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=DEFAULT_MONITOR_PORT,
        help=f"Port for the monitor website (default: {DEFAULT_MONITOR_PORT}, or env $MONITOR_PORT)",
    )
    parser.add_argument(
        "-H",
        "--host",
        type=str,
        default=os.getenv("HOST", "0.0.0.0"),
        help="Host address to bind to (default: 0.0.0.0)",
    )
    parser.add_argument(
        "-s",
        "--storage-dir",
        type=str,
        default=storage.DEFAULT_STORAGE_DIR,
        help=f"Directory where vault records are stored (default: {storage.DEFAULT_STORAGE_DIR})",
    )
    parser.add_argument(
        "--inactivity-days",
        type=int,
        default=DEFAULT_INACTIVITY_DAYS,
        help=f"Inactivity timeout in days (default: {DEFAULT_INACTIVITY_DAYS})",
    )
    return parser.parse_args()


def run_monitor_server() -> None:
    """Run standalone monitor server."""
    args = parse_arguments()
    server_address = (args.host, args.port)

    httpd = MonitorServer(
        server_address,
        MonitorRequestHandler,
        storage_dir=args.storage_dir,
        inactivity_days=args.inactivity_days,
    )

    def shutdown_handler(signum, frame):
        print("\nStopping monitor server...")
        httpd.server_close()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    print(f"============================================================")
    print(f"  SecureVault Dead Man's Switch Monitor v{MONITOR_VERSION}")
    print(f"  Dashboard: http://{args.host}:{args.port}/")
    print(f"  JSON API:  http://{args.host}:{args.port}/api/status")
    print(f"  Storage Directory: {args.storage_dir}")
    print(f"  Inactivity Threshold: {args.inactivity_days} Days")
    print(f"============================================================")
    print("Monitor ready. Press Ctrl+C to stop.")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        shutdown_handler(signal.SIGINT, None)


if __name__ == "__main__":
    run_monitor_server()
