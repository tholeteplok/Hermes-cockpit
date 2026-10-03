#!/usr/bin/env python3
"""
Hermes Mobile Cockpit (PWA)
===========================
Zero-external-dependency mission control web dashboard for Hermes Agent.
Runs on any host PC (Windows, Linux, macOS, WSL) and accessed via mobile browser.

Features:
- Universal multi-host & multi-PC dynamic node switcher (Tailscale IP).
- Live Agent status & turn heartbeat.
- Emergency Kill Switch (/busy interrupt & gateway stop).
- Tool Execution Stream with Client-Side Secret Redaction.
- Cron Jobs monitor with non-blocking Pause / Resume / Run Now.
- Output Markdown pratinjau.
- PWA manifest with standalone display support.
"""

import os
import sys
import json
import glob
import re
import html
import socket
import platform
import argparse
import subprocess
import threading
import time
from urllib.parse import urlparse, parse_qs
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime

# --- Universal Hermes Directory Resolver ---
def resolve_hermes_dir(custom_path=None):
    if custom_path and os.path.isdir(custom_path):
        return os.path.abspath(custom_path)
    
    env_dir = os.environ.get("HERMES_HOME")
    if env_dir and os.path.isdir(env_dir):
        return os.path.abspath(env_dir)
        
    system = platform.system()
    if system == "Windows":
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            candidate = os.path.join(local_app_data, "hermes")
            if os.path.isdir(candidate):
                return candidate
    
    # Unix / Linux / macOS / WSL fallback
    candidate = os.path.expanduser("~/.hermes")
    if os.path.isdir(candidate):
        return candidate
        
    # Return best guess
    return os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "hermes")


HERMES_DIR = resolve_hermes_dir()
HOSTNAME = socket.gethostname()

# --- Secret Redaction Engine ---
SECRET_PATTERNS = [
    re.compile(r'(sk-[a-zA-Z0-9_\-]{20,})', re.IGNORECASE),
    re.compile(r'(ghp_[a-zA-Z0-9]{20,})', re.IGNORECASE),
    re.compile(r'(Bearer\s+[a-zA-Z0-9_\-\.]{20,})', re.IGNORECASE),
    re.compile(r'(AIza[0-9A-Za-z-_]{35})', re.IGNORECASE),
    re.compile(r'((?:api[_-]?key|secret|password|auth_token)\s*[:=]\s*["\']?)([^"\'\s]{8,})', re.IGNORECASE),
]

def redact_secrets(text):
    if not text:
        return ""
    result = text
    for pat in SECRET_PATTERNS:
        result = pat.sub(r'\1***[REDACTED_SECRET]***', result)
    return result


# --- Hermes Data Readers ---
def read_heartbeat():
    hb_path = os.path.join(HERMES_DIR, "state", "gateway.heartbeat")
    if not os.path.isfile(hb_path):
        return {"status": "offline", "pid": None, "updated_at": None, "fresh": False}
    try:
        with open(hb_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        # Check freshness
        updated_str = data.get("updated_at")
        fresh = False
        if updated_str:
            try:
                # ISO parsing
                clean_ts = updated_str.replace("Z", "+00:00")
                dt = datetime.fromisoformat(clean_ts)
                fresh = (datetime.now().astimezone().timestamp() - dt.timestamp()) < 60
            except Exception:
                fresh = True
                
        return {
            "status": "online" if fresh else "stale",
            "pid": data.get("pid"),
            "port": data.get("loop_tick_tcp_port"),
            "updated_at": updated_str,
            "fresh": fresh
        }
    except Exception as e:
        return {"status": "error", "error": str(e), "fresh": False}


def read_cron_jobs():
    jobs_path = os.path.join(HERMES_DIR, "cron", "jobs.json")
    out_dir = os.path.join(HERMES_DIR, "cron", "output")
    if not os.path.isfile(jobs_path):
        return []
    try:
        with open(jobs_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            jobs = data.get("jobs", [])
    except Exception as e:
        return [{"id": "error", "name": f"Error loading jobs: {e}", "state": "error"}]

    enriched = []
    for j in jobs:
        jid = j.get("id", "")
        # Find latest markdown output
        latest_fn = ""
        latest_txt = "No output recorded yet."
        if jid:
            job_out_dir = os.path.join(out_dir, jid)
            if os.path.isdir(job_out_dir):
                files = sorted(glob.glob(os.path.join(job_out_dir, "*.md")))
                if files:
                    latest_fn = os.path.basename(files[-1])
                    try:
                        with open(files[-1], "r", encoding="utf-8", errors="replace") as out_f:
                            content = out_f.read()
                            if "## Response" in content:
                                content = content.split("## Response", 1)[1].strip()
                            latest_txt = redact_secrets(content[:3000])
                    except Exception as err:
                        latest_txt = f"Could not read output: {err}"
                        
        enriched.append({
            "id": jid,
            "name": j.get("name", "Unnamed Task"),
            "schedule": j.get("schedule_display", j.get("schedule", {}).get("display", "interval")),
            "state": j.get("state", "scheduled"),
            "last_status": j.get("last_status", "unknown"),
            "last_run_at": j.get("last_run_at", "-"),
            "next_run_at": j.get("next_run_at", "-"),
            "completed": j.get("repeat", {}).get("completed", 0),
            "latest_file": latest_fn,
            "latest_output": latest_txt
        })
    return enriched


def read_recent_tool_executions(limit=15):
    """Parses agent.log to extract recent tool execution events."""
    log_path = os.path.join(HERMES_DIR, "logs", "agent.log")
    if not os.path.isfile(log_path):
        return []
    
    events = []
    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            # Read last 200 lines
            lines = f.readlines()[-200:]
            
        tool_pattern = re.compile(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}).*?(?:Tool|tool|Executing|executing)[:\s]+([a-zA-Z0-9_\-]+)(.*)')
        
        for line in reversed(lines):
            match = tool_pattern.search(line)
            if match:
                ts, tool_name, details = match.groups()
                events.append({
                    "timestamp": ts.strip(),
                    "tool": tool_name.strip(),
                    "details": redact_secrets(details.strip()[:200])
                })
                if len(events) >= limit:
                    break
    except Exception as e:
        events.append({"timestamp": "", "tool": "log_reader_error", "details": str(e)})
        
    return events


def execute_action(op, target=None):
    """Executes a command asynchronously without blocking the web handler."""
    def _worker():
        try:
            if op in ("pause", "resume", "run") and target:
                subprocess.run(["hermes", "cron", op, target], capture_output=True, timeout=40)
            elif op == "kill":
                # Emergency stop
                subprocess.run(["hermes", "gateway", "stop"], capture_output=True, timeout=10)
        except Exception as err:
            print(f"[Action Worker Error] {op} {target}: {err}", file=sys.stderr)
            
    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()


# --- HTML Template (Obsidian Dark Theme & Centralized Design Tokens) ---
INDEX_HTML = """<!doctype html>
<html lang="id">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=0">
  <meta name="theme-color" content="#090d16">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
  <link rel="manifest" href="/manifest.json">
  <title>Hermes Mobile Cockpit</title>
  <style>
    :root {
      --bg: #090d16;
      --surface: #111827;
      --surface-elevated: #1e293b;
      --border: #334155;
      --border-subtle: #1e293b;
      --primary: #38bdf8;
      --primary-hover: #0284c7;
      --primary-dim: rgba(56, 189, 248, 0.12);
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --text-dim: #64748b;
      --status-ok: #34d399;
      --status-warn: #fbbf24;
      --status-err: #f87171;
      --radius-sm: 8px;
      --radius-md: 12px;
      --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      --font-sans: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: var(--font-sans);
      padding: 12px 14px 40px;
      line-height: 1.45;
      -webkit-tap-highlight-color: transparent;
    }

    /* Header & Universal Node Switcher */
    .header-bar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      margin-bottom: 12px;
      padding-bottom: 10px;
      border-bottom: 1px solid var(--border-subtle);
    }
    .brand {
      display: flex;
      flex-direction: column;
    }
    .brand h1 {
      font-size: 17px;
      font-weight: 800;
      letter-spacing: -0.3px;
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .brand-host {
      font-size: 11px;
      color: var(--text-dim);
      font-family: var(--font-mono);
    }

    /* Node Switcher Dropdown */
    .node-switcher-box {
      display: flex;
      align-items: center;
      gap: 6px;
    }
    select.node-select {
      background: var(--surface-elevated);
      color: var(--primary);
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      padding: 6px 10px;
      font-size: 12px;
      font-weight: 600;
      font-family: var(--font-mono);
      outline: none;
    }

    /* Kill Switch Button */
    .btn-kill {
      background: rgba(248, 113, 113, 0.15);
      color: var(--status-err);
      border: 1.2px solid var(--status-err);
      border-radius: var(--radius-sm);
      padding: 6px 12px;
      font-size: 12px;
      font-weight: 800;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 4px;
    }
    .btn-kill:active { background: var(--status-err); color: #fff; }

    /* Status Pill */
    .status-badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 8px;
      border-radius: 999px;
      font-size: 11px;
      font-weight: 700;
      font-family: var(--font-mono);
      background: var(--surface-elevated);
    }
    .dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--status-dim);
    }
    .dot.live { background: var(--status-ok); box-shadow: 0 0 8px var(--status-ok); }
    .dot.offline { background: var(--status-err); }

    /* Navigation Tabs */
    .tabs {
      display: flex;
      gap: 6px;
      margin: 12px 0 16px;
      overflow-x: auto;
      padding-bottom: 2px;
    }
    .tab-btn {
      background: var(--surface);
      color: var(--text-muted);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-sm);
      padding: 8px 14px;
      font-size: 13px;
      font-weight: 600;
      white-space: nowrap;
      cursor: pointer;
    }
    .tab-btn.active {
      background: var(--primary-dim);
      color: var(--primary);
      border-color: var(--primary);
    }

    /* Cards */
    .card {
      background: var(--surface);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-md);
      padding: 14px;
      margin-bottom: 12px;
    }
    .card-title {
      font-size: 15px;
      font-weight: 700;
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 6px;
    }
    .card-meta {
      font-size: 12px;
      color: var(--text-muted);
      font-family: var(--font-mono);
      margin-bottom: 10px;
    }

    /* Action Buttons */
    .btn-group {
      display: flex;
      gap: 8px;
      margin: 10px 0;
    }
    .btn {
      background: var(--surface-elevated);
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      padding: 7px 12px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      flex: 1;
      text-align: center;
    }
    .btn:active { background: var(--primary); color: #000; }
    .btn-run { border-color: var(--primary); color: var(--primary); }

    /* Code & Output Blocks */
    pre.output-box {
      background: #060911;
      border: 1px solid #1e293b;
      border-radius: var(--radius-sm);
      padding: 10px;
      font-family: var(--font-mono);
      font-size: 12px;
      color: #cbd5e1;
      white-space: pre-wrap;
      word-break: break-all;
      max-height: 240px;
      overflow-y: auto;
      margin-top: 8px;
    }

    /* Secret Redaction Banner */
    .redact-pill {
      display: inline-block;
      background: rgba(248, 113, 113, 0.15);
      color: var(--status-err);
      font-size: 10px;
      padding: 2px 6px;
      border-radius: 4px;
      margin-bottom: 4px;
    }

    /* Tool Stream Timeline */
    .tool-item {
      border-left: 2px solid var(--primary);
      padding-left: 10px;
      margin-bottom: 12px;
    }
    .tool-header {
      font-size: 13px;
      font-weight: 700;
      color: var(--primary);
      display: flex;
      justify-content: space-between;
    }
    .tool-time {
      font-size: 11px;
      color: var(--text-dim);
      font-family: var(--font-mono);
    }
    .tool-cmd {
      font-family: var(--font-mono);
      font-size: 12px;
      color: var(--text-muted);
      margin-top: 2px;
    }

    /* Toast Notification */
    #toast {
      position: fixed;
      bottom: 20px;
      left: 50%;
      transform: translateX(-50%);
      background: var(--surface-elevated);
      color: var(--text);
      border: 1px solid var(--primary);
      padding: 8px 16px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 600;
      opacity: 0;
      pointer-events: none;
      transition: opacity 0.3s;
      z-index: 9999;
      box-shadow: 0 4px 14px rgba(0,0,0,0.5);
    }
    #toast.show { opacity: 1; }
  </style>
</head>
<body>

  <!-- Header Bar -->
  <div class="header-bar">
    <div class="brand">
      <h1>HERMES COCKPIT</h1>
      <span class="brand-host" id="host-label">HOST: LOADING...</span>
    </div>
    
    <div class="node-switcher-box">
      <select class="node-select" id="node-selector" onchange="onNodeSwitch(this.value)">
        <option value="">Switch PC...</option>
      </select>
      <button class="btn-kill" onclick="triggerKill()">KILL</button>
    </div>
  </div>

  <!-- Gateway Status Banner -->
  <div class="card" style="display:flex; align-items:center; justify-content:space-between; padding:10px 14px;">
    <div style="display:flex; align-items:center; gap:8px;">
      <div class="dot" id="gateway-dot"></div>
      <span style="font-size:13px; font-weight:700;" id="gateway-text">Checking Agent...</span>
    </div>
    <div class="status-badge" id="ping-badge">SYNCING</div>
  </div>

  <!-- Tab Bar -->
  <div class="tabs">
    <button class="tab-btn active" onclick="switchTab('cron')">CRON TASKS</button>
    <button class="tab-btn" onclick="switchTab('tools')">TOOL STREAM</button>
    <button class="tab-btn" onclick="switchTab('nodes')">PC NODES</button>
  </div>

  <!-- View 1: Cron Jobs -->
  <div id="view-cron">
    <div id="cron-container">
      <div style="text-align:center; padding:20px; color:var(--text-dim);">Loading Cron Jobs...</div>
    </div>
  </div>

  <!-- View 2: Tool Execution Stream -->
  <div id="view-tools" style="display:none;">
    <div class="card">
      <div class="card-title">
        <span>Anti Black-Box Stream</span>
        <span class="redact-pill">SECRETS MASKED</span>
      </div>
      <div id="tools-container">
        <div style="text-align:center; padding:20px; color:var(--text-dim);">Listening for tool executions...</div>
      </div>
    </div>
  </div>

  <!-- View 3: PC Nodes Manager -->
  <div id="view-nodes" style="display:none;">
    <div class="card">
      <div class="card-title">Add Hermes PC (Tailscale)</div>
      <p style="font-size:12px; color:var(--text-muted); margin-bottom:12px;">
        Simpan alamat IP Tailscale PC lain agar Anda bisa berpindah agen secara instan dari ponsel ini.
      </p>
      <input type="text" id="node-name" placeholder="Nama PC (contoh: PC Kantor)" style="width:100%; padding:10px; background:var(--surface-elevated); border:1px solid var(--border); border-radius:var(--radius-sm); color:#fff; font-size:13px; margin-bottom:8px;">
      <input type="text" id="node-url" placeholder="http://100.x.y.z:8080" style="width:100%; padding:10px; background:var(--surface-elevated); border:1px solid var(--border); border-radius:var(--radius-sm); color:#fff; font-size:13px; margin-bottom:12px;">
      <button class="btn btn-run" onclick="addNode()" style="width:100%;">SIMPAN PC KE DAFTAR</button>
      
      <div style="margin-top:16px;">
        <h4 style="font-size:13px; margin-bottom:8px; color:var(--text-muted);">Daftar PC Tersimpan:</h4>
        <div id="node-list"></div>
      </div>
    </div>
  </div>

  <!-- Toast Notification -->
  <div id="toast">Aksi Berhasil Dikirim</div>

  <script>
    let currentTab = 'cron';
    let nodes = JSON.parse(localStorage.getItem('hermes_nodes') || '[]');

    function showToast(msg) {
      const t = document.getElementById('toast');
      t.innerText = msg;
      t.classList.add('show');
      setTimeout(() => t.classList.remove('show'), 2500);
    }

    function switchTab(tab) {
      currentTab = tab;
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      event.target.classList.add('active');
      document.getElementById('view-cron').style.display = tab === 'cron' ? 'block' : 'none';
      document.getElementById('view-tools').style.display = tab === 'tools' ? 'block' : 'none';
      document.getElementById('view-nodes').style.display = tab === 'nodes' ? 'block' : 'none';
      if (tab === 'nodes') renderNodeList();
    }

    // --- State Polling ---
    async function fetchState() {
      try {
        const res = await fetch('/api/state');
        if (!res.ok) throw new Error('Network error');
        const data = await res.json();
        
        // Host label
        document.getElementById('host-label').innerText = `HOST: ${data.hostname} · ${data.platform}`;
        
        // Gateway status
        const dot = document.getElementById('gateway-dot');
        const txt = document.getElementById('gateway-text');
        const badge = document.getElementById('ping-badge');
        
        if (data.heartbeat.fresh) {
          dot.className = 'dot live';
          txt.innerText = `GATEWAY ONLINE (PID ${data.heartbeat.pid || '?'})`;
          badge.innerText = 'HEALTHY';
          badge.style.color = 'var(--status-ok)';
        } else {
          dot.className = 'dot offline';
          txt.innerText = 'GATEWAY IDLE / OFFLINE';
          badge.innerText = 'OFFLINE';
          badge.style.color = 'var(--status-err)';
        }

        // Render Cron
        renderCronJobs(data.cron_jobs);
        
        // Render Tools
        renderTools(data.tools);
      } catch (err) {
        document.getElementById('gateway-text').innerText = 'CONNECTING TO PC...';
        document.getElementById('ping-badge').innerText = 'RETRYING';
      }
    }

    function renderCronJobs(jobs) {
      if (!jobs || jobs.length === 0) {
        document.getElementById('cron-container').innerHTML = '<div class="card" style="text-align:center; color:var(--text-dim);">No active cron tasks found.</div>';
        return;
      }

      let html = '';
      for (const j of jobs) {
        const isOk = j.last_status === 'ok';
        const stClass = isOk ? 'color:var(--status-ok)' : 'color:var(--status-err)';
        
        html += `
        <div class="card">
          <div class="card-title">
            <span>${escapeHtml(j.name)}</span>
            <span style="${stClass}; font-size:12px; font-family:var(--font-mono);">${j.last_status.toUpperCase()}</span>
          </div>
          <div class="card-meta">
            ${j.id} · ${j.schedule} · next: ${j.next_run_at}
          </div>
          
          <div class="btn-group">
            <button class="btn" onclick="sendAction('pause', '${j.id}')">Pause</button>
            <button class="btn" onclick="sendAction('resume', '${j.id}')">Resume</button>
            <button class="btn btn-run" onclick="sendAction('run', '${j.id}')">Run Now</button>
          </div>

          <div style="font-size:11px; color:var(--text-dim); margin-top:8px;">LATEST OUTPUT: ${j.latest_file || 'None'}</div>
          <pre class="output-box">${escapeHtml(j.latest_output)}</pre>
        </div>`;
      }
      document.getElementById('cron-container').innerHTML = html;
    }

    function renderTools(tools) {
      if (!tools || tools.length === 0) {
        document.getElementById('tools-container').innerHTML = '<div style="text-align:center; color:var(--text-dim); padding:16px;">No recent tool execution in log.</div>';
        return;
      }
      let html = '';
      for (const t of tools) {
        html += `
        <div class="tool-item">
          <div class="tool-header">
            <span>⚡ ${escapeHtml(t.tool)}</span>
            <span class="tool-time">${t.timestamp}</span>
          </div>
          <div class="tool-cmd">${escapeHtml(t.details)}</div>
        </div>`;
      }
      document.getElementById('tools-container').innerHTML = html;
    }

    async function sendAction(op, target) {
      showToast(`Mengirim perintah: ${op.toUpperCase()}...`);
      try {
        await fetch(`/api/action?op=${op}&target=${encodeURIComponent(target || '')}`);
        setTimeout(fetchState, 600);
      } catch (e) {
        showToast('Gagal mengirim perintah');
      }
    }

    function triggerKill() {
      if (confirm('DARURAT: Hentikan eksekusi agen sekarang?')) {
        sendAction('kill');
      }
    }

    // --- Multi-Host Node Manager ---
    function initNodeSelector() {
      const sel = document.getElementById('node-selector');
      sel.innerHTML = '<option value="">Switch PC...</option>';
      nodes.forEach((n, idx) => {
        const opt = document.createElement('option');
        opt.value = n.url;
        opt.innerText = n.name;
        sel.appendChild(opt);
      });
    }

    function onNodeSwitch(url) {
      if (!url) return;
      if (confirm(`Pindah kendali ke ${url}?`)) {
        window.location.href = url;
      }
    }

    function addNode() {
      const name = document.getElementById('node-name').value.trim();
      let url = document.getElementById('node-url').value.trim();
      if (!name || !url) {
        alert('Harap isi Nama dan URL IP PC');
        return;
      }
      if (!url.startsWith('http://') && !url.startsWith('https://')) {
        url = 'http://' + url;
      }
      nodes.push({ name, url });
      localStorage.setItem('hermes_nodes', JSON.stringify(nodes));
      document.getElementById('node-name').value = '';
      document.getElementById('node-url').value = '';
      initNodeSelector();
      renderNodeList();
      showToast('PC berhasil ditambahkan!');
    }

    function deleteNode(idx) {
      nodes.splice(idx, 1);
      localStorage.setItem('hermes_nodes', JSON.stringify(nodes));
      initNodeSelector();
      renderNodeList();
    }

    function renderNodeList() {
      const container = document.getElementById('node-list');
      if (nodes.length === 0) {
        container.innerHTML = '<div style="font-size:12px; color:var(--text-dim);">Belum ada PC lain tersimpan.</div>';
        return;
      }
      let html = '';
      nodes.forEach((n, idx) => {
        html += `
        <div style="display:flex; justify-content:space-between; align-items:center; background:var(--surface-elevated); padding:8px 12px; border-radius:var(--radius-sm); margin-bottom:6px; font-size:12px;">
          <div>
            <b>${escapeHtml(n.name)}</b><br>
            <span style="color:var(--primary); font-family:var(--font-mono);">${escapeHtml(n.url)}</span>
          </div>
          <div style="display:flex; gap:6px;">
            <button class="btn btn-run" onclick="window.location.href='${n.url}'" style="padding:4px 8px; font-size:11px;">Buka</button>
            <button class="btn" onclick="deleteNode(${idx})" style="padding:4px 8px; font-size:11px; color:var(--status-err);">Hapus</button>
          </div>
        </div>`;
      });
      container.innerHTML = html;
    }

    function escapeHtml(str) {
      if (!str) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
    }

    // Init
    initNodeSelector();
    fetchState();
    setInterval(fetchState, 3000);
  </script>
</body>
</html>
"""


# --- Request Handler ---
class CockpitHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Silent logger for clean stdout
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(INDEX_HTML.encode("utf-8"))
            return

        elif path == "/manifest.json":
            manifest = {
                "name": "Hermes Mobile Cockpit",
                "short_name": "Hermes",
                "display": "standalone",
                "start_url": "/",
                "background_color": "#090d16",
                "theme_color": "#090d16",
                "icons": []
            }
            self.send_json(manifest)
            return

        elif path == "/api/state":
            payload = {
                "hostname": HOSTNAME,
                "platform": platform.platform(),
                "hermes_dir": HERMES_DIR,
                "heartbeat": read_heartbeat(),
                "cron_jobs": read_cron_jobs(),
                "tools": read_recent_tool_executions(limit=15)
            }
            self.send_json(payload)
            return

        elif path == "/api/action":
            qs = parse_qs(parsed.query)
            op = qs.get("op", [""])[0]
            target = qs.get("target", [""])[0]
            if op:
                execute_action(op, target)
            self.send_json({"ok": True, "op": op, "target": target})
            return

        self.send_response(404)
        self.end_headers()

    def send_json(self, data):
        encoded = json.dumps(data).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(encoded)


def get_detected_ips():
    """Finds Tailscale IP (100.x.y.z) and local network IPs for convenient terminal output."""
    tailscale_ip = None
    local_ips = []
    
    # 1. Try tailscale CLI (common on Linux/Zorin OS and macOS)
    try:
        res = subprocess.run(["tailscale", "ip", "-4"], capture_output=True, text=True, timeout=2)
        if res.returncode == 0:
            candidate = res.stdout.strip().splitlines()[0].strip()
            if candidate.startswith("100."):
                tailscale_ip = candidate
    except Exception:
        pass
        
    # 2. Try socket inspection
    try:
        for ip in socket.gethostbyname_ex(socket.gethostname())[2]:
            if ip.startswith("100."):
                tailscale_ip = ip
            elif not ip.startswith("127."):
                local_ips.append(ip)
    except Exception:
        pass
        
    return tailscale_ip, local_ips


def main():
    parser = argparse.ArgumentParser(description="Hermes Mobile Cockpit")
    parser.add_argument("--port", type=int, default=8080, help="Port to bind (default: 8080)")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host to bind (default: 0.0.0.0)")
    parser.add_argument("--hermes-dir", type=str, default=None, help="Custom Hermes home directory")
    args = parser.parse_args()

    global HERMES_DIR
    if args.hermes_dir:
        HERMES_DIR = os.path.abspath(args.hermes_dir)

    ts_ip, local_ips = get_detected_ips()

    print("=" * 60)
    print(" Hermes Mobile Cockpit (Universal PWA)")
    print("=" * 60)
    print(f" Platform    : {platform.system()} ({platform.platform()})")
    print(f" Hostname    : {HOSTNAME}")
    print(f" Hermes Path : {HERMES_DIR}")
    print(f" Listening   : http://{args.host}:{args.port}")
    print("-" * 60)
    print(" Buka URL ini di browser HP Anda:")
    if ts_ip:
        print(f" -> TAILSCALE : http://{ts_ip}:{args.port}  (Direkomendasikan)")
    else:
        print(f" -> TAILSCALE : http://<IP-TAILSCALE-PC>:{args.port}")
    for lip in local_ips:
        print(f" -> LOCAL WI-FI: http://{lip}:{args.port}")
    print("=" * 60)

    server = ThreadingHTTPServer((args.host, args.port), CockpitHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[Cockpit] Shutting down...")
        server.server_close()


if __name__ == "__main__":
    main()
