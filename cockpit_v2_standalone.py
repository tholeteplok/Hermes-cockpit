#!/usr/bin/env python3
"""Hermes Cockpit v2 Standalone - UI baru + mascot animation + security
Includes all utilities from cockpit.py merged into single executable.
Jalankan: python3 cockpit_v2_standalone.py [--token RAHASIA] [--port 8080]
"""
import os, sys, json, hmac, secrets, argparse, platform, glob, re, html, socket, subprocess, threading, time
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# === GLOBAL STATE ===
HERMES_DIR = ""
HOSTNAME = socket.gethostname()
TOKEN = ""

# === HERMES DIRECTORY RESOLVER ===
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
    candidate = os.path.expanduser("~/.hermes")
    if os.path.isdir(candidate):
        return candidate
    return os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "hermes")

# === SECRET REDACTION ===
SECRET_PATTERNS = [
    re.compile(r'(sk-[a-zA-Z0-9_\-]{20,})', re.IGNORECASE),
    re.compile(r'(ghp_[a-zA-Z0-9]{20,})', re.IGNORECASE),
    re.compile(r'(Bearer\s+[a-zA-Z0-9_\-\.]{20,})', re.IGNORECASE),
    re.compile(r'(AIza[0-9A-Za-z-_]{35})', re.IGNORECASE),
    re.compile(r'((?:api[_-]?key|secret|password|auth_token)\s*[:=]\s*["\']?)([^\"\'\s]{8,})', re.IGNORECASE),
]

def redact_secrets(text):
    if not text:
        return ""
    result = text
    for pat in SECRET_PATTERNS:
        result = pat.sub(r'\1***[REDACTED_SECRET]***', result)
    return result

# === HERMES DATA READERS ===
def read_heartbeat():
    hb_path = os.path.join(HERMES_DIR, "state", "gateway.heartbeat")
    if not os.path.isfile(hb_path):
        return {"status": "offline", "pid": None, "updated_at": None, "fresh": False}
    try:
        with open(hb_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        updated_str = data.get("updated_at")
        fresh = False
        if updated_str:
            try:
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

def read_cron_alerts(limit=25):
    out_dir = os.path.join(HERMES_DIR, "cron", "output")
    jobs_path = os.path.join(HERMES_DIR, "cron", "jobs.json")
    job_names = {}
    if os.path.isfile(jobs_path):
        try:
            with open(jobs_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                for j in data.get("jobs", []):
                    job_names[j["id"]] = j.get("name", j["id"])
        except Exception:
            pass

    if not os.path.isdir(out_dir):
        return []

    all_files = sorted(glob.glob(os.path.join(out_dir, "*", "*.md")), key=os.path.getmtime, reverse=True)
    alerts = []
    for fpath in all_files:
        try:
            parts = fpath.split(os.sep)
            jid = parts[-2]
            fname = parts[-1]
            mtime = os.path.getmtime(fpath)
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                raw = f.read()
            if "## Response" in raw:
                body = raw.split("## Response", 1)[1].strip()
            else:
                body = raw.strip()

            # Skip silent runs
            if not body or body == "[SILENT]" or body.startswith("[SILENT]"):
                continue

            # Buat summary bersih satu baris (clean metric, no LLM monologue/markdown noise)
            summary = ""
            status_level = "ok" # ok, warn, alert

            # Pola 1: Template Update Pasar 6h
            if "UPDATE PASAR CRYPTO" in body:
                status_level = "ok"
                btc_match = re.search(r"BTC\s*:\s*\$([0-9,.]+)", body)
                eth_match = re.search(r"ETH\s*:\s*\$([0-9,.]+)", body)
                if btc_match and eth_match:
                    summary = f"BTC ${btc_match.group(1)} • ETH ${eth_match.group(1)} • 7 koin tersinkron"
                else:
                    summary = "Sinkronisasi 7 koin selesai"
            # Pola 2: Alert Pergerakan Harga
            elif "ALERT PERGERAKAN HARGA" in body or "Trigger Ambang" in body:
                status_level = "alert"
                trig = re.findall(r"•\s*\*\*([A-Z]+)\*\*\s*:\s*([+\-0-9.%]+)", body)
                if trig:
                    summary = ", ".join([f"{c} {p}" for c, p in trig[:3]])
                else:
                    summary = "Pergerakan harga melampaui ambang batas"
            # Pola 3: Berita Makro / Kripto
            elif "RADAR BERITA" in body:
                status_level = "warn"
                headlines = re.findall(r"\[([A-Z]+)\]\s*([^\n]+)", body)
                valid_headlines = [h for h in headlines if "title —" not in h[1].lower() and "link +" not in h[1].lower()]
                if valid_headlines:
                    summary = f"[{valid_headlines[0][0]}] {valid_headlines[0][1][:65]}..."
                else:
                    summary = "Pemindaian radar berita makro selesai"
                        # Pola 4: Fallback / log lama (buang semua prompt/monologue, tampilkan ringkasan bersih)
            else:
                summary = ""
                # Deteksi error atau kegagalan API
                if "gagal" in body.lower() or "error" in body.lower() or "failed" in body.lower():
                    status_level = "warn"
                    summary = "Koneksi API terkendala • Menggunakan fallback"
                elif "binance" in body.lower() or "kline" in body.lower() or "coin" in body.lower():
                    status_level = "ok"
                    summary = "Pemeriksaan ambang batas 7 koin selesai"
                elif "sec" in body.lower() or "feed" in body.lower() or "rss" in body.lower():
                    status_level = "ok"
                    summary = "Sinkronisasi feed berita makro selesai"
                else:
                    status_level = "ok"
                    summary = "Eksekusi tugas terjadwal selesai"

            ts_str = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M")
            alerts.append({
                "job_id": jid,
                "job_name": job_names.get(jid, "Tugas Cron"),
                "file": fname,
                "timestamp": ts_str,
                "mtime": mtime,
                "level": status_level,
                "summary": redact_secrets(summary),
                "body": redact_secrets(body[:2000])
            })
            if len(alerts) >= limit:
                break
        except Exception:
            continue
    return alerts

def read_recent_tool_executions(limit=30):
    events = []
    # 1) Inbound & Outbound Telegram messages dari gateway.log
    gw_path = os.path.join(HERMES_DIR, "logs", "gateway.log")
    if os.path.isfile(gw_path):
        try:
            with open(gw_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()[-350:]
            im_pattern = re.compile(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}).*?inbound message.*?platform=(\S+)\s+user=(\S+)\s+chat=(\S+)\s+msg=\x27(.*?)\x27')
            for line in lines:
                match = im_pattern.search(line)
                if match:
                    ts, plat, user, chat, msg = match.groups()
                    events.append({"timestamp": ts.strip(), "tool": "telegram", "details": f"[{user}] {msg[:140]}", "src": "telegram"})
        except Exception:
            pass

    # 2) Tool executions dari agent.log (ambil 12 tool terbaru agar ada ruang untuk Telegram)
    log_path = os.path.join(HERMES_DIR, "logs", "agent.log")
    if os.path.isfile(log_path):
        try:
            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()[-350:]
            tool_pattern = re.compile(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}).*?(?:Tool|tool|Executing|executing)[:\s]+([a-zA-Z0-9_\-]+)(.*)')
            pc_events = []
            for line in lines:
                match = tool_pattern.search(line)
                if match:
                    ts, tool_name, details = match.groups()
                    pc_events.append({"timestamp": ts.strip(), "tool": tool_name.strip(), "details": redact_secrets(details.strip()[:200]), "src": "pc"})
            # Ambil maksimal 15 pc events terbaru
            events.extend(pc_events[-15:])
        except Exception as e:
            events.append({"timestamp": "", "tool": "log_reader_error", "details": str(e), "src": "pc"})

    # Urutkan kronologis terbalik (terbaru di paling atas)
    events.sort(key=lambda x: x["timestamp"], reverse=True)
    return events[:limit]

def execute_action(op, target=None):
    def _worker():
        try:
            if op in ("pause", "resume", "run") and target:
                subprocess.run(["hermes", "cron", op, target], capture_output=True, timeout=40)
            elif op == "kill":
                subprocess.run(["hermes", "gateway", "stop"], capture_output=True, timeout=10)
        except Exception as err:
            print(f"[Action Worker Error] {op} {target}: {err}", file=sys.stderr)
    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()

def get_detected_ips():
    tailscale_ip = None
    local_ips = []
    # Coba hingga 25 kali dengan jeda jika baru booting (menunggu tailscale daemon siap)
    for _ in range(25):
        try:
            res = subprocess.run(["tailscale", "ip", "-4"], capture_output=True, text=True, timeout=3)
            if res.returncode == 0:
                candidate = res.stdout.strip().splitlines()[0].strip()
                if candidate.startswith("100."):
                    tailscale_ip = candidate
                    break
        except Exception:
            pass
        time.sleep(1)
    try:
        for ip in socket.gethostbyname_ex(socket.gethostname())[2]:
            if ip.startswith("100."):
                tailscale_ip = ip
            elif not ip.startswith("127."):
                local_ips.append(ip)
    except Exception:
        pass
    return tailscale_ip, local_ips

# === IMPROVED MASCOT STATE DETECTOR ===
TOOL_CATEGORIES = {
    "search": [
        "browser_exec", "browser_vault", "web_extract", "web_search",
        "vision_analyze", "read_file", "search_files", "session_search"
    ],
    "type": [
        "execute_code", "terminal", "write_file", "patch",
        "skill_manage", "skill_view", "kanban_create", "kanban_comment",
        "kanban_request_review", "kanban_request_changes"
    ],
    "idle": [
        "kanban_show", "kanban_list", "kanban_unblock", "kanban_block",
        "cronjob_manage", "memory", "clarify", "text_to_speech"
    ]
}

def get_tool_category(tool_name):
    name_lower = str(tool_name).lower()
    for cat, patterns in TOOL_CATEGORIES.items():
        if any(p.lower() in name_lower for p in patterns):
            return cat
    if any(k in name_lower for k in ("search", "fetch", "browser", "web", "read")):
        return "search"
    if any(k in name_lower for k in ("write", "edit", "patch", "execute", "terminal")):
        return "type"
    return "idle"

def telegram_mascot_state():
    gw_path = os.path.join(HERMES_DIR, "logs", "gateway.log")
    if not os.path.isfile(gw_path):
        return {"state": "idle", "detail": "Menunggu pesan Telegram...", "age": 9999}
    
    inbound_pattern = re.compile(r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}).*?inbound message.*?platform=(\S+)\s+user=(\S+)\s+chat=(\S+)\s+msg=\x27(.*?)\x27")
    outbound_pattern = re.compile(r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}).*?(?:Sending response|response ready).*?platform=telegram")
    
    last_in = None
    last_out = None
    try:
        with open(gw_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f.readlines()[-300:]:
                m_in = inbound_pattern.search(line)
                if m_in:
                    ts, plat, user, chat, msg = m_in.groups()
                    last_in = {"ts": ts, "msg": msg, "user": user}
                m_out = outbound_pattern.search(line)
                if m_out:
                    ts = m_out.group(1)
                    last_out = {"ts": ts}
    except Exception:
        pass

    if last_in:
        try:
            ts_in = datetime.strptime(last_in["ts"], "%Y-%m-%d %H:%M:%S")
            in_age = (datetime.now() - ts_in).total_seconds()
        except Exception:
            in_age = 9999
        
        is_replying = True
        if last_out:
            try:
                ts_out = datetime.strptime(last_out["ts"], "%Y-%m-%d %H:%M:%S")
                if ts_out >= ts_in:
                    is_replying = False
            except Exception:
                pass
        
        if in_age <= 40:
            return {"state": "msg", "detail": f"Pesan: \"{last_in['msg'][:40]}\"", "age": int(in_age)}
        elif is_replying and in_age <= 300:
            return {"state": "type", "detail": f"Mengetik balasan untuk {last_in['user']}...", "age": int(in_age)}
        else:
            return {"state": "idle", "detail": f"Terakhir: \"{last_in['msg'][:35]}\"", "age": int(in_age)}

    return {"state": "idle", "detail": "Menunggu interaksi Telegram", "age": 9999}

def mascot_state():
    hb = read_heartbeat()
    if not hb.get("fresh"):
        return {"state": "err", "tool": None}
    tools = read_recent_tool_executions(10)
    pc_tools = [t for t in tools if t.get("src") == "pc"]
    if pc_tools:
        t = pc_tools[0]
        try:
            ts = datetime.strptime(t["timestamp"], "%Y-%m-%d %H:%M:%S")
            age = (datetime.now() - ts).total_seconds()
        except Exception:
            age = 9999
        if -2 <= age <= 50:
            tool_name = t["tool"]
            category = get_tool_category(tool_name)
            if "clarify" in tool_name.lower() or "approve" in tool_name.lower():
                return {"state": "ask", "tool": tool_name}
            return {"state": category, "tool": tool_name}
    return {"state": "idle", "tool": None}

# === HTML + CSS + JS ===
ICON = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512"><rect width="512" height="512" rx="112" fill="#101826"/><circle cx="256" cy="256" r="150" fill="none" stroke="#d9b26f" stroke-width="22"/><path d="M150 262h72l34-84 40 150 30-66h36" fill="none" stroke="#7fd1b9" stroke-width="22" stroke-linecap="round" stroke-linejoin="round"/></svg>'


HTML = r"""<!doctype html><html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#101826">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="Hermes">
<link rel="manifest" href="/manifest.json">
<link rel="icon" type="image/png" sizes="64x64" href="/favicon.png">
<link rel="icon" type="image/svg+xml" href="/icon.svg">
<link rel="apple-touch-icon" sizes="192x192" href="/icon-192.png">
<title>Hermes Cockpit</title><style>
:root{
  --bg:#101826;--s1:#172236;--s2:#1f2d45;--line:#2b3b57;--tx:#eee9de;--mut:#9aa7bd;--brass:#d9b26f;--ok:#7fd1b9;--warn:#f0c36a;--bad:#ff7a6b;
  --serif:"Iowan Old Style","Palatino Linotype",Georgia,serif;--sans:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;--mono:ui-monospace,Menlo,Consolas,monospace;
  --card-bg:var(--s1);--input-bg:var(--s2);--border:var(--line);--header-bg:rgba(23,34,54,0.85);
}

/* Light Theme Variables */
[data-theme="light"]{
  --bg:#f1f5f9;--s1:#ffffff;--s2:#f8fafc;--line:#cbd5e1;--tx:#0f172a;--mut:#64748b;--brass:#d97706;--ok:#059669;--warn:#d97706;--bad:#dc2626;
  --card-bg:#ffffff;--input-bg:#ffffff;--border:#e2e8f0;--header-bg:rgba(255,255,255,0.85);
}

/* System Theme (Light Mode Default Fallback) */
@media (prefers-color-scheme: light){
  [data-theme="system"]{
    --bg:#f1f5f9;--s1:#ffffff;--s2:#f8fafc;--line:#cbd5e1;--tx:#0f172a;--mut:#64748b;--brass:#d97706;--ok:#059669;--warn:#d97706;--bad:#dc2626;
    --card-bg:#ffffff;--input-bg:#ffffff;--border:#e2e8f0;--header-bg:rgba(255,255,255,0.85);
  }
}
*{box-sizing:border-box;margin:0;padding:0}html,body{background:var(--bg);color:var(--tx);font:15px/1.5 var(--sans);-webkit-tap-highlight-color:transparent}
body{padding:env(safe-area-inset-top) 16px calc(140px + env(safe-area-inset-bottom))}
button{font:inherit;color:inherit;border:0;background:none;cursor:pointer}button:focus-visible,input:focus-visible{outline:2px solid var(--brass);outline-offset:2px}
.hero{margin:0 0 16px;text-align:center}
.ring{width:132px;height:132px;margin:0 auto 14px;border-radius:50%;border:3px solid var(--line);display:grid;place-items:center;position:relative}
.ring::after{content:"";position:absolute;inset:-3px;border-radius:50%;border:3px solid var(--c,var(--line));opacity:.9}
.live .ring::after{animation:pulse 2.4s ease-out infinite}
@keyframes pulse{0%{transform:scale(1);opacity:.9}100%{transform:scale(1.28);opacity:0}}
.ring svg{width:58px;height:58px;stroke:var(--c,var(--mut));fill:none;stroke-width:2.4;stroke-linecap:round;stroke-linejoin:round}
.hero h1{font:600 26px/1.2 var(--serif)}.hero p{color:var(--mut);margin-top:4px;font-size:14px}
.hero.live{--c:var(--ok)}.hero.stale{--c:var(--warn)}.hero.off{--c:var(--bad)}
.kill{margin:16px auto 0;position:relative;overflow:hidden;padding:11px 22px;border-radius:999px;border:1.5px solid var(--bad);color:var(--bad);font-weight:600;font-size:14px;touch-action:none;user-select:none}
.kill i{position:absolute;inset:0;background:var(--bad);transform:scaleX(0);transform-origin:left;opacity:.28}
.kill.hold i{transform:scaleX(1);transition:transform 1.2s linear}.kill span{position:relative}
.sec{font:600 13px var(--sans);color:var(--mut);margin:20px 2px 8px}
.card{background:var(--s1);border:1px solid var(--line);border-radius:14px;padding:14px;margin-bottom:12px}
.row{display:flex;align-items:center;justify-content:space-between;gap:10px}
.name{font:600 17px var(--serif)}.meta{color:var(--mut);font-size:13px;margin-top:2px}
.chip{font-size:12px;font-weight:600;padding:3px 10px;border-radius:999px;background:var(--s2);white-space:nowrap}
.chip.ok{color:var(--ok)}.chip.bad{color:var(--bad)}.chip.warn{color:var(--warn)}
.acts{display:flex;gap:8px;margin-top:12px}.b{flex:1;min-height:44px;border-radius:10px;background:var(--s2);border:1px solid var(--line);font-weight:600;font-size:14px}
.b.main{background:var(--brass);color:#1b1608;border-color:var(--brass)}.b:active{filter:brightness(1.25)}.b[disabled]{opacity:.5}
details{margin-top:12px}summary{color:var(--brass);font-size:14px;min-height:32px;cursor:pointer}
.out{background:var(--s2);color:var(--tx);border:1px solid var(--line);border-radius:10px;padding:12px 14px;margin-top:8px;max-height:300px;overflow-y:auto;font-size:13.5px;line-height:1.6;overflow-wrap:anywhere}
.out h4{font:600 15px var(--sans);color:var(--tx);margin:10px 0 4px}
.out code{font:12px var(--mono);background:rgba(0,0,0,0.25);color:var(--brass);padding:2px 6px;border-radius:4px;border:1px solid var(--line)}
.out pre{background:rgba(0,0,0,0.3);padding:10px;border-radius:6px;overflow-x:auto;margin:6px 0;font:12px/1.5 var(--mono);color:var(--tx)}
.out li{margin-left:20px;color:var(--tx)}
.out strong, .out b{color:var(--tx);font-weight:700}
[data-theme="light"] .out code{background:#f1f5f9;border-color:#cbd5e1;color:#b45309}
[data-theme="light"] .out pre{background:#f8fafc;border-color:#e2e8f0}
.tl{border-left:2px solid var(--line);margin-left:6px}.ev{position:relative;padding:0 0 16px 16px}
.ev::before{content:"";position:absolute;left:-6px;top:6px;width:10px;height:10px;border-radius:50%;background:var(--brass)}
.ev b{font:600 14px var(--mono)}.ev time{color:var(--mut);font-size:12px;margin-left:8px}.ev div{color:var(--mut);font:12.5px var(--mono);overflow-wrap:anywhere;margin-top:2px}
.empty{text-align:center;color:var(--mut);padding:28px 10px}
.sk{height:110px;border-radius:14px;margin-bottom:12px;background:linear-gradient(90deg,var(--s1),var(--s2),var(--s1));background-size:200% 100%;animation:sh 1.4s infinite}@keyframes sh{to{background-position:-200% 0}}
nav{position:fixed;left:0;right:0;bottom:0;display:flex;background:var(--s1);border-top:1px solid var(--line);padding-bottom:env(safe-area-inset-bottom)}
nav button{flex:1;padding:10px 0 9px;color:var(--mut);font-size:12px;font-weight:600;display:grid;justify-items:center;gap:2px}
nav button svg{width:22px;height:22px;stroke:currentColor;fill:none;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}nav button.on{color:var(--brass)}
input{width:100%;padding:12px;margin-bottom:8px;background:var(--input-bg);border:1px solid var(--border);border-radius:10px;color:var(--tx);font-size:15px}
#toast{position:fixed;left:50%;bottom:calc(92px + env(safe-area-inset-bottom));transform:translate(-50%,12px);background:var(--s2);border:1px solid var(--brass);padding:9px 18px;border-radius:999px;font-size:14px;opacity:0;pointer-events:none;transition:.25s;z-index:9}
#toast.show{opacity:1;transform:translate(-50%,0)}#banner{display:none;background:#3a2326;color:var(--bad);border-radius:10px;padding:8px 12px;margin-top:12px;font-size:13px}
#login{display:none;margin-top:60px}#login h1{font:600 26px var(--serif);margin-bottom:6px}#login p{color:var(--mut);margin-bottom:16px}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}



#notif-list::-webkit-scrollbar{width:4px}
#notif-list::-webkit-scrollbar-track{background:transparent}
#notif-list::-webkit-scrollbar-thumb{background:var(--line);border-radius:4px}
#notif-list::-webkit-scrollbar-thumb:hover{background:var(--mut)}


@keyframes pulseDot{
  0%,100%{ transform:scale(1); opacity:1; }
  50%{ transform:scale(1.12); opacity:0.85; }
}


/* Theme Selector Buttons */
.theme-btn{display:flex;flex-direction:column;align-items:center;gap:4px;padding:9px 6px;border-radius:10px;background:var(--s2);border:1.5px solid var(--line);color:var(--tx);cursor:pointer;transition:all .2s}
.theme-btn.active{border-color:var(--brass);background:rgba(217,178,111,0.15);color:var(--brass)}
[data-theme="light"] .theme-btn.active{background:rgba(217,119,6,0.12);border-color:#d97706}


/* Quick Action Buttons */
.qa-btn{background:var(--s2);border:1px solid var(--line);color:var(--mut);font-size:11.5px;font-weight:600;padding:5px 10px;border-radius:6px;white-space:nowrap;cursor:pointer;transition:all .2s;flex-shrink:0}
.qa-btn:hover{background:var(--s1);color:var(--tx);border-color:var(--brass)}
.qa-btn:active{transform:scale(0.97)}
#cmd-form:focus-within{border-color:var(--brass);box-shadow:0 0 12px rgba(217,178,111,0.25)}

/* Status Chips Robot & Telegram */
.stat-chip{display:inline-flex;align-items:center;gap:6px;padding:4px 12px;border-radius:999px;font-size:12px;font-weight:600;background:var(--s1);border:1px solid var(--line);color:var(--tx);transition:all .3s}
.stat-chip.busy{border-color:var(--ok);background:rgba(127,209,185,0.1);color:var(--ok)}
.stat-chip.tg-busy{border-color:#0088cc;background:rgba(0,136,204,0.12);color:#38bdf8}
.stat-chip.err{border-color:var(--bad);background:rgba(255,122,107,0.12);color:var(--bad)}
.stat-chip .chip-icon{font-size:13px;line-height:1}

/* Robot Maskot Sci-Fi & Animasi */
#cat{transform:translate(48px,146px)}.fc{transition:none}
.p{display:none}[data-p=loaf] .zz,[data-p=think] .tb,[data-p=ask] .qb,[data-p=err] .eb,[data-p=look] .mag{display:block}

/* Mata Digital & Ekspresi Visor Robot */
.eye{transform-box:fill-box;transform-origin:center;animation:digiBlink 4s infinite}
@keyframes digiBlink{0%,92%,100%{transform:scaleY(1)}96%{transform:scaleY(.1)}}
.mouth{stroke:#5eead4;transition:all .3s}
.core-light{animation:corePulse 2s ease-in-out infinite alternate}
@keyframes corePulse{0%{filter:drop-shadow(0 0 2px #5eead4);opacity:.85}100%{filter:drop-shadow(0 0 5px #5eead4);opacity:1}}
.ant-light{animation:antPulse 1.8s infinite alternate}
@keyframes antPulse{0%{opacity:.6}100%{opacity:1}}

/* Mode Standby (Tidur/Loaf) */
[data-p=loaf] .eye{animation:none;transform:scaleY(.15);opacity:.4}
[data-p=loaf] .mouth{opacity:.4}
[data-p=loaf] .core-light{animation:none;opacity:.35}
[data-p=loaf] .bodyg{transform:translateY(8px) scaleY(.86)}
[data-p=loaf] .lg{opacity:0}[data-p=loaf] .arm{opacity:0}
[data-p=loaf] .tail{animation:none}

/* Mode Mengetik/Bekerja (Type) */
[data-p=type] .arm-l{animation:robotTap .28s infinite alternate}
[data-p=type] .arm-r{animation:robotTap .28s infinite alternate .14s}
@keyframes robotTap{from{transform:translateY(0)}to{transform:translateY(-6px)}}

/* Mode Minta Persetujuan (Mendekat & Membesar di Tengah) */
[data-p=ask] .bodyg{animation:askTilt 2s ease-in-out infinite alternate}
@keyframes askTilt{0%{transform:translateY(0) rotate(-1.5deg)}100%{transform:translateY(-3px) rotate(2deg)}}
[data-p=ask] .arm-r{animation:askWave .45s ease-in-out infinite alternate;transform-origin:11px -22px}
@keyframes askWave{0%{transform:rotate(0deg)}100%{transform:rotate(-36deg) translateY(-2px)}}
[data-p=ask] .eye{animation:none;transform:scale(1.15)}

/* Layar Komputer: Menyala hanya saat sedang bekerja (state type), mati saat lainnya */
svg:not([data-state=type]) .screen-content{display:none}
svg:not([data-state=type]) .screen-bg{fill:#060d16!important}
svg:not([data-state=type]) .screen-border{fill:#223c52!important}

/* Mode Berpikir & Mencari */
[data-p=think] .bodyg{animation:tilt 2.4s ease-in-out infinite}@keyframes tilt{50%{transform:rotate(-4deg)}}
[data-p=walk] .bodyg{animation:mechaHop .32s infinite}@keyframes mechaHop{50%{transform:translateY(-3px)}}
[data-p=walk] .lg1{animation:mstep .32s infinite}[data-p=walk] .lg2{animation:mstep .32s infinite .16s}@keyframes mstep{50%{transform:translateY(-4px)}}
[data-p=look] .bodyg{animation:scanTilt 1.3s ease-in-out infinite}@keyframes scanTilt{50%{transform:translateX(3px) rotate(3deg)}}
.mag{animation:scan 1.5s ease-in-out infinite;transform-origin:26px -14px}@keyframes scan{50%{transform:rotate(-16deg)}}

/* Mode Gangguan / Error */
[data-p=err] .eye{fill:#ff7a6b!important;animation:errBlink .3s infinite alternate}
[data-p=err] .mouth{stroke:#ff7a6b!important}
[data-p=err] .core-light{fill:#ff7a6b!important;filter:drop-shadow(0 0 6px #ff7a6b)}
[data-p=err] .ant-light{fill:#ff7a6b!important}
[data-p=err] .bodyg{animation:shake .25s 4}@keyframes shake{25%{transform:translateX(-3px)}75%{transform:translateX(3px)}}
@keyframes errBlink{from{opacity:.2}to{opacity:1}}

/* Ekor Robot */
.tail{transform-origin:-10px -10px;animation:mechaWag 1.8s ease-in-out infinite alternate}
@keyframes mechaWag{to{transform:rotate(12deg)}}

/* Balon Status & Dialog */
.dots circle{animation:dot 1.4s infinite}.dots circle:nth-child(2){animation-delay:.2s}.dots circle:nth-child(3){animation-delay:.4s}@keyframes dot{50%{opacity:.25}}
.z{font:700 13px system-ui;fill:#9aa7bd;animation:fl 3s infinite}.z2{animation-delay:1.3s}@keyframes fl{0%{transform:translate(0,6px);opacity:0}30%{opacity:1}100%{transform:translate(8px,-14px);opacity:0}}
.bub{animation:bn .8s infinite alternate}@keyframes bn{to{transform:translateY(-4px)}}
.ln{transform-box:fill-box;transform-origin:left;animation:code 1.2s steps(6) infinite}@keyframes code{0%{transform:scaleX(.2)}100%{transform:scaleX(1)}}
#alarm{display:none;fill:#ff7a6b;pointer-events:none}svg[data-s=error] #alarm{display:block;animation:al 1s infinite}@keyframes al{50%{opacity:.22}0%,100%{opacity:0}}

/* Ruangan Sci-Fi */
.room{border-radius:18px;overflow:hidden;border:1px solid #33486b;background:#4f6791;box-shadow:0 8px 24px rgba(0,0,0,.35)}
.room svg{width:100%;height:auto;display:block}
.ufo-light{transition:opacity .6s ease;animation:ufoPulse 4s ease-in-out infinite alternate}
@keyframes ufoPulse{0%{opacity:.08}100%{opacity:.22}}
.blink-dot{animation:blinkDot 1.5s infinite}@keyframes blinkDot{50%{opacity:.3}}
.hero h1{margin-top:14px}

/* Lampu & Suasana Standby (Tidur) */
.room-dim{pointer-events:none;transition:opacity .8s ease;opacity:0}
svg[data-state=idle] .ufo-light{opacity:0!important;animation:none!important}
svg[data-state=idle] .ufo-dome{fill:#356762;opacity:.55;transition:fill .5s}
svg[data-state=idle] .ufo-glow{fill:#4a6e2e;transition:fill .5s}
svg[data-state=idle] .ufo-dots{fill:#223c10;transition:fill .5s}
svg[data-state=idle] .room-dim{opacity:.4}

/* Sorotan Cahaya Jendela Antariksa Saat Lampu Mati */
.window-beam{opacity:0;pointer-events:none;transition:opacity .8s ease}
svg[data-state=idle] .window-beam{opacity:.42;animation:starlightDrift 5s ease-in-out infinite alternate}
@keyframes starlightDrift{0%{opacity:.32}100%{opacity:.5}}



/* Transisi Posisi Kucing Telegram 3D Antara Ranjang & Karpet */
#tgcat{
  transition: transform 0.9s cubic-bezier(0.25, 1, 0.5, 1);
}

/* Switching Sprite 3D */
.tg-sprite-sleep, .tg-sprite-type, .tg-sprite-alert{display:none}
[data-tg=idle] .tg-sprite-sleep{display:block}
[data-tg=type] .tg-sprite-type{display:block}
[data-tg=msg] .tg-sprite-alert{display:block}

/* Animasi Napas Tidur Lembut di Ranjang */
[data-tg=idle] .tg-sprite-sleep{
  animation: tg3dSleepBreathe 3.5s infinite ease-in-out;
  transform-origin: 0px 0px;
}
@keyframes tg3dSleepBreathe{
  0%,100%{ transform: scale(1) translateY(0); }
  50%{ transform: scale(1.02, 0.97) translateY(0.5px); }
}

/* Animasi Mengambang Balas Chat di Karpet */
[data-tg=type] .tg-sprite-type{
  animation: tg3dTypeVibe 2.4s infinite ease-in-out alternate;
  transform-origin: 0px 0px;
}
@keyframes tg3dTypeVibe{
  0%,100%{ transform: translateY(0); }
  50%{ transform: translateY(-1.5px); }
}

/* Animasi Jam Weker Getar Lembut & Halus (Micro-Vibration) */
.alarm-waves{display:none}
.ringing #alarm-clock{
  animation: alarmMicroVibe 0.18s 4 alternate ease-in-out;
  transform-origin: 324px 131px;
}
.ringing .alarm-waves{
  display:block;
  animation: wavePulse 0.3s infinite alternate;
}
@keyframes alarmMicroVibe{
  0%{transform: translate(337px, 142px) rotate(-1.5deg);}
  100%{transform: translate(337px, 142px) rotate(1.5deg);}
}
@keyframes wavePulse{
  0%{opacity:.15;stroke-width:.8}
  100%{opacity:.6;stroke-width:1.2}
}

/* Animasi Zzz Kucing Tidur di Ranjang */
.tg-zzz{display:none}
[data-tg=idle] .tg-zzz{display:block}
.tg-z{animation:tgFloatZ 2.4s infinite ease-out;opacity:0}
.tg-z1{animation-delay:0s}
.tg-z2{animation-delay:0.75s}
.tg-z3{animation-delay:1.5s}
@keyframes tgFloatZ{
  0%{opacity:0;transform:translate(0,0) scale(0.6)}
  30%{opacity:0.9}
  80%{opacity:0.8}
  100%{opacity:0;transform:translate(5px,-16px) scale(1.15)}
}

/* Mode Idle Tidur Nyenyak di Ranjang */
.tg-sleep-eyes{display:none}
[data-tg=idle] .tg-eyes{display:none}
[data-tg=idle] .tg-sleep-eyes{display:block}
[data-tg=idle] .tg-face{animation:tgSleepBreath 3.2s infinite ease-in-out;transform-origin:0px 0px}
@keyframes tgSleepBreath{0%,100%{transform:scale(1) translateY(0)}50%{transform:scale(1.02, 0.98) translateY(0.5px)}}

/* Mode Mengetik Balasan (Type): Pegang HP & Balon Ngetik Muncul */
.tg-phone-grp{display:none}
.tg-buble{display:none}
[data-tg=type] .tg-arm-idle{display:none}
[data-tg=type] .tg-phone-grp{display:block}
[data-tg=type] .tg-phone-arm-l{animation:tgPhoneTap .32s infinite alternate ease-in-out;transform-origin:-3.8px -8.5px}
[data-tg=type] .tg-phone-arm-r{animation:tgPhoneTap .32s infinite alternate ease-in-out .16s;transform-origin:3.8px -8.5px}
@keyframes tgPhoneTap{0%{transform:translateY(0)}100%{transform:translateY(-1.5px) rotate(2deg)}}

[data-tg=type] .tg-buble{display:block;animation:tgBubleFloat 2.6s infinite ease-in-out;transform-origin:0px -80px}
@keyframes tgBubleFloat{0%,100%{transform:translateY(0)}50%{transform:translateY(-2px)}}

.tdot{animation:tgDotBounce .85s infinite ease-in-out}
.tdot1{animation-delay:0s}
.tdot2{animation-delay:.22s}
.tdot3{animation-delay:.44s}
@keyframes tgDotBounce{
  0%, 100%{ transform:translateY(0); opacity:0.4; }
  50%{ transform:translateY(-2.2px); opacity:1; }
}

.tg-tail{animation:tgTailWag 2.2s infinite alternate ease-in-out;transform-origin:9px -4px}
@keyframes tgTailWag{0%{transform:rotate(-5deg)}100%{transform:rotate(10deg)}}


/* Efek Siang / Malam Jendela Kokpit Berdasarkan Tema */
.porthole-night{display:block;transition:opacity .5s ease}
.porthole-day{display:none;transition:opacity .5s ease}

/* Saat Tema Terang (Light Mode): Aktifkan Jendela Siang */
[data-theme="light"] .porthole-night{display:none}
[data-theme="light"] .porthole-day{display:block}
[data-theme="light"] .window-beam polygon{fill:url(#dayBeamGrad)}

/* Saat Tema Sistem Mendeteksi Terang */
@media (prefers-color-scheme: light){
  [data-theme="system"] .porthole-night{display:none}
  [data-theme="system"] .porthole-day{display:block}
  [data-theme="system"] .window-beam polygon{fill:url(#dayBeamGrad)}
}

/* Mode Rotasi Virtual 90 Derajat (Fallback Universal) */
body.virtual-landscape {
  transform: rotate(90deg);
  transform-origin: left top;
  width: 100vh !important;
  height: 100vw !important;
  position: absolute;
  top: 0;
  left: 100vw;
  overflow-x: hidden;
}
body.virtual-landscape nav {
  width: 100vh !important;
}
</style></head><body>
<div id="login"><h1>Masuk ke Hermes</h1><p>Masukkan token yang tampil di terminal PC saat cockpit dijalankan.</p>
<input id="tk" type="password" placeholder="Token akses" autocomplete="off"><button class="b main" style="width:100%" onclick="doLogin()">Masuk</button></div>
<main id="app" style="display:none">
<!-- Top App Bar (Di Atas Visual / Scene) -->
<header style="display:flex;align-items:center;justify-content:space-between;padding:calc(10px + env(safe-area-inset-top)) 4px 12px;margin-bottom:8px">
  <div style="display:flex;align-items:center;gap:8px">
    <div style="width:28px;height:28px;border-radius:8px;background:var(--s1);border:1px solid var(--line);display:grid;place-items:center">
      <svg viewBox="0 0 24 24" style="width:16px;height:16px;stroke:var(--brass);fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>
    </div>
    <span style="font-size:14px;font-weight:700;letter-spacing:0.4px;color:var(--tx)">HERMES COCKPIT</span>
  </div>
  <div style="display:flex;align-items:center;gap:8px">
    <div id="notif-btn" onclick="toggleNotifDrawer()" title="Notifikasi & Alert" style="position:relative;background:var(--s1);border:1px solid var(--line);color:var(--tx);width:34px;height:34px;border-radius:8px;display:grid;place-items:center;cursor:pointer;transition:all .2s">
      <svg viewBox="0 0 24 24" style="width:16px;height:16px;stroke:currentColor;fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9M13.73 21a2 2 0 0 1-3.46 0"/></svg>
      <span id="notif-badge" style="display:none;position:absolute;top:-4px;right:-4px;background:#ef4444;color:#fff;font-size:10px;font-family:var(--mono);font-weight:700;min-width:16px;height:16px;border-radius:999px;padding:0 3px;line-height:16px;text-align:center;box-shadow:0 0 8px rgba(239,68,68,0.7);border:1.5px solid var(--bg);animation:pulseDot 2s infinite">0</span>
    </div>
    <div id="rotate-btn" onclick="toggleOrientation()" title="Rotasi Layar (Portrait / Landscape)" style="background:var(--s1);border:1px solid var(--line);color:var(--tx);height:34px;padding:0 10px;border-radius:8px;font-size:12px;font-weight:600;display:flex;align-items:center;gap:6px;cursor:pointer;transition:all .2s">
      <!-- Icon Rotasi Ponsel Elegan -->
      <svg id="rotate-icon" viewBox="0 0 24 24" style="width:15px;height:15px;stroke:currentColor;fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;transition:transform .3s ease">
        <path d="M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/>
        <path d="M3 3v5h5"/>
        <path d="M3 12a9 9 0 0 0 9 9 9.75 9.75 0 0 0 6.74-2.74L21 16"/>
        <path d="M16 16h5v5"/>
      </svg>
      <span id="rotate-txt">Rotasi</span>
    </div>
  </div>
</header>

<!-- Notification Slide-out Drawer (Linear / Dev-Tools Style) -->
<div id="notif-drawer-backdrop" onclick="toggleNotifDrawer(false)" style="display:none;position:fixed;inset:0;background:rgba(5,9,16,0.6);backdrop-filter:blur(4px);z-index:100;opacity:0;transition:opacity .2s"></div>
<aside id="notif-drawer" style="position:fixed;top:0;right:0;bottom:0;width:min(92vw, 420px);background:var(--s1);border-left:1px solid var(--line);z-index:101;transform:translateX(100%);transition:transform .25s cubic-bezier(0.16, 1, 0.3, 1);display:flex;flex-direction:column;box-shadow:-8px 0 32px rgba(0,0,0,0.35)">
  <!-- Header Minimalis Monokrom (Clean Drawer) -->
  <div style="padding:calc(14px + env(safe-area-inset-top)) 16px 12px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between">
    <div style="display:flex;align-items:center;gap:8px">
      <span style="font-size:13px;font-weight:600;letter-spacing:0.3px;color:var(--tx);text-transform:uppercase">Activity & Alerts</span>
      <span id="notif-drawer-count" style="font-size:11px;font-family:var(--mono);color:var(--mut);background:var(--s2);padding:2px 7px;border-radius:4px;border:1px solid var(--line)">0</span>
    </div>
    <button onclick="toggleNotifDrawer(false)" style="background:none;border:none;color:var(--mut);font-size:16px;cursor:pointer;padding:2px 6px;line-height:1;display:grid;place-items:center" title="Tutup">✕</button>
  </div>
  <!-- Feed List (Flat hairline borders, clickable rows) -->
  <div id="notif-list" style="flex:1;overflow-y:auto;padding:0">
    <div style="text-align:center;color:var(--mut);padding:36px 16px;font-size:13px">Belum ada aktivitas baru.</div>
  </div>
</aside>
<section class="hero" id="hero">
<div class="room" id="room"></div>
<h1 id="h-title">Memeriksa Hermes…</h1>
<div id="status-chips" style="display:flex;justify-content:center;gap:8px;margin:8px 0 12px;flex-wrap:wrap">
  <div id="chip-robot" class="stat-chip"><span class="chip-icon">🤖</span><span class="chip-label" id="chip-robot-txt">Robot: Siaga</span></div>
  <div id="chip-tg" class="stat-chip"><span class="chip-icon">🐱</span><span class="chip-label" id="chip-tg-txt">Telegram: Siaga</span></div>
</div>

<!-- Command Center Container -->
<div id="command-center" style="max-width:540px;margin:0 auto 16px;text-align:left">
  <!-- Interactive Prompt Input Box -->
  <form id="cmd-form" onsubmit="submitCommand(event)" style="display:flex;align-items:center;background:var(--s1);border:1.5px solid var(--line);border-radius:12px;padding:4px 6px 4px 12px;box-shadow:0 4px 16px rgba(0,0,0,0.25);transition:border-color .2s">
    <span style="color:var(--brass);font-size:14px;margin-right:8px;font-family:var(--mono);font-weight:700">></span>
    <input id="cmd-input" type="text" placeholder="Perintahkan Hermes (mis. 'Periksa sisa disk PC')..." style="flex:1;background:none;border:none;color:var(--tx);font-size:13.5px;padding:8px 0;margin:0;outline:none" autocomplete="off">
    <button type="submit" id="cmd-btn" style="background:var(--brass);color:#1b1608;font-weight:700;font-size:12px;padding:7px 14px;border-radius:8px;display:flex;align-items:center;gap:4px;flex-shrink:0;cursor:pointer;transition:opacity .2s">
      <span id="cmd-btn-txt">Kirim</span>
      <span id="cmd-spinner" style="display:none">⏳</span>
    </button>
  </form>

  <!-- Quick Action Preset Buttons -->
  <div style="display:flex;gap:6px;margin-top:8px;overflow-x:auto;padding-bottom:4px">
    <button type="button" class="qa-btn" onclick="sendPresetAction('__ACTION_SYNC_CRYPTO__', 'Sinkronkan Harga')">🔄 Update Harga Kripto</button>
    <button type="button" class="qa-btn" onclick="sendPresetAction('Ringkas berita makro ekonomi dan kripto terbaru', 'Cek Berita')">📰 Cek Berita</button>
    <button type="button" class="qa-btn" onclick="sendPresetAction('Cek status pemakaian RAM, CPU, dan sisa ruang disk PC', 'Cek Server')">💻 Status Server</button>
    <button type="button" class="qa-btn" onclick="sendPresetAction('__ACTION_CLEAR_CACHE__', 'Bersihkan Cache')">🧹 Bersihkan Cache</button>
  </div>

  <!-- Command Response Card (Collapsible) -->
  <div id="cmd-res-card" style="display:none;background:var(--s1);border:1px solid var(--line);border-radius:12px;padding:12px 14px;margin-top:10px;box-shadow:0 4px 20px rgba(0,0,0,0.3)">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px">
      <div style="font-size:11.5px;font-weight:700;color:var(--brass);display:flex;align-items:center;gap:5px">
        <span>⚡ Respons Hermes</span>
        <span id="cmd-exec-time" style="font-size:10px;font-family:var(--mono);color:var(--mut);font-weight:400"></span>
      </div>
      <button onclick="$('cmd-res-card').style.display='none'" style="color:var(--mut);font-size:14px;padding:0 4px;cursor:pointer">✕</button>
    </div>
    <div id="cmd-res-content" style="font-size:13px;line-height:1.55;color:var(--tx);max-height:280px;overflow-y:auto" class="out" style="background:var(--s2);color:var(--tx);border:1px solid var(--line);font-family:var(--sans)"></div>
  </div>
</div>

<button class="kill" id="kill"><i></i><span>Tahan untuk hentikan agen</span></button>
<div id="banner">PC tidak terjangkau. Memeriksa ulang…</div>
</section>
<div id="v-jobs"><div class="sec">Tugas terjadwal</div><div id="jobs"><div class="sk"></div><div class="sk"></div></div></div>
<div id="v-act" hidden><div class="sec">Aktivitas terbaru</div><div class="tl" id="acts"></div></div>
<div id="v-dev" hidden>
  <div class="sec">Pengaturan Sistem</div>
  
  <!-- Pemilihan Tema (Light / Dark / System) -->
  <div class="card" style="padding:14px;margin-bottom:12px">
    <div style="font-weight:600;font-size:14px;color:var(--tx);margin-bottom:4px">🎨 Tema Tampilan</div>
    <div style="font-size:12px;color:var(--mut);margin-bottom:12px">Pilih preferensi mode warna antarmuka Cockpit.</div>
    <div id="theme-selector" style="display:grid;grid-template-columns:repeat(3, 1fr);gap:8px">
      <button type="button" class="theme-btn" data-theme-val="dark" onclick="setTheme('dark')">
        <span style="font-size:16px">🌙</span>
        <span style="font-size:12px;font-weight:600">Gelap</span>
      </button>
      <button type="button" class="theme-btn" data-theme-val="light" onclick="setTheme('light')">
        <span style="font-size:16px">☀️</span>
        <span style="font-size:12px;font-weight:600">Terang</span>
      </button>
      <button type="button" class="theme-btn" data-theme-val="system" onclick="setTheme('system')">
        <span style="font-size:16px">💻</span>
        <span style="font-size:12px;font-weight:600">Sistem</span>
      </button>
    </div>
  </div>

  <!-- Pengaturan Notifikasi Web -->
  <div class="card" style="padding:14px">
    <div style="display:flex;align-items:center;justify-content:space-between;gap:12px">
      <div>
        <div style="font-weight:600;font-size:14px;color:var(--tx);display:flex;align-items:center;gap:6px">
          <span>🔔 Notifikasi Web (PWA)</span>
        </div>
        <div id="push-status-desc" style="font-size:12px;color:var(--mut);margin-top:2px">Terima pop-up notifikasi saat alert harga kripto terpicu.</div>
      </div>
      <button id="push-btn-settings" onclick="requestPushPermission()" class="b main" style="flex-shrink:0;min-height:36px;padding:0 14px;font-size:12.5px;border-radius:8px">Aktifkan</button>
    </div>
  </div>

  <!-- Info Mesin / Host Aktif -->
  <div class="sec">Perangkat Aktif</div>
  <div class="card">
    <div class="row">
      <div>
        <div class="name" id="host">-</div>
        <div class="meta" id="plat"></div>
      </div>
      <span class="chip ok">Terhubung</span>
    </div>
  </div>

  <!-- Tambah PC Node Lain -->
  <div class="sec">Daftar PC Agent Lain</div>
  <div class="card">
    <input id="nn" placeholder="Nama Mesin (mis. Laptop Kantor)">
    <input id="nu" placeholder="Alamat IP/Domain (mis. 100.x.y.z:8080)">
    <button class="b main" style="width:100%;margin-top:4px" onclick="addNode()">Simpan Perangkat</button>
  </div>
  <div id="nodes"></div>

  <!-- Sesi & Logout -->
  <div class="sec">Sesi Pengguna</div>
  <div class="card">
    <button class="b" style="width:100%;color:var(--bad);border-color:rgba(255,122,107,0.3)" onclick="logout()">Keluar dari Cockpit</button>
  </div>
</div></main>
<nav id="nav"><button class="on" data-t="jobs"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>Tugas</button>
<button data-t="act"><svg viewBox="0 0 24 24"><path d="M3 12h4l3-8 4 16 3-8h4"/></svg>Aktivitas</button>
<button data-t="dev"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>Pengaturan</button></nav>
<div id="toast"></div>
<script>
const $=id=>document.getElementById(id);let tok='demo',timer=null,nodes=[{name:'PC Kantor',url:'http://100.64.0.7:8080'}];
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function toast(m){const t=$('toast');t.textContent=m;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2200)}
function md(s){let h=esc(s).replace(/`([^`]+)`/g,'<code>$1</code>').replace(/\*\*([^*]+)\*\*/g,'<b>$1</b>');
return h.split('\n').map(l=>/^#{1,4} /.test(l)?'<h4>'+l.replace(/^#+ /,'')+'</h4>':/^\s*[-*] /.test(l)?'<li>'+l.replace(/^\s*[-*] /,'')+'</li>':l?l+'<br>':'<br>').join('')}
function rel(iso){const d=new Date(iso);if(isNaN(d))return iso&&iso!=='-'?iso:'-';let s=Math.round((d-Date.now())/1000),a=Math.abs(s),
u=a<60?[a,'dtk']:a<3600?[Math.round(a/60),'mnt']:a<86400?[Math.round(a/3600),'jam']:[Math.round(a/86400),'hari'];return s>=0?`dalam ${u[0]} ${u[1]}`:`${u[0]} ${u[1]} lalu`}
async function api(path,opt={}){const r=await fetch(path,{...opt,headers:{'Authorization':'Bearer '+tok,'Content-Type':'application/json'}});
if(r.status===401){logout(true);throw new Error('auth')}if(!r.ok)throw new Error(r.status);return r.json()}
function doLogin(){tok=$('tk').value.trim();if(!tok)return;start()}
function logout(bad){tok='';clearInterval(timer);$('app').style.display='none';$('nav').style.display='none';$('login').style.display='block';if(bad)toast('Token salah atau kedaluwarsa')}


let currentTheme = 'dark';
try {
  currentTheme = localStorage.getItem('hermes_theme') || 'dark';
} catch(e){}

function applyTheme(theme){
  currentTheme = theme;
  document.documentElement.setAttribute('data-theme', theme);
  const metaTheme = document.querySelector('meta[name="theme-color"]');
  if(metaTheme){
    metaTheme.setAttribute('content', (theme === 'light' || (theme === 'system' && window.matchMedia('(prefers-color-scheme: light)').matches)) ? '#f1f5f9' : '#101826');
  }
  // Update state tombol aktif
  document.querySelectorAll('.theme-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.themeVal === theme);
  });
}

function setTheme(theme){
  applyTheme(theme);
  try {
    localStorage.setItem('hermes_theme', theme);
  } catch(e){}
  toast({dark: 'Tema Gelap aktif', light: 'Tema Terang aktif', system: 'Tema Mengikuti Sistem'}[theme] || 'Tema diperbarui');
}

// Inisialisasi tema segera saat script dimuat
applyTheme(currentTheme);

// Listener untuk perubahan preferensi sistem jika mode system aktif
if(window.matchMedia){
  window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', () => {
    if(currentTheme === 'system') applyTheme('system');
  });
}

let isLandscapeVirtual = false;

async function toggleOrientation(){
  const isLandscape = window.innerWidth > window.innerHeight || isLandscapeVirtual;
  const targetMode = isLandscape ? 'portrait' : 'landscape';

  // 1. Coba Native Screen Orientation Lock API (Standar Aplikasi PWA / Fullscreen)
  let lockedNative = false;
  try {
    if(screen.orientation && screen.orientation.lock){
      if(!document.fullscreenElement && !document.webkitFullscreenElement){
        const el = document.documentElement;
        if(el.requestFullscreen) await el.requestFullscreen().catch(()=>{});
        else if(el.webkitRequestFullscreen) await el.webkitRequestFullscreen().catch(()=>{});
      }
      await screen.orientation.lock(targetMode === 'landscape' ? 'landscape-primary' : 'portrait-primary');
      lockedNative = true;
    }
  } catch(e) {
    // Browser mungkin menolak lock jika tanpa gesture tertentu, gunakan fallback
    lockedNative = false;
  }

  // 2. Fallback CSS Virtual Rotation (Berjalan 100% di semua browser / HP tanpa batasan OS)
  if(!lockedNative){
    isLandscapeVirtual = !isLandscapeVirtual;
    document.body.classList.toggle('virtual-landscape', isLandscapeVirtual);
  }

  updateRotateBtnUI();
  toast(targetMode === 'landscape' ? 'Layar diputar ke Landscape' : 'Layar diputar ke Portrait');
}

function updateRotateBtnUI(){
  const isLand = window.innerWidth > window.innerHeight || isLandscapeVirtual;
  const icon = $('rotate-icon');
  const txt = $('rotate-txt');
  if(icon) icon.style.transform = isLand ? 'rotate(90deg)' : 'rotate(0deg)';
  if(txt) txt.textContent = isLand ? 'Portrait' : 'Rotasi';
}

window.addEventListener('resize', updateRotateBtnUI);
if(screen.orientation){
  screen.orientation.addEventListener('change', updateRotateBtnUI);
}

let isCommandExecuting = false;

async function submitCommand(e){
  if(e) e.preventDefault();
  if(isCommandExecuting) return;
  const inp = $('cmd-input');
  if(!inp) return;
  const q = inp.value.trim();
  if(!q) return;
  executeCommandCenter(q);
}

function sendPresetAction(cmd, label){
  if(isCommandExecuting) return;
  toast('Menjalankan: ' + label + '...');
  executeCommandCenter(cmd, label);
}

async function executeCommandCenter(cmd, customLabel){
  const inp = $('cmd-input');
  const btn = $('cmd-btn');
  const btnTxt = $('cmd-btn-txt');
  const spin = $('cmd-spinner');
  const card = $('cmd-res-card');
  const out = $('cmd-res-content');
  const timeEl = $('cmd-exec-time');

  isCommandExecuting = true;
  if(btn) btn.disabled = true;
  if(btnTxt) btnTxt.textContent = 'Memproses...';
  if(spin) spin.style.display = 'inline';

  // Animasi Robot beralih ke ngetik / bekerja saat perintah dikirim
  const catEl = $('cat');
  if(catEl) catEl.dataset.p = 'type';
  const hTitle = $('h-title');
  if(hTitle) hTitle.textContent = 'Hermes bekerja';
  const chipR = $('chip-robot-txt');
  if(chipR) chipR.textContent = 'Robot: ' + (customLabel || 'Perintah Web');

  if(card){
    card.style.display = 'block';
    out.innerHTML = '<div style="color:var(--mut);font-style:italic">Sedang mengeksekusi instruksi di PC... Mohon tunggu.</div>';
    timeEl.textContent = 'Menjalankan...';
  }

  const startTime = Date.now();
  try {
    const res = await api('/api/command', {
      method: 'POST',
      body: JSON.stringify({ command: cmd })
    });
    const dur = ((Date.now() - startTime) / 1000).toFixed(1);
    timeEl.textContent = `${dur}s`;
    out.innerHTML = md(res.reply || 'Perintah selesai dieksekusi.');
    if(inp && !cmd.startsWith('__ACTION_')) inp.value = '';
    toast('Eksekusi selesai ✓');
    setTimeout(poll, 1000);
  } catch(err) {
    timeEl.textContent = 'Error';
    out.innerHTML = `<span style="color:var(--bad)">Gagal mengeksekusi: ${esc(err.message)}</span>`;
    toast('Gagal mengirim perintah');
  } finally {
    isCommandExecuting = false;
    if(btn) btn.disabled = false;
    if(btnTxt) btnTxt.textContent = 'Kirim';
    if(spin) spin.style.display = 'none';
  }
}

function start(){$('login').style.display='none';$('app').style.display='block';$('nav').style.display='flex';poll();clearInterval(timer);timer=setInterval(poll,4000)}
document.addEventListener('visibilitychange',()=>{if(!tok)return;clearInterval(timer);if(!document.hidden){poll();timer=setInterval(poll,4000)}});
document.querySelectorAll('nav button').forEach(b=>b.onclick=()=>{document.querySelectorAll('nav button').forEach(x=>x.classList.toggle('on',x===b));
['jobs','act','dev'].forEach(t=>$('v-'+t).hidden=t!==b.dataset.t);
  const heroEl = $('hero');
  if(heroEl) heroEl.style.display = (b.dataset.t === 'jobs') ? 'block' : 'none';
  if(b.dataset.t==='dev'){renderNodes();updatePushBtnUI();}
  window.scrollTo({top: 0, behavior: 'instant'});
});

let currentAlerts = [];
let lastSeenAlertMtime = 0;
let expandedAlertIdx = null;
try {
  lastSeenAlertMtime = parseFloat(localStorage.getItem('hermes_last_seen_alert') || '0');
} catch(e){}

function toggleNotifDrawer(forceState){
  const drawer = $('notif-drawer');
  const backdrop = $('notif-drawer-backdrop');
  if(!drawer || !backdrop) return;
  const isOpening = forceState !== undefined ? forceState : (drawer.style.transform === 'translateX(100%)' || !drawer.style.transform);
  if(isOpening){
    backdrop.style.display = 'block';
    setTimeout(()=>{ backdrop.style.opacity = '1'; drawer.style.transform = 'translateX(0)'; }, 10);
    if(currentAlerts.length > 0){
      lastSeenAlertMtime = currentAlerts[0].mtime;
      try { localStorage.setItem('hermes_last_seen_alert', String(lastSeenAlertMtime)); } catch(e){}
      updateNotifBadge();
    }
  } else {
    backdrop.style.opacity = '0';
    drawer.style.transform = 'translateX(100%)';
    setTimeout(()=>{ backdrop.style.display = 'none'; }, 260);
  }
}

function updateNotifBadge(){
  const badge = $('notif-badge');
  const countEl = $('notif-drawer-count');
  const unread = currentAlerts.filter(a => a.mtime > lastSeenAlertMtime).length;
  if(badge){
    if(unread > 0){
      badge.textContent = unread > 9 ? '9+' : String(unread);
      badge.style.display = 'block'; if('setAppBadge' in navigator) navigator.setAppBadge(unread).catch(()=>{});
    } else {
      badge.style.display = 'none'; if('clearAppBadge' in navigator) navigator.clearAppBadge().catch(()=>{});
    }
  }
  if(countEl){
    countEl.textContent = unread > 0 ? `${unread} new` : `${currentAlerts.length}`;
  }
}

function toggleAlertDetail(idx){
  expandedAlertIdx = expandedAlertIdx === idx ? null : idx;
  renderAlerts(currentAlerts);
}

function renderAlerts(alerts){
  if(!alerts) return;
  const prevLatest = currentAlerts.length > 0 ? currentAlerts[0].mtime : 0;
  currentAlerts = alerts;
  updateNotifBadge();

  if(prevLatest > 0 && alerts.length > 0 && alerts[0].mtime > prevLatest){
    triggerWebNotification(alerts[0].job_name, alerts[0].summary);
  }

  const container = $('notif-list');
  if(!container) return;
  if(alerts.length === 0){
    container.innerHTML = '<div style="text-align:center;color:#64748b;padding:36px 16px;font-size:13px">Belum ada aktivitas baru.</div>';
    return;
  }

  container.innerHTML = alerts.map((a, idx) => {
    const isNew = a.mtime > lastSeenAlertMtime;
    const isExpanded = expandedAlertIdx === idx;
    // Status dot color: subtle professional tones
    const dotColor = a.level === 'alert' ? '#ef4444' : a.level === 'warn' ? '#f59e0b' : '#10b981';
    
    return `<div onclick="toggleAlertDetail(${idx})" style="padding:12px 16px;border-bottom:1px solid var(--line);cursor:pointer;background:${isExpanded ? 'var(--s2)' : 'transparent'};transition:background .15s">
      <div style="display:flex;align-items:center;justify-content:space-between;gap:8px">
        <div style="display:flex;align-items:center;gap:7px;overflow:hidden">
          <span style="width:6px;height:6px;border-radius:50%;background:${dotColor};flex-shrink:0"></span>
          <span style="font-size:12.5px;font-weight:600;color:var(--tx);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(a.job_name)}</span>
          ${isNew ? '<span style="font-size:9px;color:var(--brass);background:rgba(217,119,6,0.12);padding:1px 5px;border-radius:3px;font-family:var(--mono)">NEW</span>' : ''}
        </div>
        <div style="display:flex;align-items:center;gap:6px;flex-shrink:0">
          <time style="font-size:11px;font-family:var(--mono);color:var(--mut)">${esc((a.timestamp||'').slice(11))} WIB</time>
          <span style="font-size:12px;color:var(--mut);transform:rotate(${isExpanded ? '90deg' : '0deg'});transition:transform .2s">›</span>
        </div>
      </div>
      <div style="font-size:12px;color:var(--mut);margin-top:4px;line-height:1.4">${esc(a.summary)}</div>
      ${isExpanded ? `<div class="out" style="margin-top:8px;font-size:11.5px;max-height:260px">${md(a.body)}</div>` : ''}
    </div>`;
  }).join('');
}

function requestPushPermission(){
  if(!('Notification' in window)){
    toast('Peramban tidak mendukung Web Notification');
    return;
  }
  Notification.requestPermission().then(permission => {
    updatePushBtnUI(permission);
    if(permission === 'granted'){
      toast('Notifikasi Web Aktif! 🔔');
      triggerWebNotification('Hermes Cockpit', 'Notifikasi sistem berhasil diaktifkan.');
    } else {
      toast('Izin notifikasi tidak diberikan');
    }
  });
}

function updatePushBtnUI(perm){
  const p = perm || (('Notification' in window) ? Notification.permission : 'default');
  const btnSettings = $('push-btn-settings');
  const descSettings = $('push-status-desc');
  if(!btnSettings) return;
  if(p === 'granted'){
    btnSettings.textContent = 'Aktif ✓';
    btnSettings.disabled = true;
    btnSettings.style.background = '#10b981';
    btnSettings.style.color = '#ffffff';
    btnSettings.style.borderColor = '#10b981';
    if(descSettings) descSettings.textContent = 'Notifikasi sistem peramban/PWA aktif berjalan.';
  } else if(p === 'denied'){
    btnSettings.textContent = 'Diblokir';
    btnSettings.disabled = true;
    btnSettings.style.background = 'var(--bad)';
    btnSettings.style.color = '#ffffff';
    btnSettings.style.borderColor = 'var(--bad)';
    if(descSettings) descSettings.textContent = 'Izin notifikasi diblokir pada setelan peramban ponsel Anda.';
  } else {
    btnSettings.textContent = 'Aktifkan';
    btnSettings.disabled = false;
    btnSettings.style.background = 'var(--brass)';
    btnSettings.style.color = '#1b1608';
    btnSettings.style.borderColor = 'var(--brass)';
    if(descSettings) descSettings.textContent = 'Terima pop-up notifikasi saat alert harga kripto terpicu.';
  }
}

function triggerWebNotification(title, text){
  if('Notification' in window && Notification.permission === 'granted'){
    try {
      // 1. Standar Notification API
      if(navigator.serviceWorker && navigator.serviceWorker.controller){
        navigator.serviceWorker.controller.postMessage({
          type: 'SHOW_NOTIFICATION',
          title: title || 'Hermes Alert',
          body: text || 'Aktivitas baru tercatat.'
        });
      } else {
        new Notification(title || 'Hermes Alert', {
          body: text || 'Aktivitas baru tercatat.',
          icon: '/icon-192.png',
          badge: '/icon-192.png'
        });
      }
    } catch(e){}
  }
}

// Sinkronisasi status izin tombol saat drawer dibuka
const _origToggle = toggleNotifDrawer;
toggleNotifDrawer = function(force){
  _origToggle(force);
  updatePushBtnUI();
};

async function poll(){try{const d=await api('/api/state');$('banner').style.display='none';hero(d.heartbeat);scene(d.mascot);updateTgMascot(d.tg_mascot);$('host').textContent=d.hostname;$('plat').textContent=d.platform;jobs(d.cron_jobs);acts(d.tools);renderAlerts(d.alerts)}
catch(e){if(e.message!=='auth')$('banner').style.display='block'}}

let lastHeartbeat = {fresh: true, status: 'online'};
let lastRobotMascot = {state: 'idle', tool: null};
let lastTgState = {state:'idle', detail:''};
const TG_POS = {
  bed: {x: 372, y: 146},
  carpet: {x: 220, y: 165}
};

function hero(h){
  lastHeartbeat = h || {fresh: true, status: 'online'};
  const el = $('hero');
  if(el){
    const st = lastHeartbeat.fresh ? 'live' : lastHeartbeat.status === 'stale' ? 'stale' : 'off';
    el.className = 'hero ' + st;
  }
  updateStatusDisplay();
}

function updateStatusDisplay(){
  const h = lastHeartbeat;
  const isLive = h.fresh && h.status !== 'offline';
  const rState = lastRobotMascot.state || 'idle';
  const tgState = lastTgState.state || 'idle';

  // 1. Judul utama dinamis
  const titleEl = $('h-title');
  if(titleEl){
    if(!isLive){
      titleEl.textContent = h.status === 'stale' ? 'Hermes tidak merespons' : 'Hermes mati';
    } else {
      const isBusy = (rState === 'type' || rState === 'search' || rState === 'ask') || (tgState === 'type' || tgState === 'msg');
      titleEl.textContent = isBusy ? 'Hermes bekerja' : 'Hermes siaga';
    }
  }

  // 2. Chip Status Robot (PC)
  const chipR = $('chip-robot');
  const txtR = $('chip-robot-txt');
  if(chipR && txtR){
    if(!isLive){
      chipR.className = 'stat-chip err';
      txtR.textContent = 'Robot: Terputus';
    } else if(rState === 'type'){
      chipR.className = 'stat-chip busy';
      txtR.textContent = 'Robot: ' + (lastRobotMascot.tool ? esc(lastRobotMascot.tool) : 'Mengetik');
    } else if(rState === 'search'){
      chipR.className = 'stat-chip busy';
      txtR.textContent = 'Robot: ' + (lastRobotMascot.tool ? esc(lastRobotMascot.tool) : 'Mencari');
    } else if(rState === 'ask'){
      chipR.className = 'stat-chip busy';
      txtR.textContent = 'Robot: Konfirmasi';
    } else {
      chipR.className = 'stat-chip';
      txtR.textContent = 'Robot: Siaga';
    }
  }

  // 3. Chip Status Telegram
  const chipTg = $('chip-tg');
  const txtTg = $('chip-tg-txt');
  if(chipTg && txtTg){
    if(tgState === 'type'){
      chipTg.className = 'stat-chip tg-busy';
      txtTg.textContent = 'Telegram: Mengetik balasan';
    } else if(tgState === 'msg'){
      chipTg.className = 'stat-chip tg-busy';
      txtTg.textContent = 'Telegram: Pesan masuk';
    } else {
      chipTg.className = 'stat-chip';
      txtTg.textContent = 'Telegram: Siaga';
    }
  }
}

function updateTgMascot(tg){
  if(!tg) return;
  const prevState = lastTgState.state || 'idle';
  lastTgState = tg;
  const cat = $('tgcat');
  const clockArea = $('cat-bed-area');
  if(!cat) return;
  const s = tg.state || 'idle';
  cat.dataset.tg = s;

  if(s === 'type' || s === 'msg'){
    if(prevState === 'idle' && clockArea){
      clockArea.classList.add('ringing');
      setTimeout(()=>{ clockArea.classList.remove('ringing'); }, 900);
    }
    cat.style.transform = `translate(${TG_POS.carpet.x}px, ${TG_POS.carpet.y}px)`;
  } else {
    cat.style.transform = `translate(${TG_POS.bed.x}px, ${TG_POS.bed.y}px)`;
    if(clockArea) clockArea.classList.remove('ringing');
  }

  updateStatusDisplay();
}

function jobs(list){
  if(!list||!list.length){$('jobs').innerHTML='<div class="empty">Belum ada tugas terjadwal di PC ini.</div>';return}
  const open=new Set([...document.querySelectorAll('details[open]')].map(x=>x.dataset.id));
  $('jobs').innerHTML=list.map(j=>{
    const paused=/pause/i.test(j.state),ok=j.last_status==='ok',cls=paused?'warn':ok?'ok':'bad',lbl=paused?'Dijeda':ok?'Berhasil':j.last_status==='unknown'?'Belum jalan':'Gagal';
    return `<div class="card"><div class="row"><div><div class="name">${esc(j.name)}</div><div class="meta">${esc(j.schedule)} · berikutnya ${esc(rel(j.next_run_at))}</div></div><span class="chip ${cls}">${lbl}</span></div>
    <div class="meta">Terakhir jalan ${esc(rel(j.last_run_at))} · ${j.completed}× selesai</div>
    <div class="acts"><button class="b" onclick="act('${paused?'resume':'pause'}','${esc(j.id)}',this)">${paused?'Lanjutkan':'Jeda'}</button><button class="b main" onclick="act('run','${esc(j.id)}',this)">Jalankan sekarang</button></div>
    <details data-id="${esc(j.id)}" ${open.has(j.id)?'open':''}><summary>Hasil terakhir${j.latest_file?' · '+esc(j.latest_file):''}</summary><div class="out">${md(j.latest_output)}</div></details></div>`
  }).join('');
}

function acts(t){
  $('acts').innerHTML = !t||!t.length ? '<div class="empty">Belum ada aktivitas di log.</div>' : t.map(e=>{
    const isTg = e.src === 'telegram' || e.tool === 'telegram';
    const tag = isTg ? '<span style="background:rgba(0,136,204,0.15);color:#0284c7;font-weight:600;padding:1px 6px;border-radius:4px;font-size:11px;margin-right:6px">Telegram</span>' : '<span style="background:rgba(16,185,129,0.15);color:var(--ok);font-weight:600;padding:1px 6px;border-radius:4px;font-size:11px;margin-right:6px">PC / Agent</span>';
    return `<div class="ev" style="${isTg?'--brass:#0284c7':''}">
      ${tag}<b style="color:var(--tx)">${esc(e.tool)}</b><time style="color:var(--mut)">${esc((e.timestamp||'').slice(11))}</time>
      <div style="margin-top:4px;color:var(--mut)">${esc(e.details)}</div>
    </div>`;
  }).join('');
}
async function act(op,target,btn){if(btn)btn.disabled=true;try{await api('/api/action',{method:'POST',body:JSON.stringify({op,target})});
toast({pause:'Tugas dijeda',resume:'Tugas dilanjutkan',run:'Tugas dijalankan',kill:'Agen dihentikan'}[op]);setTimeout(poll,900)}catch(e){toast('Gagal mengirim perintah')}finally{if(btn)setTimeout(()=>btn.disabled=false,1200)}}
(()=>{const k=$('kill');let t;const on=e=>{e.preventDefault();k.classList.add('hold');t=setTimeout(()=>{k.classList.remove('hold');act('kill','')},1200)};
const off=()=>{clearTimeout(t);k.classList.remove('hold')};k.addEventListener('pointerdown',on);['pointerup','pointerleave','pointercancel'].forEach(n=>k.addEventListener(n,off))})();
function renderNodes(){$('nodes').innerHTML=nodes.map((n,i)=>`<div class="card row"><div><div class="name">${esc(n.name)}</div><div class="meta">${esc(n.url)}</div></div>
<div style="display:flex;gap:6px"><button class="chip" onclick="location.href='${esc(n.url)}'">Buka</button><button class="chip bad" onclick="delNode(${i})">Hapus</button></div></div>`).join('')}
function addNode(){const name=$('nn').value.trim();let url=$('nu').value.trim();if(!name||!url)return toast('Isi nama dan alamat PC');if(!/^https?:\/\//.test(url))url='http://'+url;
nodes.push({name,url});$('nn').value=$('nu').value='';renderNodes();toast('PC disimpan')}
function delNode(i){nodes.splice(i,1);renderNodes()}
const sleep=ms=>new Promise(r=>setTimeout(r,ms));

/* Komponen Gambar Ruang Sci-Fi */
const F=(x,y,w,h,f,r=0)=>`<rect x="${x}" y="${y}" width="${w}" height="${h}" rx="${r}" fill="${f}"/>`;
const C=(x,y,r,f)=>`<circle cx="${x}" cy="${y}" r="${r}" fill="${f}"/>`;

const walls=()=>{
  let s=F(0,0,420,138,'#526b9a')+F(0,138,420,67,'#7bc4b8');
  s+=`<path d="M68 0v138 M238 0v138 M370 0v138 M0 86h238 M238 60h182" stroke="#41567d" stroke-width="1.2"/>`;
  const dots=[[4,4],[64,4],[72,4],[234,4],[242,4],[366,4],[374,4],[416,4],[4,82],[64,82],[72,82],[234,82],[4,90],[64,90],[72,90],[234,90],
              [242,56],[366,56],[374,56],[416,56],[242,64],[366,64],[374,64],[416,64],[4,134],[64,134],[72,134],[234,134],[242,134],[366,134],[374,134],[416,134]];
  dots.forEach(([x,y])=>{s+=C(x,y,1.4,'#354869')});
  return s;
};

const ufoLamp=()=>`
<g id="ufo">
  <polygon class="ufo-light" points="186,22 216,22 250,135 152,135" fill="#a6e34b"/>
  <line x1="201" y1="0" x2="201" y2="12" stroke="#3b4f73" stroke-width="1.8"/>
  <ellipse class="ufo-dome" cx="201" cy="18" rx="20" ry="12" fill="#78d5c8"/>
  <ellipse class="ufo-glow" cx="201" cy="24" rx="44" ry="11" fill="#a4df4f"/>
  <ellipse cx="201" cy="26" rx="36" ry="6" fill="#88c437"/>
  <circle class="ufo-dots" cx="180" cy="27" r="2.2" fill="#4b781a"/>
  <circle class="ufo-dots" cx="194" cy="28.5" r="2.2" fill="#4b781a"/>
  <circle class="ufo-dots" cx="208" cy="28.5" r="2.2" fill="#4b781a"/>
  <circle class="ufo-dots" cx="222" cy="27" r="2.2" fill="#4b781a"/>
</g>`;

const solarMobile=()=>`
<g id="mobile">
  <line x1="24" y1="52" x2="90" y2="52" stroke="#1f2c42" stroke-width="1.5"/>
  <line x1="32" y1="52" x2="32" y2="70" stroke="#1f2c42" stroke-width="1"/>
  <line x1="56" y1="52" x2="56" y2="60" stroke="#1f2c42" stroke-width="1"/>
  <line x1="64" y1="52" x2="64" y2="74" stroke="#1f2c42" stroke-width="1"/>
  <line x1="82" y1="52" x2="82" y2="72" stroke="#1f2c42" stroke-width="1"/>
  <line x1="44" y1="52" x2="44" y2="82" stroke="#1f2c42" stroke-width="1"/>
  <circle cx="56" cy="62" r="9" fill="#4a8f52"/>
  <ellipse cx="56" cy="62" rx="24" ry="6" fill="none" stroke="#a4df4f" stroke-width="3" transform="rotate(-18 56 62)"/>
  <circle cx="32" cy="74" r="5" fill="#a4df4f"/>
  <circle cx="64" cy="74" r="4.5" fill="#f0db65"/>
  <circle cx="82" cy="75" r="8" fill="#8ed164"/>
  <circle cx="44" cy="84" r="7.5" fill="#58a4c7"/>
  <path d="M40 82q4-2 7 1M39 86q5 3 9 0" stroke="#377a9c" stroke-width="1.2" fill="none"/>
</g>`;

const porthole=()=>`
<g id="porthole">
  <defs>
    <!-- Masking kaca bulat jendela agar pemandangan tidak keluar bingkai -->
    <clipPath id="portholeClip">
      <circle cx="170" cy="75" r="28"/>
    </clipPath>
    <!-- Gradien Langit Siang (Day Sky: Biru Cerah & Cahaya Matahari Emas) -->
    <radialGradient id="daySkyGrad" cx="70%" cy="30%" r="80%">
      <stop offset="0%" stop-color="#fffbeb"/>
      <stop offset="25%" stop-color="#bae6fd"/>
      <stop offset="70%" stop-color="#38bdf8"/>
      <stop offset="100%" stop-color="#0284c7"/>
    </radialGradient>
    <!-- Gradien Antariksa Malam (Night Sky: Deep Cosmos & Starlight) -->
    <radialGradient id="nightSkyGrad" cx="30%" cy="30%" r="85%">
      <stop offset="0%" stop-color="#1e1b4b"/>
      <stop offset="50%" stop-color="#090d16"/>
      <stop offset="100%" stop-color="#030712"/>
    </radialGradient>
  </defs>

  <!-- Sekrup & Rangka Luar Jendela Kapal -->
  <rect x="107" y="65" width="8" height="18" rx="2" fill="#9cb0ca"/>
  <rect x="225" y="72" width="7" height="6" rx="2" fill="#9cb0ca"/>
  <circle cx="170" cy="75" r="42" fill="#b9cadf" stroke="#879cb8" stroke-width="2"/>
  ${(()=>{let b='';for(let a=0;a<360;a+=30){const rad=a*Math.PI/180;b+=`<circle cx="${(170+37*Math.cos(rad)).toFixed(1)}" cy="${(75+37*Math.sin(rad)).toFixed(1)}" r="1.6" fill="#6f84a3"/>`}return b;})()}
  <circle cx="170" cy="75" r="32" fill="#d9e6f5"/>

  <!-- Kaca Jendela & Pemandangan Alam Semesta Berdasarkan Preset Tema -->
  <g clip-path="url(#portholeClip)">
    <!-- 1. Pemandangan Malam (Default Dark Mode) -->
    <g class="porthole-night">
      <rect x="140" y="45" width="60" height="60" fill="url(#nightSkyGrad)"/>
      <!-- Bintang-bintang Kejora Berkerlip -->
      <circle cx="152" cy="62" r="1.2" fill="#ffffff" opacity=".9"/>
      <circle cx="188" cy="58" r="0.9" fill="#93c5fd" opacity=".8"/>
      <circle cx="165" cy="88" r="1.1" fill="#fef08a" opacity=".85"/>
      <circle cx="182" cy="85" r="0.8" fill="#ffffff" opacity=".7"/>
      <circle cx="156" cy="78" r="0.7" fill="#67e8f9" opacity=".9"/>
      <!-- Planet Mini Saturnus di Kejauhan Antariksa -->
      <ellipse cx="178" cy="66" rx="7" ry="2.2" fill="none" stroke="#d97706" stroke-width="1.2" transform="rotate(-15 178 66)"/>
      <circle cx="178" cy="66" r="3.8" fill="#a78bfa"/>
      <!-- Nebula Ungu Lembut -->
      <ellipse cx="160" cy="82" rx="14" ry="7" fill="#7c3aed" opacity=".22" filter="blur(2px)"/>
    </g>

    <!-- 2. Pemandangan Siang (Light Mode: Cerah Atmosferik) -->
    <g class="porthole-day">
      <rect x="140" y="45" width="60" height="60" fill="url(#daySkyGrad)"/>
      <!-- Matahari / Bintang Terang Menyala -->
      <circle cx="182" cy="60" r="9" fill="#fde047" opacity=".35" filter="blur(3px)"/>
      <circle cx="182" cy="60" r="5.5" fill="#ffffff"/>
      <circle cx="182" cy="60" r="7.5" fill="#fef08a" opacity=".6"/>
      <!-- Awan Stratosfer Tipis Mengapung -->
      <path d="M142 84 q8 -5 18 -1 q10 3 20 -2 q8 -3 16 3" stroke="#ffffff" stroke-width="3" stroke-linecap="round" fill="none" opacity=".65"/>
      <path d="M150 90 q10 -3 24 1 q12 2 18 -3" stroke="#e0f2fe" stroke-width="2" stroke-linecap="round" fill="none" opacity=".5"/>
    </g>
  </g>

  <!-- Pantulan Kilau Kaca Cembung -->
  <path d="M150 56a28 28 0 0 1 38 6q-20 4-38 -6z" fill="#ffffff" opacity=".35"/>
</g>`;

const windowBeam=()=>`
<g class="window-beam">
  <defs>
    <linearGradient id="starlightGrad" x1="0%" y1="0%" x2="40%" y2="100%">
      <stop offset="0%" stop-color="#bceaff" stop-opacity="0.85"/>
      <stop offset="45%" stop-color="#91d2ff" stop-opacity="0.35"/>
      <stop offset="100%" stop-color="#72b5ff" stop-opacity="0"/>
    </linearGradient>
    <linearGradient id="dayBeamGrad" x1="0%" y1="0%" x2="40%" y2="100%">
      <stop offset="0%" stop-color="#fef08a" stop-opacity="0.75"/>
      <stop offset="45%" stop-color="#fed7aa" stop-opacity="0.25"/>
      <stop offset="100%" stop-color="#fef08a" stop-opacity="0"/>
    </linearGradient>
  </defs>
  <polygon points="144,78 196,78 310,196 60,196" fill="url(#starlightGrad)"/>
</g>`;

const digiClock=()=>`
<g id="clock">
  <line x1="322" y1="41" x2="313" y2="41" stroke="#6bcfcf" stroke-width="2.4" stroke-linecap="round"/>
  <line x1="325" y1="44" x2="333" y2="44" stroke="#6bcfcf" stroke-width="2.4" stroke-linecap="round"/>
  <rect x="295" y="47" width="56" height="23" rx="7" fill="#a4df4f"/>
  <rect x="300" y="50" width="46" height="14" rx="4" fill="#172e3d"/>
  <text id="clock-time" x="323" y="61" text-anchor="middle" font-family="monospace" font-weight="700" font-size="10" fill="#a8f5e5" letter-spacing="1">--:--</text>
  <rect x="338" y="54" width="4" height="6" rx="1" fill="#46cdb1"/>
  <circle cx="316" cy="67" r="1.4" fill="#588521"/>
  <circle cx="323" cy="67" r="1.4" fill="#588521"/>
  <circle cx="330" cy="67" r="1.4" fill="#588521"/>
</g>`;

const airlock=()=>`
<g id="airlock">
  <rect x="289" y="94" width="10" height="18" rx="2" fill="#ffffff" stroke="#b0bece" stroke-width="1"/>
  <rect x="291" y="96" width="6" height="5" fill="#1b2e3e"/>
  <circle cx="293" cy="104" r=".9" fill="#5f7399"/><circle cx="296" cy="104" r=".9" fill="#5f7399"/>
  <circle cx="293" cy="107" r=".9" fill="#5f7399"/><circle cx="296" cy="107" r=".9" fill="#5f7399"/>
  <rect x="302" y="77" width="56" height="63" rx="7" fill="#edf2f7" stroke="#cbd5e1" stroke-width="2"/>
  <rect x="307" y="81" width="46" height="58" fill="#d8e1ea"/>
  <path d="M312 85h36v20l-16 14v28h-20z" fill="#ccd7e3" stroke="#b7c5d4" stroke-width="1.2"/>
  <path d="M315 88h30v15l-14 12v30h-16z" fill="#dce4ed"/>
  <rect x="287" y="137" width="56" height="15" rx="3" fill="#369680"/>
  ${(()=>{let g='';for(let i=291;i<=339;i+=4){g+=`<line x1="${i}" y1="139" x2="${i}" y2="150" stroke="#1d6655" stroke-width="1.2"/>`}return g;})()}
</g>`;

const rocketToy=()=>`
<g id="rocket">
  <path d="M384 128q-10 8-12 20h6q3-12 10-16z" fill="#d2dbe5"/>
  <path d="M404 128q10 8 12 20h-6q-3-12-10-16z" fill="#d2dbe5"/>
  <path d="M394 85l-9 43h18z" fill="#edf2f7"/>
  <rect x="385" y="128" width="18" height="20" fill="#edf2f7"/>
  <ellipse cx="394" cy="112" rx="14" ry="4" fill="#a4d7ea"/>
  <ellipse cx="394" cy="111" rx="12" ry="2.5" fill="#def4fc"/>
  <rect x="391" y="148" width="6" height="3" fill="#b9c6d4"/>
</g>`;

const sciBed=()=>`
<g id="scibed">
  <path d="M-6 116h40q18 0 24 14l10 16" fill="none" stroke="#edf3f8" stroke-width="6" stroke-linecap="round"/>
  <path d="M12 126l22 18" stroke="#cbd7e3" stroke-width="3"/>
  <ellipse cx="16" cy="128" rx="13" ry="7" fill="#f4f5d7"/>
  <ellipse cx="42" cy="125" rx="13" ry="7" fill="#f4f5d7"/>
  <rect x="-8" y="132" width="102" height="36" rx="7" fill="#edf2f8"/>
  <path d="M-8 138h98 M-8 144h98 M-8 150h98 M-8 156h98 M-8 162h98" stroke="#879ec2" stroke-width="2.2"/>
</g>`;

const sciDesk=()=>`
<g id="scidesk">
  <rect x="124" y="110" width="70" height="7" rx="3.5" fill="#a4df4f"/>
  <path d="M152 117c0 8 7 14 7 21h-16c0-7 7-13 7-21z" fill="#a4df4f"/>
  <rect x="139" y="137" width="28" height="3" rx="1.5" fill="#88c437"/>
  <rect class="screen-border" x="132" y="85" width="40" height="25" rx="5" fill="#3280ab" stroke="#1d5677" stroke-width="1.5"/>
  <rect x="127" y="93" width="5" height="10" rx="2" fill="#ff7a6b"/>
  <rect x="172" y="93" width="5" height="10" rx="2" fill="#ff7a6b"/>
  <rect class="screen-bg" x="136" y="88" width="32" height="18" rx="2" fill="#0f1f2e"/>
  <g class="screen-content">
    <rect class="ln" x="139" y="91" width="14" height="2" fill="#7fd1b9"/>
    <rect class="ln" x="139" y="95" width="22" height="2" fill="#f0c36a" style="animation-delay:.3s"/>
    <rect class="ln" x="139" y="99" width="17" height="2" fill="#ff7a6b" style="animation-delay:.6s"/>
    <circle class="blink-dot" cx="163" cy="93" r="1.4" fill="#a4df4f"/>
    <circle class="blink-dot" cx="163" cy="98" r="1.4" fill="#7fd1b9" style="animation-delay:.4s"/>
  </g>
</g>`;

const controlPedestal=()=>`
<g id="pedestal">
  <path d="M251 118v18h-4v-18z" fill="#4d9db3"/>
  <path d="M246 135c0-4 10-4 10 0v6h-10z" fill="#4d9db3"/>
  <rect x="240" y="140" width="20" height="3" rx="1.5" fill="#3a8296"/>
  <polygon points="237,118 263,118 260,105 240,105" fill="#69b9cf"/>
  <circle cx="244" cy="113" r="2.2" fill="#ff7a6b"/>
  <circle cx="249" cy="114" r="1.8" fill="#f0c36a"/>
  <rect x="254" y="102" width="4" height="14" rx="2" fill="#ff5a47"/>
  <rect x="252" y="100" width="8" height="3" rx="1" fill="#e03e2a"/>
</g>`;

const saturnRug=()=>`
<g id="saturnrug">
  <!-- Karpet Saturnus Megah di Foreground Depan (Pusat x=220, y=170) - Efek Luas 3D -->
  <!-- Bayangan lembut karpet di lantai depan -->
  <ellipse cx="220" cy="173" rx="52" ry="14" fill="#060c14" opacity=".55"/>
  <!-- Badan Karpet Bulat Planet Zamrud Cerah Kontras -->
  <ellipse cx="220" cy="170" rx="44" ry="12.5" fill="#059669" stroke="#047857" stroke-width="2"/>
  <ellipse cx="220" cy="169.5" rx="36" ry="9.5" fill="#10b981"/>
  <!-- Cincin Saturnus Emas Menyala Menjorok ke Depan -->
  <ellipse cx="220" cy="170" rx="64" ry="7.5" fill="none" stroke="#fbbf24" stroke-width="3.8"/>
  <ellipse cx="220" cy="170" rx="70" ry="8.5" fill="none" stroke="#f59e0b" stroke-width="1.8"/>
  <!-- Garis Belah Cahaya Putih Cincin -->
  <path d="M162 169q58-5.5 116 0" stroke="#ffffff" stroke-width="1.4" fill="none" opacity=".95"/>
  <!-- Bintang Emas di Tengah Karpet -->
  <polygon points="220,165 222.5,168.5 226,169.5 222.5,170.8 220,174 217.5,170.8 214,169.5 217.5,168.5" fill="#fbbf24"/>
</g>`;

/* Maskot Baru: Mecha Robocat (Sesuai Referensi Gambar dengan Warna Kucing Oranye-Krem-Navy Sebelumnya) */
const ROBOCAT=`
<g id="cat">
  <g class="face" id="fc" style="transform:scaleX(1)">
    <!-- Ekor Robot Bersegmen -->
    <path class="tail" d="M-10 -12q-16 2-15 -18" stroke="#1c273c" stroke-width="4" fill="none" stroke-linecap="round"/>
    <circle class="tail" cx="-25" cy="-30" r="3.5" fill="#e0a874" stroke="#1c273c" stroke-width="1.5"/>
    <circle class="tail ant-light" cx="-25" cy="-30" r="1.5" fill="#5eead4"/>

    <!-- Kaki Robot Chibi -->
    <g class="lg">
      <path class="lg1" d="M-8 -6v6h6v-6z" fill="#1c273c"/>
      <path class="lg2" d="M2 -6v6h6v-6z" fill="#1c273c"/>
      <rect x="-9" y="-2" width="8" height="3" rx="1.5" fill="#2d3f5e"/>
      <rect x="1" y="-2" width="8" height="3" rx="1.5" fill="#2d3f5e"/>
    </g>

    <!-- Badan & Pelindung Mecha -->
    <g class="bodyg">
      <!-- Celana / Bagian Bawah Gelap -->
      <path d="M-10 -14h20v8q0 4-4 4h-12q-4 0-4-4z" fill="#1c273c" stroke="#121a28" stroke-width="1.4"/>
      <!-- Baju Zirah Putih/Krem Bersudut -->
      <path d="M-12 -25h24l-3 12h-18z" fill="#fdfaf3" stroke="#1c273c" stroke-width="1.5"/>
      <path d="M-12 -25h5l-1 12h-4z M12 -25h-5l1 12h4z" fill="#e0a874"/>
      <!-- Inti Reaktor Dada Melingkar (Chest Core) -->
      <circle cx="0" cy="-17" r="5.5" fill="#1c273c"/>
      <circle class="core-light" cx="0" cy="-17" r="3.6" fill="#5eead4"/>

      <!-- Telinga Kucing Robotik (Outer Oranye Jahe & Inner Gelap) -->
      <path d="M-15 -42q-4 -14 6 -17q9 2 6 17z" fill="#e0a874" stroke="#1c273c" stroke-width="2"/>
      <path d="M-13 -42q-2 -10 5 -12q6 2 4 12z" fill="#1c273c"/>
      <path d="M15 -42q4 -14 -6 -17q-9 2 -6 17z" fill="#e0a874" stroke="#1c273c" stroke-width="2"/>
      <path d="M13 -42q2 -10 -5 -12q-6 2 -4 12z" fill="#1c273c"/>

      <!-- Antena Samping dengan Ujung Bola Bercahaya -->
      <line x1="-19" y1="-38" x2="-23" y2="-47" stroke="#1c273c" stroke-width="2" stroke-linecap="round"/>
      <circle class="ant-light" cx="-23" cy="-47" r="2.8" fill="#5eead4" stroke="#1c273c" stroke-width="1.2"/>
      <line x1="19" y1="-38" x2="23" y2="-47" stroke="#1c273c" stroke-width="2" stroke-linecap="round"/>
      <circle class="ant-light" cx="23" cy="-47" r="2.8" fill="#5eead4" stroke="#1c273c" stroke-width="1.2"/>

      <!-- Bantalan Headphone Telinga di Samping Kepala -->
      <rect x="-23" y="-40" width="5" height="13" rx="2.5" fill="#fdfaf3" stroke="#1c273c" stroke-width="1.8"/>
      <rect x="18" y="-40" width="5" height="13" rx="2.5" fill="#fdfaf3" stroke="#1c273c" stroke-width="1.8"/>

      <!-- Helm Mecha Putih Membulat -->
      <path d="M-19 -35c0 -14 9 -20 19 -20s19 6 19 20c0 10 -8 13 -19 13s-19 -3 -19 -13z" fill="#fdfaf3" stroke="#1c273c" stroke-width="2"/>
      <!-- Lis Alis Oranye Khas Maskot -->
      <path d="M-10 -49q10 -4 20 0" stroke="#e0a874" stroke-width="2.6" fill="none" stroke-linecap="round"/>

      <!-- Layar Visor Kaca Helm Hitam-Kebiruan -->
      <path d="M-16 -37c0 -8 6 -11 16 -11s16 3 16 11c0 8 -6 10 -16 10s-16 -2 -16 -10z" fill="#141c2c" stroke="#1c273c" stroke-width="1.6"/>

      <!-- Wajah Digital Bercahaya (Mata Kapsul & Mulut Kucing :3) -->
      <g class="eyes">
        <rect class="eye" x="-10" y="-40" width="4.8" height="8.5" rx="2.4" fill="#5eead4"/>
        <rect class="eye" x="5.2" y="-40" width="4.8" height="8.5" rx="2.4" fill="#5eead4"/>
      </g>
      <circle cx="0" cy="-33" r="1.3" fill="#5eead4"/>
      <path class="mouth" d="M-3.5 -31q1.8 1.8 3.5 0q1.8 1.8 3.5 0" stroke-width="1.4" fill="none" stroke-linecap="round"/>

      <!-- Sambungan Leher Robot -->
      <rect x="-8" y="-25" width="16" height="2.5" rx="1" fill="#1c273c"/>
    </g>

    <!-- Tangan Robot Mecha -->
    <g class="arm arm-l"><path d="M-11 -22l-4 8" stroke="#1c273c" stroke-width="5" stroke-linecap="round"/><circle class="pa" cx="-15" cy="-14" r="3.2" fill="#fdfaf3" stroke="#1c273c" stroke-width="1.4"/></g>
    <g class="arm arm-r"><path d="M11 -22l4 8" stroke="#1c273c" stroke-width="5" stroke-linecap="round"/><circle class="pb" cx="15" cy="-14" r="3.2" fill="#fdfaf3" stroke="#1c273c" stroke-width="1.4"/></g>

    <!-- Kaca Pembesar Sensor Scanner -->
    <g class="p mag"><line x1="16" y1="-14" x2="28" y2="-24" stroke="#d9b26f" stroke-width="2.5" stroke-linecap="round"/><circle cx="32" cy="-28" r="7" fill="#5eead4" fill-opacity=".25" stroke="#5eead4" stroke-width="2"/></g>
  </g>

  <!-- Balon Status Animasi -->
  <g class="p zz"><text class="z" x="18" y="-56">z</text><text class="z z2" x="28" y="-68">Z</text></g>
  <g class="p tb dots"><circle cx="16" cy="-62" r="2" fill="#9aa7bd"/><circle cx="24" cy="-70" r="3" fill="#9aa7bd"/><rect x="20" y="-102" width="44" height="24" rx="12" fill="#1f2d45" stroke="#5f7399"/><circle cx="33" cy="-90" r="2.5" fill="#eee9de"/><circle cx="42" cy="-90" r="2.5" fill="#eee9de"/><circle cx="51" cy="-90" r="2.5" fill="#eee9de"/></g>
  <g class="p qb"><g class="bub"><circle cx="0" cy="-76" r="13" fill="#f0c36a"/><text x="0" y="-69" text-anchor="middle" style="font:700 18px system-ui" fill="#1b1608">?</text></g></g>
  <g class="p eb"><g class="bub"><circle cx="0" cy="-76" r="13" fill="#ff7a6b"/><text x="0" y="-69" text-anchor="middle" style="font:700 18px system-ui" fill="#2a0d09">!</text></g></g>
</g>`;

/* Titik Posisi Robot di Ruang Sci-Fi */
const RM={
  s:{idle:{x:48,y:142},type:{x:174,y:154},ask:{x:210,y:168},search:[{x:248,y:154},{x:330,y:154}],err:{x:220,y:162}},
  f:{idle:1,type:-1,ask:1,err:1}
};
const TX={
  idle:'Mode standby. Lampu padam, beristirahat di kasur.',
  type:'Mengoperasikan konsol monitor komputer',
  ask:'Meminta persetujuan Anda untuk mengeksekusi aksi',
  search:'Memeriksa modul kontrol dan airlock',
  err:'Sistem darurat aktif! Periksa terminal PC.'
};

let cur='',run=0;
function updateClock(){
  const el=$('clock-time');
  if(!el)return;
  const d=new Date();
  const hh=String(d.getHours()).padStart(2,'0');
  const mm=String(d.getMinutes()).padStart(2,'0');
  el.textContent=`${hh}:${mm}`;
}


/* Maskot Kucing Telegram di Scene */


const catBedAndClock=()=>`
<!-- Area Ranjang Donut Kucing & Jam Weker di Sisi Kanan Lantai -->
<g id="cat-bed-area">
  <!-- Meja Nakas Kayu Minimalis untuk Jam Weker -->
  <rect x="304" y="142" width="20" height="20" rx="3" fill="#22334d" stroke="#142133" stroke-width="1.2"/>
  <rect x="302" y="139" width="24" height="4" rx="2" fill="#3a5278"/>
  <rect x="308" y="148" width="12" height="2" rx="0.5" fill="#142133"/>

  <!-- Jam Weker Retro-Futuristik (Di Atas Meja Nakas) -->
  <g id="alarm-clock" transform="translate(314, 131)">
    <line x1="-4" y1="5.5" x2="-6" y2="8" stroke="#d9b26f" stroke-width="1.4" stroke-linecap="round"/>
    <line x1="4" y1="5.5" x2="6" y2="8" stroke="#d9b26f" stroke-width="1.4" stroke-linecap="round"/>
    <circle cx="-5.5" cy="-5.5" r="2.6" fill="#d9b26f" stroke="#1c273c" stroke-width=".8"/>
    <circle cx="5.5" cy="-5.5" r="2.6" fill="#d9b26f" stroke="#1c273c" stroke-width=".8"/>
    <rect x="-1" y="-7.5" width="2" height="2" fill="#d9b26f"/>
    <circle cx="0" cy="0" r="7" fill="#0088cc" stroke="#1c273c" stroke-width="1.2"/>
    <circle cx="0" cy="0" r="5.2" fill="#ffffff"/>
    <line x1="0" y1="0" x2="0" y2="-3" stroke="#1c273c" stroke-width="1" stroke-linecap="round"/>
    <line x1="0" y1="0" x2="2.2" y2="0.8" stroke="#ff7a6b" stroke-width="1" stroke-linecap="round"/>
    <g class="alarm-waves">
      <path d="M-8.5 -2.5q-2 -2.5 0 -5" stroke="#f0c36a" stroke-width="1" fill="none" stroke-linecap="round"/>
      <path d="M8.5 -2.5q2 -2.5 0 -5" stroke="#f0c36a" stroke-width="1" fill="none" stroke-linecap="round"/>
    </g>
  </g>

  <!-- Ranjang Donut Futuristik Empuk untuk Kucing Tidur (x=372, y=152) -->
  <g id="cat-bed">
    <ellipse cx="372" cy="158" rx="28" ry="10" fill="#080f1d" opacity=".4"/>
    <ellipse cx="372" cy="153" rx="26" ry="9" fill="#1b3354" stroke="#0088cc" stroke-width="1.8"/>
    <ellipse cx="372" cy="151" rx="20" ry="7" fill="#7ee2ff" opacity=".9"/>
    <ellipse cx="372" cy="150" rx="14" ry="5" fill="#fdfaf3"/>
    <circle cx="372" cy="150" r="1.8" fill="#ffb4c8" opacity=".8"/>
    <circle cx="369" cy="148" r="0.9" fill="#ffb4c8" opacity=".8"/>
    <circle cx="372" cy="147.2" r="0.9" fill="#ffb4c8" opacity=".8"/>
    <circle cx="375" cy="148" r="0.9" fill="#ffb4c8" opacity=".8"/>
  </g>
</g>`;

const TGCAT=`
<g id="tgcat" transform="translate(372,146)" data-tg="idle">
  <!-- Bayangan lembut di bawah karakter -->
  <ellipse id="tg-shadow" cx="0" cy="0" rx="15" ry="3.8" fill="#080f1d" opacity=".45"/>

  <!-- Sprite 3D Kucing (Switching otomatis berdasarkan data-tg) -->
  <!-- 1. Pose Tidur (Sleep / Idle di ranjang) -->
  <g class="tg-sprite-sleep">
    <image href="/cat_3d_sleep.png" x="-24" y="-22" width="48" height="32" preserveAspectRatio="xMidYMid meet"/>
  </g>

  <!-- 2. Pose Mengetik HP (Type / Balas Chat di karpet) -->
  <g class="tg-sprite-type">
    <image href="/cat_3d_type.png" x="-24" y="-50" width="48" height="52" preserveAspectRatio="xMidYMid meet"/>
  </g>

  <!-- 3. Pose Waspada / Pesan Masuk (Alert / Msg) -->
  <g class="tg-sprite-alert">
    <image href="/cat_3d_alert.png" x="-20" y="-42" width="42" height="46" preserveAspectRatio="xMidYMid meet"/>
  </g>

  <!-- Balon Chat Putih Bersih dengan Animasi Dot Biru Telegram -->
  <g class="tg-buble">
    <!-- Balon Putih Bersih dengan Bayangan Lembut -->
    <path d="M-4 -76 h42 a6 6 0 0 1 6 6 v12 a6 6 0 0 1 -6 6 h-28 l-6 6 v-6 h-8 a6 6 0 0 1 -6 -6 v-12 a6 6 0 0 1 6 -6 z" fill="#ffffff" stroke="#e2e8f0" stroke-width="1" filter="drop-shadow(0 4px 10px rgba(0,0,0,0.35))"/>
    <!-- 3 Dot Biru Telegram Beranimasi Tepat di Tengah-Tengah Balon -->
    <circle class="tdot tdot1" cx="6.5" cy="-65.5" r="2.1" fill="#0088cc"/>
    <circle class="tdot tdot2" cx="14" cy="-65.5" r="2.1" fill="#0088cc"/>
    <circle class="tdot tdot3" cx="21.5" cy="-65.5" r="2.1" fill="#0088cc"/>
  </g>

  <!-- Efek Tidur Zzz Lembut & Terang di Atas Ranjang Kucing -->
  <g class="tg-zzz">
    <text class="tg-z tg-z1" x="10" y="-18" fill="#7ee2ff" font-weight="700" font-size="10" filter="drop-shadow(0 0 3px #0088cc)">z</text>
    <text class="tg-z tg-z2" x="18" y="-28" fill="#5eead4" font-weight="700" font-size="13" filter="drop-shadow(0 0 3px #0088cc)">Z</text>
    <text class="tg-z tg-z3" x="26" y="-40" fill="#f0c36a" font-weight="700" font-size="16" filter="drop-shadow(0 0 4px #d97706)">Z</text>
  </g>
</g>`;

function mount(){
  $('room').innerHTML=`<svg viewBox="0 0 420 205" data-s="ok" data-state="idle" role="img" aria-label="Cockpit Maskot Robot Hermes">
    ${walls()}
    ${solarMobile()}
    ${porthole()}
    ${windowBeam()}
    ${ufoLamp()}
    ${digiClock()}
    ${airlock()}
    ${sciBed()}
    ${sciDesk()}
    ${controlPedestal()}
    ${saturnRug()}
    ${catBedAndClock()}
    ${ROBOCAT}
    ${TGCAT}
    <rect class="room-dim" width="420" height="205" fill="#080f1d"/>
    <rect id="alarm" width="420" height="205"/>
  </svg>`;
  const c=$('cat');
  c.style.transform=`translate(${RM.s.idle.x}px,${RM.s.idle.y}px) scale(1)`;
  c.dataset.p='loaf';
  updateClock();
  setInterval(updateClock,1000);
}

async function go(pos, scale=1){
  const c=$('cat');
  const cu=new DOMMatrix(getComputedStyle(c).transform).m41;
  const d=Math.abs(pos.x-cu);
  const targetTransform=`translate(${pos.x}px,${pos.y}px) scale(${scale})`;
  if(d>3 || scale!==1){
    $('fc').style.transform=`scaleX(${pos.x>cu?1:-1})`;
    c.dataset.p='walk';
    const t=Math.max(0.25,d/70);
    c.style.transition=`transform ${t}s cubic-bezier(0.25, 1, 0.5, 1)`;
    c.style.transform=targetTransform;
    await sleep(t*1000+60);
  } else {
    c.style.transform=targetTransform;
  }
}

async function scene(m){
  if(!m)return;
  lastRobotMascot = m;
  const s=m.state;
  updateStatusDisplay();
  if(s===cur)return;
  cur=s;
  const my=++run,c=$('cat');
  const svgEl=$('room').firstChild;
  svgEl.dataset.s=s==='err'?'error':'ok';
  svgEl.dataset.state=s;

  // Break search loop only when state changes
  if(s==='search'){
    let cycles=0;
    while(my===run && cycles<6){
      for(const p of RM.s.search){
        if(my!==run)return;
        await go(p, 1);
        if(my!==run)return;
        c.dataset.p='look';
        await sleep(1800);
      }
      cycles++;
    }
    return;
  }

  const isAsk=s==='ask';
  await go(RM.s[s], isAsk?1.65:1);
  if(my!==run)return;
  if(RM.f[s]) $('fc').style.transform=`scaleX(${RM.f[s]})`;
  c.dataset.p={idle:'loaf',type:'type',ask:'ask',err:'err'}[s]||'loaf';
}


if('serviceWorker' in navigator){
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js').catch(()=>{});
  });
}

mount();
tok?start():logout();
</script></body></html>"""

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(data)

    def _authed(self):
        got = self.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        return bool(got) and hmac.compare_digest(got.encode(), TOKEN.encode())

    def do_GET(self):
        p = urlparse(self.path).path
        if p == "/": return self._send(200, HTML.encode(), "text/html; charset=utf-8")
        if p == "/icon.svg":
            svg_file = os.path.join(HERMES_DIR, "dashboard", "icon.svg")
            if os.path.isfile(svg_file):
                with open(svg_file, "rb") as sf:
                    return self._send(200, sf.read(), "image/svg+xml")
            return self._send(200, ICON.encode(), "image/svg+xml")
        if p == "/favicon.ico" or p == "/favicon.png":
            fav = os.path.join(HERMES_DIR, "dashboard", "favicon.png")
            if os.path.isfile(fav):
                with open(fav, "rb") as ff:
                    return self._send(200, ff.read(), "image/png")
        if (p.startswith("/cat_badge_") or p.startswith("/cat_3d_")) and p.endswith(".png"):
            fname = os.path.basename(p)
            fpath = os.path.join(HERMES_DIR, "dashboard", fname)
            if os.path.isfile(fpath):
                with open(fpath, "rb") as bf:
                    return self._send(200, bf.read(), "image/png")
        if p == "/manifest.json":
            return self._send(200, {
                "name": "Hermes Cockpit",
                "short_name": "Hermes",
                "display": "standalone",
                "orientation": "portrait-primary",
                "start_url": "/",
                "scope": "/",
                "background_color": "#101826",
                "theme_color": "#101826",
                "icons": [
                    {"src": "/icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any maskable"},
                    {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any maskable"},
                    {"src": "/icon.svg", "sizes": "any", "type": "image/svg+xml", "purpose": "any"}
                ]
            })
        if p == "/icon-192.png" or p == "/icon-512.png":
            sz = 192 if "192" in p else 512
            png_path = os.path.join(HERMES_DIR, "dashboard", f"icon-{sz}.png")
            if os.path.isfile(png_path):
                with open(png_path, "rb") as f:
                    return self._send(200, f.read(), "image/png")
        if p == "/sw.js":
            sw_code = "self.addEventListener('install', e => self.skipWaiting()); self.addEventListener('activate', e => self.clients.claim()); self.addEventListener('fetch', e => e.respondWith(fetch(e.request))); self.addEventListener('message', e => { if(e.data && e.data.type === 'SHOW_NOTIFICATION'){ self.registration.showNotification(e.data.title, { body: e.data.body, icon: '/icon-192.png', badge: '/icon-192.png' }); } });"
            return self._send(200, sw_code.encode(), "application/javascript; charset=utf-8")
        if p == "/api/state":
            if not self._authed(): return self._send(401, {"error": "unauthorized"})
            return self._send(200, {"hostname": HOSTNAME, "platform": platform.system(), "heartbeat": read_heartbeat(),
                                    "cron_jobs": read_cron_jobs(), "tools": read_recent_tool_executions(25),
                                    "mascot": mascot_state(), "tg_mascot": telegram_mascot_state(), "alerts": read_cron_alerts(15)})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        p = urlparse(self.path).path
        if not self._authed(): return self._send(401, {"error": "unauthorized"})
        
        # 1. Endpoint Aksi Cron / Kill
        if p == "/api/action":
            try:
                n = min(int(self.headers.get("Content-Length", 0)), 1024)
                body = json.loads(self.rfile.read(n) or b"{}")
                op, target = str(body.get("op", "")), str(body.get("target", ""))
            except Exception:
                return self._send(400, {"error": "bad request"})
            if op == "kill":
                execute_action("kill")
            elif op in ("pause", "resume", "run") and target in {j.get("id") for j in read_cron_jobs()}:
                execute_action(op, target)
            else:
                return self._send(400, {"error": "invalid action"})
            return self._send(200, {"ok": True})

        # 2. Endpoint Command Center Interaktif (/api/command)
        if p == "/api/command":
            try:
                n = min(int(self.headers.get("Content-Length", 0)), 4096)
                body = json.loads(self.rfile.read(n) or b"{}")
                cmd = str(body.get("command", "")).strip()
            except Exception:
                return self._send(400, {"error": "bad request"})
            
            if not cmd:
                return self._send(400, {"error": "command is empty"})

            # Handle Preset Actions Khusus
            if cmd == "__ACTION_SYNC_CRYPTO__":
                # Jalankan langsung job crypto prices 6h
                subprocess.Popen(["hermes", "cron", "run", "5ef2ddd68c11"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return self._send(200, {"ok": True, "reply": "Sinkronisasi harga pasar crypto dipicu di latar belakang. Laporan akan diperbarui sesaat lagi."})

            if cmd == "__ACTION_CLEAR_CACHE__":
                scratch_dir = os.path.join(HERMES_DIR, "cache", "scratch")
                cleaned = 0
                if os.path.isdir(scratch_dir):
                    for fn in os.listdir(scratch_dir):
                        fp = os.path.join(scratch_dir, fn)
                        try:
                            if os.path.isfile(fp):
                                os.unlink(fp)
                                cleaned += 1
                        except Exception:
                            pass
                return self._send(200, {"ok": True, "reply": f"Pembersihan selesai: {cleaned} berkas sementara di workspace scratch berhasil dihapus."})

            # Eksekusi Prompt Interaktif ke Hermes Agent CLI via subprocess oneshot
            def _run_cli_query(q):
                try:
                    # Jalankan hermes chat dengan -Q (quiet mode: hanya hasil jawaban akhir bersih tanpa streaming trace CLI)
                    res = subprocess.run(
                        ["hermes", "chat", "-q", q, "--oneshot", "-Q"],
                        capture_output=True,
                        text=True,
                        timeout=90
                    )
                    raw_out = res.stdout.strip() or res.stderr.strip() or "Selesai tanpa output."
                    # Bersihkan baris session_id di akhir jika ada
                    lines = [l for l in raw_out.splitlines() if not l.startswith("session_id:")]
                    return "\n".join(lines).strip()
                except subprocess.TimeoutExpired:
                    return "Waktu eksekusi habis (timeout 90 detik). Tugas mungkin masih berjalan di background."
                except Exception as e:
                    return f"Gagal mengeksekusi perintah: {e}"

            # Jalankan query
            reply_text = _run_cli_query(cmd)
            return self._send(200, {"ok": True, "reply": redact_secrets(reply_text)})

        self._send(404, {"error": "not found"})

def main():
    global HERMES_DIR, TOKEN
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--host", default=None, help="Default: IP Tailscale, atau 127.0.0.1 bila tidak ada")
    ap.add_argument("--hermes-dir", default=None)
    ap.add_argument("--token", default=os.environ.get("COCKPIT_TOKEN"))
    ap.add_argument("--ssl-cert", default=None, help="Path ke file sertifikat .crt")
    ap.add_argument("--ssl-key", default=None, help="Path ke file private key .key")
    a = ap.parse_args()
    HERMES_DIR = resolve_hermes_dir(a.hermes_dir)
    
    # Token: env var > CLI arg > saved file > generate new
    token_file = os.path.join(HERMES_DIR, ".cockpit_token")
    if a.token:
        TOKEN = a.token
    elif os.path.isfile(token_file):
        try:
            with open(token_file, "r") as f:
                TOKEN = f.read().strip()
        except Exception:
            TOKEN = secrets.token_urlsafe(24)
    else:
        TOKEN = secrets.token_urlsafe(24)
        try:
            with open(token_file, "w") as f:
                f.write(TOKEN)
            os.chmod(token_file, 0o600)
        except Exception:
            pass
    
    ts_ip, _ = get_detected_ips()
    host = a.host or ts_ip or "127.0.0.1"
    print(f"Hermes Cockpit v2 (standalone + mascot improved)\n  Hermes : {HERMES_DIR}\n  Alamat : http://{host}:{a.port}\n  Token  : {TOKEN}")
    if host == "0.0.0.0": print("  PERINGATAN: 0.0.0.0 membuka cockpit ke seluruh jaringan Wi-Fi.", file=sys.stderr)
    cert_path = a.ssl_cert or os.path.join(HERMES_DIR, "dashboard", "cert.crt")
    key_path = a.ssl_key or os.path.join(HERMES_DIR, "dashboard", "cert.key")
    
    server = ThreadingHTTPServer((host, a.port), Handler)
    use_https = False
    if os.path.isfile(cert_path) and os.path.isfile(key_path):
        try:
            import ssl
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
            server.socket = ctx.wrap_socket(server.socket, server_side=True)
            use_https = True
            print(f"  SSL    : Aktif (HTTPS) menggunakan {cert_path}")
        except Exception as e:
            print(f"  SSL    : Gagal ({e}), fallback ke HTTP biasa", file=sys.stderr)

    proto = "https" if use_https else "http"
    print(f"  URL    : {proto}://{host}:{a.port}/")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nBerhenti.")


if __name__ == "__main__":
    main()
