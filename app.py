#!/usr/bin/env python3
"""Hermes dashboard - stdlib only, no deps. Bind 0.0.0.0:8080"""
import json, os, glob, html, subprocess, urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime

HOME = os.path.expanduser("~")
JOBS = os.path.join(HOME, ".hermes/cron/jobs.json")
OUTDIR = os.path.join(HOME, ".hermes/cron/output")

def load_jobs():
    try:
        with open(JOBS) as f:
            return json.load(f).get("jobs", [])
    except Exception as e:
        return [{"error": str(e)}]

def latest_output(job_id):
    d = os.path.join(OUTDIR, job_id)
    files = sorted(glob.glob(os.path.join(d, "*.md")))
    if not files:
        return "", "no output yet"
    p = files[-1]
    try:
        with open(p) as f:
            txt = f.read()
        # ambil bagian Response saja biar ringkas
        if "## Response" in txt:
            txt = txt.split("## Response", 1)[1].strip()
        return os.path.basename(p), txt[:4000]
    except Exception as e:
        return "", str(e)

PAGE = """<!doctype html><html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#0f172a">
<link rel="manifest" href="/manifest.json">
<title>Hermes Dashboard</title>
<style>body{font-family:system-ui;background:#0f172a;color:#e2e8f0;margin:0;padding:16px}
.card{background:#1e293b;border-radius:12px;padding:14px;margin:12px 0}
.ok{color:#4ade80}.err{color:#f87171}.mut{color:#94a3b8}
button{background:#334155;color:#fff;border:0;border-radius:8px;padding:8px 12px;margin:4px 4px 0 0;font-size:14px}
pre{white-space:pre-wrap;font-size:13px;background:#0b1220;padding:10px;border-radius:8px;max-height:300px;overflow:auto}
h1{font-size:20px}h2{font-size:16px;margin:0 0 8px}</style></head>
<body><h1>Hermes Dashboard</h1><div class="mut">%TIME% WIB · <a style="color:#7dd3fc" href="/">refresh</a></div>
%CARDS%
<script>if('serviceWorker' in navigator){}</script></body></html>"""

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if u.path == "/manifest.json":
            return self.send_json({"name":"Hermes Dashboard","short_name":"Hermes","display":"standalone","start_url":"/","background_color":"#0f172a","theme_color":"#0f172a","icons":[]})
        if u.path == "/action":
            q = urllib.parse.parse_qs(u.query)
            jid, op = q.get("job",[""])[0], q.get("op",[""])[0]
            if jid and op in ("pause","resume","run"):
                subprocess.run(["hermes","cron",op,jid], capture_output=True, timeout=30)
            self.send_response(302); self.send_header("Location","/"); self.end_headers(); return
        jobs = load_jobs()
        cards = ""
        for j in jobs:
            jid = j.get("id","?")
            fn, out = latest_output(jid)
            st = j.get("last_status") or j.get("state","?")
            cls = "ok" if st == "ok" else ("err" if "fail" in str(st) or "error" in str(st) else "mut")
            cards += f"""<div class="card"><h2>{html.escape(j.get('name','?'))}</h2>
<div class="mut">{jid} · {html.escape(j.get('schedule_display',''))} · next: {html.escape(str(j.get('next_run_at','-')))}</div>
<div>Status: <b class="{cls}">{html.escape(str(st))}</b> · last: {html.escape(str(j.get('last_run_at','-')))}</div>
<div><a href="/action?op=pause&job={jid}"><button>Pause</button></a>
<a href="/action?op=resume&job={jid}"><button>Resume</button></a>
<a href="/action?op=run&job={jid}"><button>Run</button></a></div>
<div class="mut">latest: {html.escape(fn)}</div><pre>{html.escape(out)}</pre></div>"""
        body = PAGE.replace("%TIME%", datetime.now().strftime("%d %b %H:%M")).replace("%CARDS%", cards)
        b = body.encode()
        self.send_response(200); self.send_header("Content-Type","text/html"); self.send_header("Content-Length",str(len(b))); self.end_headers()
        self.wfile.write(b)
    def send_json(self, obj):
        b = json.dumps(obj).encode()
        self.send_response(200); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(b))); self.end_headers()
        self.wfile.write(b)

if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), H).serve_forever()
