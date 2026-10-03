#!/usr/bin/env python3
"""Hermes Cockpit v2 - UI baru + keamanan + mascot animation perbaikan.
Taruh di folder yang sama dengan cockpit.py.
Jalankan: python3 cockpit_v2.py [--token RAHASIA] [--port 8080] [--host IP]
"""
import os, sys, json, hmac, secrets, argparse, platform
from datetime import datetime
from urllib.parse import urlparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import cockpit as ck  # memakai pembaca data & redaksi dari versi lama

TOKEN = ""
ICON = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512"><rect width="512" height="512" rx="112" fill="#101826"/>'
        '<circle cx="256" cy="256" r="150" fill="none" stroke="#d9b26f" stroke-width="22"/>'
        '<path d="M150 262h72l34-84 40 150 30-66h36" fill="none" stroke="#7fd1b9" stroke-width="22" stroke-linecap="round" stroke-linejoin="round"/></svg>')

# === IMPROVED MASCOT STATE DETECTOR ===
TOOL_CATEGORIES = {
    "search": [
        "browser_exec", "browser_vault", "web_extract", "web_search",
        "vision_analyze", "read_file", "search_files", "session_search"
    ],
    "type": [
        "execute_code", "terminal", "write_file", "patch",
        "skill_manage", "skill_view", "kanban_create", "kanban_comment",
        "kanban_request_review", "kanban_request_changes", "patch"
    ],
    "idle": [
        "kanban_show", "kanban_list", "kanban_unblock", "kanban_block",
        "cronjob_manage", "memory", "clarify", "text_to_speech"
    ]
}

def get_tool_category(tool_name):
    """Categorize tool ke search/type/idle berdasarkan pola."""
    name_lower = str(tool_name).lower()
    for cat, patterns in TOOL_CATEGORIES.items():
        if any(p.lower() in name_lower for p in patterns):
            return cat
    # fallback pattern matching
    if any(k in name_lower for k in ("search", "fetch", "browser", "web", "read")):
        return "search"
    if any(k in name_lower for k in ("write", "edit", "patch", "execute", "terminal")):
        return "type"
    return "idle"

def mascot_state():
    """
    Detector mascot state: idle / think / type / search / err
    - err: heartbeat offline
    - think: heartbeat online tapi no recent tool (agent berpikir/menunggu)
    - type: recent tool execution (tulis/edit/execute)
    - search: recent tool execution (cari/baca)
    - idle: default fallback
    """
    hb = ck.read_heartbeat()
    
    # Heartbeat offline => error
    if not hb.get("fresh"):
        return {"state": "err", "tool": None}
    
    # Get recent tools (5 latest)
    tools = ck.read_recent_tool_executions(5)
    
    if tools:
        t = tools[0]
        try:
            # Parse timestamp (format: "YYYY-MM-DD HH:MM:SS")
            ts = datetime.strptime(t["timestamp"], "%Y-%m-%d %H:%M:%S")
            age = (datetime.now() - ts).total_seconds()
        except Exception:
            age = 9999
        
        # Tool activity within last 50 seconds is "fresh"
        if -2 <= age <= 50:
            tool_name = t["tool"]
            category = get_tool_category(tool_name)
            return {"state": category, "tool": tool_name}
    
    # Heartbeat online but no recent tool => agent is thinking
    return {"state": "think", "tool": None}


HTML = r"""<!doctype html><html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#101826"><link rel="manifest" href="/manifest.json"><link rel="icon" href="/icon.svg">
<title>Hermes Cockpit</title><style>
:root{--bg:#101826;--s1:#172236;--s2:#1f2d45;--line:#2b3b57;--tx:#eee9de;--mut:#9aa7bd;--brass:#d9b26f;--ok:#7fd1b9;--warn:#f0c36a;--bad:#ff7a6b;
--serif:"Iowan Old Style","Palatino Linotype",Georgia,serif;--sans:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;--mono:ui-monospace,Menlo,Consolas,monospace}
*{box-sizing:border-box;margin:0;padding:0}html,body{background:var(--bg);color:var(--tx);font:15px/1.5 var(--sans);-webkit-tap-highlight-color:transparent}
body{padding:env(safe-area-inset-top) 16px calc(88px + env(safe-area-inset-bottom))}
button{font:inherit;color:inherit;border:0;background:none;cursor:pointer}button:focus-visible,input:focus-visible{outline:2px solid var(--brass);outline-offset:2px}
.hero{margin:18px 0 22px;text-align:center}
.ring{width:132px;height:132px;margin:0 auto 14px;border-radius:50%;border:3px solid var(--line);display:grid;place-items:center;position:relative}
.ring::after{content:"";position:absolute;inset:-3px;border-radius:50%;border:3px solid var(--c,var(--line));opacity:.9}
.live .ring::after{animation:pulse 2.4s ease-out infinite}
@keyframes pulse{0%{transform:scale(1);opacity:.9}100%{transform:scale(1.28);opacity:0}}
.ring svg{width:58px;height:58px;stroke:var(--c,var(--mut));fill:none;stroke-width:2.4;stroke-linecap:round;stroke-linejoin:round}
.hero h1{font:600 26px/1.2 var(--serif)}.hero p{color:var(--mut);margin-top:4px;font-size:14px}
.hero.live{--c:var(--ok)}.hero.think{--c:var(--warn)}.hero.off{--c:var(--bad)}
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
.out{background:#0b121e;border-radius:10px;padding:12px;margin-top:8px;max-height:280px;overflow:auto;font-size:14px;line-height:1.55;overflow-wrap:anywhere}
.out h4{font:600 15px var(--serif);margin:8px 0 2px}.out code{font:12.5px var(--mono);background:var(--s2);padding:1px 5px;border-radius:5px}.out li{margin-left:18px}
.tl{border-left:2px solid var(--line);margin-left:6px}.ev{position:relative;padding:0 0 16px 16px}
.ev::before{content:"";position:absolute;left:-6px;top:6px;width:10px;height:10px;border-radius:50%;background:var(--brass)}
.ev b{font:600 14px var(--mono)}.ev time{color:var(--mut);font-size:12px;margin-left:8px}.ev div{color:var(--mut);font:12.5px var(--mono);overflow-wrap:anywhere;margin-top:2px}
.empty{text-align:center;color:var(--mut);padding:28px 10px}
.sk{height:110px;border-radius:14px;margin-bottom:12px;background:linear-gradient(90deg,var(--s1),var(--s2),var(--s1));background-size:200% 100%;animation:sh 1.4s infinite}@keyframes sh{to{background-position:-200% 0}}
nav{position:fixed;left:0;right:0;bottom:0;display:flex;background:var(--s1);border-top:1px solid var(--line);padding-bottom:env(safe-area-inset-bottom)}
nav button{flex:1;padding:10px 0 9px;color:var(--mut);font-size:12px;font-weight:600;display:grid;justify-items:center;gap:2px}
nav button svg{width:22px;height:22px;stroke:currentColor;fill:none;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}nav button.on{color:var(--brass)}
input{width:100%;padding:12px;margin-bottom:8px;background:var(--s2);border:1px solid var(--line);border-radius:10px;color:var(--tx);font-size:15px}
#toast{position:fixed;left:50%;bottom:calc(92px + env(safe-area-inset-bottom));transform:translate(-50%,12px);background:var(--s2);border:1px solid var(--brass);padding:9px 18px;border-radius:999px;font-size:14px;opacity:0;pointer-events:none;transition:.25s;z-index:9}
#toast.show{opacity:1;transform:translate(-50%,0)}#banner{display:none;background:#3a2326;color:var(--bad);border-radius:10px;padding:8px 12px;margin-top:12px;font-size:13px}
#login{display:none;margin-top:60px}#login h1{font:600 26px var(--serif);margin-bottom:6px}#login p{color:var(--mut);margin-bottom:16px}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
/* kucing */
#cat{transform:translate(40px,170px)}.fc{transition:none}
.p{display:none}[data-p=loaf] .zz,[data-p=think] .tb,[data-p=ask] .qb,[data-p=err] .eb,[data-p=look] .mag{display:block}
.eye{transform-box:fill-box;transform-origin:center;animation:blink 4s infinite}@keyframes blink{0%,94%,100%{transform:scaleY(1)}97%{transform:scaleY(.1)}}
[data-p=loaf] .eye{animation:none;transform:scaleY(.12)}[data-p=think] .eyes{transform:translateY(-3px)}
[data-p=loaf] .bodyg{transform:translateY(8px) scaleY(.72)}[data-p=loaf] .lg{opacity:0}[data-p=loaf] .paw{opacity:0}
[data-p=think] .bodyg{animation:tilt 2.4s ease-in-out infinite}@keyframes tilt{50%{transform:rotate(-5deg)}}
[data-p=walk] .bodyg{animation:hop .35s infinite}@keyframes hop{50%{transform:translateY(-3px)}}
[data-p=walk] .lg1{animation:step .35s infinite}[data-p=walk] .lg2{animation:step .35s infinite .17s}@keyframes step{50%{transform:translateY(-4px)}}
[data-p=type] .pa{animation:tap .3s infinite}[data-p=type] .pb{animation:tap .3s infinite .15s}@keyframes tap{50%{transform:translateY(-4px)}}
[data-p=ask] .pa{animation:wave .5s infinite alternate}@keyframes wave{from{transform:translate(-4px,-16px)}to{transform:translate(2px,-22px)}}
[data-p=look] .bodyg{animation:sniff 1.3s ease-in-out infinite}@keyframes sniff{50%{transform:translateX(3px) rotate(3deg)}}
.mag{animation:scan 1.5s ease-in-out infinite;transform-origin:26px -14px}@keyframes scan{50%{transform:rotate(-16deg)}}
[data-p=err] .bodyg{animation:shake .25s 4}@keyframes shake{25%{transform:translateX(-3px)}75%{transform:translateX(3px)}}
.tail{transform-origin:-14px -10px;animation:wag 1.4s ease-in-out infinite alternate}[data-p=loaf] .tail,[data-p=err] .tail{animation:none}@keyframes wag{to{transform:rotate(14deg)}}
.dots circle{animation:dot 1.4s infinite}.dots circle:nth-child(2){animation-delay:.2s}.dots circle:nth-child(3){animation-delay:.4s}@keyframes dot{50%{opacity:.25}}
.z{font:700 13px system-ui;fill:#9aa7bd;animation:fl 3s infinite}.z2{animation-delay:1.3s}@keyframes fl{0%{transform:translate(0,6px);opacity:0}30%{opacity:1}100%{transform:translate(8px,-14px);opacity:0}}
.bub{animation:bn .8s infinite alternate}@keyframes bn{to{transform:translateY(-4px)}}
.ln{transform-box:fill-box;transform-origin:left;animation:code 1.2s steps(6) infinite}@keyframes code{0%{transform:scaleX(.2)}100%{transform:scaleX(1)}}
#alarm{display:none;fill:#ff7a6b;pointer-events:none}svg[data-s=error] #alarm{display:block;animation:al 1s infinite}@keyframes al{50%{opacity:.22}0%,100%{opacity:0}}
.room{border-radius:16px;overflow:hidden;border:1px solid var(--line);background:var(--s1)}.room svg{width:100%;height:auto;display:block}.hero h1{margin-top:14px}
</style></head><body>
<div id="login"><h1>Masuk ke Hermes</h1><p>Masukkan token yang tampil di terminal PC saat cockpit dijalankan.</p>
<input id="tk" type="password" placeholder="Token akses" autocomplete="off"><button class="b main" style="width:100%" onclick="doLogin()">Masuk</button></div>
<main id="app" style="display:none">
<section class="hero" id="hero"><div class="room" id="room"></div>
<h1 id="h-title">Memeriksa Hermes…</h1><p id="h-sub">&nbsp;</p>
<button class="kill" id="kill"><i></i><span>Tahan untuk hentikan agen</span></button><div id="banner">PC tidak terjangkau. Memeriksa ulang…</div></section>
<div id="v-jobs"><div class="sec">Tugas terjadwal</div><div id="jobs"><div class="sk"></div><div class="sk"></div></div></div>
<div id="v-act" hidden><div class="sec">Aktivitas terbaru</div><div class="tl" id="acts"></div></div>
<div id="v-dev" hidden><div class="sec">Perangkat</div>
<div class="card"><div class="name" id="host">-</div><div class="meta" id="plat"></div></div>
<div class="sec">Tambah PC lain</div><div class="card"><input id="nn" placeholder="Nama (mis. PC Kantor)"><input id="nu" placeholder="100.x.y.z:8080">
<button class="b main" style="width:100%" onclick="addNode()">Simpan PC</button></div><div id="nodes"></div>
<button class="b" style="width:100%;margin-top:8px" onclick="logout()">Keluar</button></div></main>
<nav id="nav"><button class="on" data-t="jobs"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>Tugas</button>
<button data-t="act"><svg viewBox="0 0 24 24"><path d="M3 12h4l3-8 4 16 3-8h4"/></svg>Aktivitas</button>
<button data-t="dev"><svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/></svg>Perangkat</button></nav>
<div id="toast"></div>
<script>
const $=id=>document.getElementById(id);let tok=localStorage.getItem('hm_token')||'',timer=null,nodes=JSON.parse(localStorage.getItem('hermes_nodes')||'[]');
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function toast(m){const t=$('toast');t.textContent=m;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2200)}
function md(s){let h=esc(s).replace(/`([^`]+)`/g,'<code>$1</code>').replace(/\*\*([^*]+)\*\*/g,'<b>$1</b>');
return h.split('\n').map(l=>/^#{1,4} /.test(l)?'<h4>'+l.replace(/^#+ /,'')+'</h4>':/^\s*[-*] /.test(l)?'<li>'+l.replace(/^\s*[-*] /,'')+'</li>':l?l+'<br>':'<br>').join('')}
function rel(iso){const d=new Date(iso);if(isNaN(d))return iso&&iso!=='-'?iso:'-';let s=Math.round((d-Date.now())/1000),a=Math.abs(s),
u=a<60?[a,'dtk']:a<3600?[Math.round(a/60),'mnt']:a<86400?[Math.round(a/3600),'jam']:[Math.round(a/86400),'hari'];return s>=0?`dalam ${u[0]} ${u[1]}`:`${u[0]} ${u[1]} lalu`}
async function api(path,opt={}){const r=await fetch(path,{...opt,headers:{'Authorization':'Bearer '+tok,'Content-Type':'application/json'}});
if(r.status===401){logout(true);throw new Error('auth')}if(!r.ok)throw new Error(r.status);return r.json()}
function doLogin(){tok=$('tk').value.trim();if(!tok)return;localStorage.setItem('hm_token',tok);start()}
function logout(bad){localStorage.removeItem('hm_token');tok='';clearInterval(timer);$('app').style.display='none';$('nav').style.display='none';$('login').style.display='block';if(bad)toast('Token salah atau kedaluwarsa')}
function start(){$('login').style.display='none';$('app').style.display='block';$('nav').style.display='flex';poll();clearInterval(timer);timer=setInterval(poll,4000)}
document.addEventListener('visibilitychange',()=>{if(!tok)return;clearInterval(timer);if(!document.hidden){poll();timer=setInterval(poll,4000)}});
document.querySelectorAll('nav button').forEach(b=>b.onclick=()=>{document.querySelectorAll('nav button').forEach(x=>x.classList.toggle('on',x===b));
['jobs','act','dev'].forEach(t=>$('v-'+t).hidden=t!==b.dataset.t);if(b.dataset.t==='dev')renderNodes()});
async function poll(){try{const d=await api('/api/state');$('banner').style.display='none';hero(d.heartbeat,d.mascot);scene(d.mascot);$('host').textContent=d.hostname;$('plat').textContent=d.platform;jobs(d.cron_jobs);acts(d.tools)}
catch(e){if(e.message!=='auth')$('banner').style.display='block'}}
function hero(h,m){const el=$('hero');const st=h.fresh?m.state==='think'?'think':'live':h.status==='stale'?'stale':'off';el.className='hero '+st;
$('h-title').textContent=st==='live'?'Hermes aktif':st==='think'?'Hermes sedang berpikir':st==='stale'?'Hermes tidak merespons':'Hermes mati';
$('h-sub').textContent=st==='live'?'Gateway sehat · PID '+(h.pid||'?'):st==='think'?'Menunggu tugas baru':st==='stale'?'Detak terakhir sudah lama. Cek PC Anda.':'Gateway tidak berjalan di PC ini.'}
function jobs(list){if(!list||!list.length){$('jobs').innerHTML='<div class="empty">Belum ada tugas terjadwal di PC ini.</div>';return}
const open=new Set([...document.querySelectorAll('details[open]')].map(x=>x.dataset.id));
$('jobs').innerHTML=list.map(j=>{const paused=/pause/i.test(j.state),ok=j.last_status==='ok',cls=paused?'warn':ok?'ok':'bad',lbl=paused?'Dijeda':ok?'Berhasil':j.last_status==='unknown'?'Belum jalan':'Gagal';
return `<div class="card"><div class="row"><div><div class="name">${esc(j.name)}</div><div class="meta">${esc(j.schedule)} · berikutnya ${esc(rel(j.next_run_at))}</div></div><span class="chip ${cls}">${lbl}</span></div>
<div class="meta">Terakhir jalan ${esc(rel(j.last_run_at))} · ${j.completed}× selesai</div>
<div class="acts"><button class="b" onclick="act('${paused?'resume':'pause'}','${esc(j.id)}',this)">${paused?'Lanjutkan':'Jeda'}</button><button class="b main" onclick="act('run','${esc(j.id)}',this)">Jalankan sekarang</button></div>
<details data-id="${esc(j.id)}" ${open.has(j.id)?'open':''}><summary>Hasil terakhir${j.latest_file?' · '+esc(j.latest_file):''}</summary><div class="out">${md(j.latest_output)}</div></details></div>`}).join('')}
function acts(t){$('acts').innerHTML=!t||!t.length?'<div class="empty">Belum ada aktivitas tool di log.</div>':t.map(e=>`<div class="ev"><b>${esc(e.tool)}</b><time>${esc(e.timestamp.slice(11))}</time><div>${esc(e.details)}</div></div>`).join('')}
async function act(op,target,btn){if(btn)btn.disabled=true;try{await api('/api/action',{method:'POST',body:JSON.stringify({op,target})});
toast({pause:'Tugas dijeda',resume:'Tugas dilanjutkan',run:'Tugas dijalankan',kill:'Agen dihentikan'}[op]);setTimeout(poll,900)}catch(e){toast('Gagal mengirim perintah')}finally{if(btn)setTimeout(()=>btn.disabled=false,1200)}}
(()=>{const k=$('kill');let t;const on=e=>{e.preventDefault();k.classList.add('hold');t=setTimeout(()=>{k.classList.remove('hold');act('kill','')},1200)};
const off=()=>{clearTimeout(t);k.classList.remove('hold')};k.addEventListener('pointerdown',on);['pointerup','pointerleave','pointercancel'].forEach(n=>k.addEventListener(n,off))})();
function renderNodes(){$('nodes').innerHTML=nodes.map((n,i)=>`<div class="card row"><div><div class="name">${esc(n.name)}</div><div class="meta">${esc(n.url)}</div></div>
<div style="display:flex;gap:6px"><button class="chip" onclick="location.href='${esc(n.url)}'">Buka</button><button class="chip bad" onclick="delNode(${i})">Hapus</button></div></div>`).join('')}
function addNode(){const name=$('nn').value.trim();let url=$('nu').value.trim();if(!name||!url)return toast('Isi nama dan alamat PC');if(!/^https?:\/\//.test(url))url='http://'+url;
nodes.push({name,url});localStorage.setItem('hermes_nodes',JSON.stringify(nodes));$('nn').value=$('nu').value='';renderNodes();toast('PC disimpan')}
function delNode(i){nodes.splice(i,1);localStorage.setItem('hermes_nodes',JSON.stringify(nodes));renderNodes()}
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const F=(x,y,w,h,f,r=0)=>`<rect x="${x}" y="${y}" width="${w}" height="${h}" rx="${r}" fill="${f}"/>`;
const C=(x,y,r,f)=>`<circle cx="${x}" cy="${y}" r="${r}" fill="${f}"/>`;
const shelf=(x,w)=>{let s=F(x,88,w,82,'#3b2a1e',3),c=['#d9b26f','#7fd1b9','#ff7a6b','#9aa7bd','#eee9de'];for(let r=0;r<3;r++){const y=88+r*26;s+=F(x+3,y+24,w-6,3,'#5a4330');let bx=x+6,i=0;while(bx<x+w-12){const bw=5+(i*3)%5,bh=13+(i*7)%9;s+=F(bx,y+24-bh,bw,bh,c[(i+r)%5],1);bx+=bw+2;i++}}return s};
const door=x=>F(x,92,34,78,'#5a4330',3)+F(x+4,97,26,32,'#6b523b',2)+C(x+27,134,2.5,'#d9b26f');
const win=(x,w)=>F(x,70,w,58,'#0f2036',3)+C(x+w-16,86,6,'#eee9de')+F(x+w/2-1,70,2,58,'#5f7399')+F(x-3,128,w+6,5,'#5f7399',2);
const sofa=x=>F(x,150,84,20,'#7a5b8a',8)+F(x+6,128,72,26,'#8d6b9e',10)+F(x-6,138,14,32,'#7a5b8a',7)+F(x+76,138,14,32,'#7a5b8a',7);
const bed=x=>`<ellipse cx="${x}" cy="166" rx="30" ry="8" fill="#7a5b8a"/><ellipse cx="${x}" cy="164" rx="22" ry="5" fill="#9a78ab"/>`;
const desk=x=>F(x,150,78,6,'#8a6a47',2)+F(x+6,156,5,14,'#6b523b')+F(x+67,156,5,14,'#6b523b')+F(x+18,146,42,4,'#5f7399')+F(x+22,114,34,32,'#0b121e',3)+
 `<rect class="ln" x="${x+27}" y="122" width="18" height="3" fill="#7fd1b9"/><rect class="ln" x="${x+27}" y="130" width="24" height="3" fill="#d9b26f" style="animation-delay:.3s"/><rect class="ln" x="${x+27}" y="138" width="14" height="3" fill="#7fd1b9" style="animation-delay:.6s"/>`;
const wb=x=>F(x,84,58,38,'#eee9de',3)+F(x+6,94,30,3,'#5f7399')+F(x+6,104,42,3,'#d9b26f')+F(x+6,112,22,3,'#ff7a6b');
const globe=x=>C(x,140,15,'#3b6f8a')+F(x-2,155,4,10,'#8a6a47')+F(x-10,165,20,4,'#8a6a47',2)+`<path d="M${x-12} 136q12 8 24 0" stroke="#7fd1b9" fill="none" stroke-width="2"/>`;
const chair=x=>F(x,148,56,22,'#2f6b5e',8)+F(x+6,122,44,30,'#3a806f',10)+F(x-6,134,14,36,'#2f6b5e',7)+F(x+48,134,14,36,'#2f6b5e',7);
const plant=x=>F(x,152,16,18,'#8a6a47',3)+`<path d="M${x+8} 152q-14-18-6-30M${x+8} 152q0-22 4-34M${x+8} 152q14-14 12-28" stroke="#4fae8b" stroke-width="5" fill="none" stroke-linecap="round"/>`;
const CAT=`<g id="cat"><g class="face" id="fc" style="transform:scaleX(1)">
<path class="tail" d="M-16 -10q-24 2-20-24" stroke="#c98f5a" stroke-width="7" fill="none" stroke-linecap="round"/>
<g class="lg"><rect class="lg1" x="-12" y="-8" width="9" height="8" rx="4" fill="#b87f4c"/><rect class="lg2" x="4" y="-8" width="9" height="8" rx="4" fill="#b87f4c"/></g>
<g class="bodyg"><ellipse cx="0" cy="-20" rx="19" ry="18" fill="#e0a874"/><ellipse cx="0" cy="-12" rx="10" ry="8" fill="#f4dcbc"/>
<path d="M-15 -33l-3-15 12 8zM15 -33l3-15-12 8z" fill="#e0a874"/>
<g class="eyes"><ellipse class="eye" cx="-7" cy="-26" rx="2.6" ry="3.4" fill="#101826"/><ellipse class="eye" cx="7" cy="-26" rx="2.6" ry="3.4" fill="#101826"/></g>
<path d="M-2 -20l2 2 2-2z" fill="#e58f8f"/><path d="M-12 -19l-9-2M-12 -16l-9 3M12 -19l9-2M12 -16l9 3" stroke="#f4dcbc" stroke-width="1.3" stroke-linecap="round"/></g>
<circle class="paw pa" cx="14" cy="-8" r="5" fill="#f4dcbc"/><circle class="paw pb" cx="24" cy="-8" r="5" fill="#f4dcbc"/>
<g class="p mag"><line x1="26" y1="-12" x2="38" y2="-24" stroke="#a8864a" stroke-width="3" stroke-linecap="round"/><circle cx="43" cy="-30" r="8" fill="#7fd1b9" fill-opacity=".25" stroke="#d9b26f" stroke-width="2.5"/></g></g>
<g class="p zz"><text class="z" x="16" y="-44">z</text><text class="z z2" x="26" y="-56">Z</text></g>
<g class="p tb dots"><circle cx="14" cy="-52" r="2" fill="#9aa7bd"/><circle cx="22" cy="-60" r="3" fill="#9aa7bd"/><rect x="18" y="-92" width="44" height="24" rx="12" fill="#1f2d45" stroke="#5f7399"/><circle cx="31" cy="-80" r="2.5" fill="#eee9de"/><circle cx="40" cy="-80" r="2.5" fill="#eee9de"/><circle cx="49" cy="-80" r="2.5" fill="#eee9de"/></g>
<g class="p qb"><g class="bub"><circle cx="0" cy="-66" r="13" fill="#f0c36a"/><text x="0" y="-59" text-anchor="middle" style="font:700 18px system-ui" fill="#1b1608">?</text></g></g>
<g class="p eb"><g class="bub"><circle cx="0" cy="-66" r="13" fill="#ff7a6b"/><text x="0" y="-59" text-anchor="middle" style="font:700 18px system-ui" fill="#2a0d09">!</text></g></g></g>`;
const RM={s:{idle:140,think:140,type:274,search:[372,400],err:200},f:{idle:1,think:1,type:1,err:1}};
const TX={idle:'Meringkuk di sofa, menunggu tugas.',think:'Sedang berpikir… mencari ide.',type:'Mengetik di meja kerja',search:'Menyisir rak buku',err:'Alarm menyala. Cek PC Anda.'};
let cur='',run=0;
function mount(){$('room').innerHTML=`<svg viewBox="0 0 420 200" data-s="ok" role="img" aria-label="Kucing Hermes di rumah">${F(0,0,420,170,'#2d2a3e')}${F(0,170,420,30,'#4a3b3b')}${door(10)+sofa(96)+win(206,52)+plant(268)+desk(282)+shelf(366,50)}${CAT}<rect id="alarm" width="420" height="200"/></svg>`;const c=$('cat');c.style.transform=`translate(${RM.s.idle}px,170px)`;c.dataset.p='loaf'}\nasync function go(x){const c=$('cat'),cu=new DOMMatrix(getComputedStyle(c).transform).m41,d=Math.abs(x-cu);if(d>3){$('fc').style.transform=`scaleX(${x>cu?1:-1})`;c.dataset.p='walk';const t=d/62;c.style.transition=`transform ${t}s linear`;c.style.transform=`translate(${x}px,170px)`;await sleep(t*1000+60)}}\nasync function scene(m){if(!m)return;const s=m.state;$('h-sub').textContent=TX[s]+(m.tool&&(s==='type'||s==='search')?' · '+m.tool:'');if(s===cur)return;cur=s;const my=++run,c=$('cat');\n$('room').firstChild.dataset.s=s==='err'?'error':'ok';\nif(s==='search'){while(my===run)for(const x of RM.s.search){if(my!==run)return;await go(x);if(my!==run)return;c.dataset.p='look';await sleep(1700)}return}\nawait go(RM.s[s]);if(my!==run)return;$('fc').style.transform=`scaleX(${RM.f[s]})`;c.dataset.p={idle:'loaf',think:'think',type:'type',err:'err'}[s]}\nmount();\ntok?start():logout();\n</script></body></html>"""


def mascot_state_updated():
    """Improved detector mascot state dengan kategori tool yang lengkap."""
    hb = ck.read_heartbeat()
    
    if not hb.get("fresh"):
        return {"state": "err", "tool": None}
    
    tools = ck.read_recent_tool_executions(5)
    
    if tools:
        t = tools[0]
        try:
            ts = datetime.strptime(t["timestamp"], "%Y-%m-%d %H:%M:%S")
            age = (datetime.now() - ts).total_seconds()
        except Exception:
            age = 9999
        
        if -2 <= age <= 50:
            tool_name = t["tool"]
            category = get_tool_category(tool_name)
            return {"state": category, "tool": tool_name}
    
    return {"state": "think", "tool": None}


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
        if p == "/icon.svg": return self._send(200, ICON.encode(), "image/svg+xml")
        if p == "/manifest.json":
            return self._send(200, {"name": "Hermes Cockpit", "short_name": "Hermes", "display": "standalone", "start_url": "/",
                                    "background_color": "#101826", "theme_color": "#101826",
                                    "icons": [{"src": "/icon.svg", "sizes": "any", "type": "image/svg+xml", "purpose": "any"}]})
        if p == "/api/state":
            if not self._authed(): return self._send(401, {"error": "unauthorized"})
            return self._send(200, {"hostname": ck.HOSTNAME, "platform": platform.system(), "heartbeat": ck.read_heartbeat(),
                                    "cron_jobs": ck.read_cron_jobs(), "tools": ck.read_recent_tool_executions(15),
                                    "mascot": mascot_state_updated()})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if urlparse(self.path).path != "/api/action": return self._send(404, {"error": "not found"})
        if not self._authed(): return self._send(401, {"error": "unauthorized"})
        try:
            n = min(int(self.headers.get("Content-Length", 0)), 1024)
            body = json.loads(self.rfile.read(n) or b"{}")
            op, target = str(body.get("op", "")), str(body.get("target", ""))
        except Exception:
            return self._send(400, {"error": "bad request"})
        if op == "kill":
            ck.execute_action("kill")
        elif op in ("pause", "resume", "run") and target in {j.get("id") for j in ck.read_cron_jobs()}:
            ck.execute_action(op, target)
        else:
            return self._send(400, {"error": "invalid action"})
        self._send(200, {"ok": True})


def main():
    global TOKEN
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--host", default=None, help="Default: IP Tailscale, atau 127.0.0.1 bila tidak ada")
    ap.add_argument("--hermes-dir", default=None)
    ap.add_argument("--token", default=os.environ.get("COCKPIT_TOKEN"))
    a = ap.parse_args()
    ck.HERMES_DIR = ck.resolve_hermes_dir(a.hermes_dir)
    TOKEN = a.token or secrets.token_urlsafe(24)
    ts_ip, _ = ck.get_detected_ips()
    host = a.host or ts_ip or "127.0.0.1"
    print(f"Hermes Cockpit v2 (mascot improved)\n  Hermes : {ck.HERMES_DIR}\n  Alamat : http://{host}:{a.port}\n  Token  : {TOKEN}")
    if host == "0.0.0.0": print("  PERINGATAN: 0.0.0.0 membuka cockpit ke seluruh jaringan Wi-Fi.", file=sys.stderr)
    try:
        ThreadingHTTPServer((host, a.port), Handler).serve_forever()
    except KeyboardInterrupt:
        print("\nBerhenti.")


if __name__ == "__main__":
    main()
