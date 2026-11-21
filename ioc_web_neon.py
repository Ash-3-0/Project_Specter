# SPECTER WEB GUI (AbuseIPDB + VirusTotal), hosted locally
# Run:  python ioc_web_neon.py          (no pip install needed, standard library only)
# Open: http://127.0.0.1:8765  (opens automatically)
# Keys: fill keys.json (next to this file / the exe), or type them in the page, or set env vars
#       ABUSEIPDB_KEY, VT_KEY, HONEYPOT_KEY. Defaults load automatically and are only sent to the page if you tick 'show keys'.
# The server listens on 127.0.0.1 only, so nobody else on your network can reach it.

import os
import re
import sys
import json
import ipaddress
import socket
import threading
import webbrowser
import urllib.request
import urllib.parse
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"
VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/"
HOST, PORT = "127.0.0.1", int(os.getenv("PORT", "8765"))


DOWNLOAD_URL = ""  # put your GitHub releases link here, e.g. "https://github.com/<user>/specter-web/releases"
NO_KEYS_MSG = "You don't have access to the API keys. Download the exe for more."

KEYS_NOTES = []  # human-readable log of where default keys came from (shown at startup)


def load_default_keys(default_rate):
    """Default keys: keys.json bundled in the exe, then next to the exe/script, then in the current folder, then env vars."""
    d = {"abuse": "", "vt": "", "hp": "", "rate": default_rate}
    places = []
    if getattr(sys, "_MEIPASS", None):
        places.append(os.path.join(sys._MEIPASS, "keys.json"))
    base = os.path.dirname(sys.executable) if getattr(sys, "frozen", False) else os.path.dirname(os.path.abspath(__file__))
    for p in (os.path.join(base, "keys.json"), os.path.join(os.getcwd(), "keys.json")):
        if p not in places:
            places.append(p)
    loaded = False
    for p in places:
        if not os.path.isfile(p):
            continue
        try:
            with open(p, encoding="utf-8-sig") as f:  # utf-8-sig also accepts files saved with a BOM
                j = json.load(f)
        except (OSError, ValueError) as e:
            KEYS_NOTES.append("keys.json could not be read (%s): %s" % (p, e))
            continue
        loaded = True
        KEYS_NOTES.append("keys.json loaded from " + p)
        for k, jk in (("abuse", "abuseipdb_key"), ("vt", "vt_key"), ("hp", "honeypot_key")):
            if str(j.get(jk, "")).strip():
                d[k] = str(j[jk]).strip()
        try:
            d["rate"] = max(1, min(1000, int(j.get("vt_per_min", d["rate"]))))
        except (TypeError, ValueError):
            pass
    if not loaded and not KEYS_NOTES:
        KEYS_NOTES.append("keys.json not found. Looked in: " + " | ".join(places))
    for k, ev in (("abuse", "ABUSEIPDB_KEY"), ("vt", "VT_KEY"), ("hp", "HONEYPOT_KEY")):
        if os.getenv(ev):
            d[k] = os.getenv(ev).strip()
    return d


DEFAULT_KEYS = load_default_keys(4)

# Browser tab icon (neon ghost logo), served at /favicon.svg
FAVICON_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
<defs><filter id="g" x="-40%" y="-40%" width="180%" height="180%"><feGaussianBlur stdDeviation="2" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs>
<rect x="2" y="2" width="60" height="60" rx="15" fill="#0a0a12" stroke="#ff2bd6" stroke-width="3"/>
<path d="M18 47V30a14 14 0 0 1 28 0v17l-4.7-4.2-4.6 4.2-4.7-4.2-4.7 4.2-4.6-4.2z" fill="#00f5ff" fill-opacity=".14" stroke="#00f5ff" stroke-width="3.4" stroke-linejoin="round" filter="url(#g)"/>
<circle cx="26.5" cy="30" r="3.2" fill="#ff2bd6" filter="url(#g)"/><circle cx="37.5" cy="30" r="3.2" fill="#ff2bd6" filter="url(#g)"/>
</svg>"""

APP_NAME = "SPECTER"
AUTHOR = "Sparsh Bisht"
COMPANY = "AshHunts.pvtltd"
CREDIT = "developed by " + AUTHOR + " // " + COMPANY
BANNER = r"""
 ____   ____   _____   ____  _____  _____  ____
/ ___| |  _ \ | ____| / ___||_   _|| ____||  _ \
\___ \ | |_) ||  _|  | |      | |  |  _|  | |_) |
 ___) ||  __/ | |___ | |___   | |  | |___ |  _ <
|____/ |_|    |_____| \____|  |_|  |_____||_| \_\
"""


def print_banner():
    """Colored CLI banner. Silent in windowed exes (no console)."""
    if sys.stdout is None:
        return
    if os.name == "nt" and sys.stdout.isatty():
        os.system("")  # enables ANSI colors on Windows 10+ consoles
    print("\033[94m" + BANNER + "\033[0m")
    print("\033[37m  " + CREDIT + "\033[0m")
    print("\033[90m  AbuseIPDB + VirusTotal + Project Honey Pot // bulk IP threat lookup\033[0m\n")



def http_json(url, headers):
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode("utf-8"))


def verdict_for(score):
    if score >= 75:
        return "Malicious"
    if score >= 25:
        return "Suspicious"
    return "Clean"

def check_honeypot(ip, key):
    """Project Honey Pot http:BL lookup (DNS based, IPv4 only)."""
    try:
        if ipaddress.ip_address(ip).version != 4:
            return "n/a (IPv4 only)"
    except ValueError:
        return "-"
    if not re.fullmatch(r"[a-z]{12}", key or ""):
        return "Bad key format"
    q = key + "." + ".".join(reversed(ip.split("."))) + ".dnsbl.httpbl.org"
    try:
        res = socket.gethostbyname(q)
    except socket.gaierror as e:
        return "Not listed" if e.errno in (socket.EAI_NONAME, getattr(socket, "EAI_NODATA", -5)) else "DNS error"
    except (UnicodeError, OSError):
        return "DNS error"
    a, days, threat, vtype = (int(x) for x in res.split("."))
    if a != 127:
        return "Bad key/response"
    if vtype == 0:
        return "Search engine"
    kinds = [n for bit, n in ((1, "Suspicious"), (2, "Harvester"), (4, "Comment spammer")) if vtype & bit]
    return "T%d | %dd | %s" % (threat, days, "/".join(kinds) or "Listed")


def blacklist_status(score, vt_mal, hp):
    """BLACKLISTED if any source flags the IP: AbuseIPDB >= 75, VirusTotal >= 3 engines, or Honey Pot listing."""
    src = []
    if isinstance(score, int) and score >= 75:
        src.append("ABUSE")
    if isinstance(vt_mal, int) and vt_mal >= 3:
        src.append("VT")
    if isinstance(hp, str) and hp.startswith("T") and "|" in hp:
        src.append("HP")
    return "BLACKLISTED [" + "+".join(src) + "]" if src else "NOT BLACKLISTED"


def explain(api, e):
    """Short human-readable reason for an API failure."""
    if isinstance(e, urllib.error.HTTPError):
        if e.code in (401, 403):
            return "%s: key rejected (%d)" % (api, e.code)
        if e.code == 429:
            return "%s: rate limit (429)" % api
        return "%s: HTTP %d" % (api, e.code)
    if isinstance(e, TimeoutError) or "timed out" in str(e):
        return "%s: timeout" % api
    if isinstance(e, urllib.error.URLError):
        return "%s: no connection" % api
    return "%s: bad response" % api


def check(ip, abuse_key, vt_key, hp_key=""):
    """Returns {row:[...9 cols], tag, kind, err}. Same logic as the desktop GUI."""
    dash = "-"
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"row": [ip, dash, "Invalid IP"] + [dash] * 6, "tag": "Error", "kind": "invalid"}
    if addr.is_private:
        return {"row": [ip, dash, "Localhost" if addr.is_loopback else "Private"] + [dash] * 6,
                "tag": "Skipped", "kind": "skip"}
    errs = (urllib.error.URLError, KeyError, TimeoutError, json.JSONDecodeError, OSError)
    try:
        d = http_json(ABUSE_URL + "?" + urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90}),
                      {"Key": abuse_key, "Accept": "application/json"})["data"]
    except errs as e:
        reason = explain("Abuse", e)
        return {"row": [ip, dash, "Error: " + reason] + [dash] * 6, "tag": "Error", "kind": "api_error", "err": reason}
    vm = vs = "n/a"
    vt_err = None
    try:
        vt = http_json(VT_URL + ip, {"x-apikey": vt_key})["data"]["attributes"]["last_analysis_stats"]
        vm, vs = vt["malicious"], vt["suspicious"]
    except errs as e:
        vt_err = explain("VT", e)
    hp = check_honeypot(ip, hp_key) if hp_key else dash
    score = d["abuseConfidenceScore"]
    v = verdict_for(score)
    res = {"row": [d["ipAddress"], score, v, d.get("countryCode") or dash, d["totalReports"], vm, vs, hp,
                   blacklist_status(score, vm, hp)], "tag": v, "kind": "ok"}
    if vt_err:
        res.update(kind="vt_error", err=vt_err)
    return res


class Server(ThreadingHTTPServer):
    """Never share a port with a stale instance (on Windows SO_REUSEADDR lets two servers bind the same port,
    so an old SPECTER_Web without keys could keep answering the browser)."""
    allow_reuse_address = os.name != "nt"

    def server_bind(self):
        if os.name == "nt" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, body, ctype):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self.send(200, PAGE, "text/html; charset=utf-8")
        elif self.path in ("/favicon.svg", "/favicon.ico"):
            self.send(200, FAVICON_SVG, "image/svg+xml")
        elif self.path == "/api/env":
            self.send(200, json.dumps({"abuse": bool(DEFAULT_KEYS["abuse"]), "vt": bool(DEFAULT_KEYS["vt"]), "hp": bool(DEFAULT_KEYS["hp"]), "rate": DEFAULT_KEYS["rate"], "notes": KEYS_NOTES, "msg": NO_KEYS_MSG, "download": DOWNLOAD_URL}),
                      "application/json")
        elif self.path == "/api/keys":
            # only for the local page itself: Host must be localhost and a custom header is required
            # (a custom header makes cross-site requests need a CORS preflight, which is never answered)
            host = self.headers.get("Host", "").rsplit(":", 1)[0].strip("[]")
            if host not in ("127.0.0.1", "localhost") or self.headers.get("X-Specter") != "1":
                return self.send(403, "forbidden", "text/plain")
            self.send(200, json.dumps({"abuse": DEFAULT_KEYS["abuse"], "vt": DEFAULT_KEYS["vt"], "hp": DEFAULT_KEYS["hp"]}),
                      "application/json")
        else:
            self.send(404, "not found", "text/plain")

    def do_POST(self):
        if self.path != "/api/check":
            return self.send(404, "not found", "text/plain")
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
            ak = body.get("abuse_key") or DEFAULT_KEYS["abuse"]
            vk = body.get("vt_key") or DEFAULT_KEYS["vt"]
            hk = body.get("hp_key") or DEFAULT_KEYS["hp"]
            res = check(str(body.get("ip", "")).strip(), ak, vk, hk)
        except Exception as e:  # never crash the server on a bad request
            res = {"row": ["-"] * 9, "tag": "Error", "kind": "api_error", "err": str(e)}
        self.send(200, json.dumps(res), "application/json")


PAGE = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SPECTER</title>
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<style>
:root{--bg:#0d1117;--panel:#161b22;--field:#0d1117;--line:#30363d;--text:#e6edf3;--dim:#8b949e;--accent:#4c8dff;--green:#3fb950;--yellow:#d29922;--red:#f85149;--orange:#f0883e;--head:#1c2128;--sel:#1f3050;
--font:"Segoe UI",system-ui,-apple-system,"Helvetica Neue",Arial,sans-serif;--mono:Consolas,"Cascadia Mono","SF Mono",Menlo,monospace}
*{box-sizing:border-box}
html,body{height:100%}
body{margin:0;background:var(--bg);color:var(--text);font:13px/1.4 var(--font);display:flex;flex-direction:column;padding:20px 28px 16px;min-width:900px;overflow:auto}
.head{display:flex;align-items:center}
.logo{font-size:26px;font-weight:700;letter-spacing:.14em}
.spacer{flex:1}
#dot{font-size:12px;color:var(--green);margin-right:8px}
#status{font-size:13px;font-weight:600;color:var(--green)}
.sub{color:var(--dim);font-size:12px;margin-top:2px}
#strip{height:1px;margin:12px 0 14px;background:var(--line)}
.top{display:grid;grid-template-columns:3fr 2fr;gap:16px}
.box{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px 16px 14px}
.box h3{margin:0 0 10px;font-size:13px;font-weight:600}
textarea,input.k{width:100%;background:var(--field);color:var(--text);font:13px var(--mono);outline:none;border:1px solid var(--line);border-radius:6px}
textarea{height:110px;resize:none;padding:8px 10px;display:block}
input.k{height:34px;padding:0 10px;margin-bottom:8px}
input.k::placeholder{color:var(--dim);font-family:var(--font)}
textarea:focus,input.k:focus,#rate:focus{border-color:var(--accent);box-shadow:0 0 0 2px rgba(76,141,255,.25)}
.row{display:flex;align-items:center;gap:10px;margin-top:10px}
.btn{height:34px;min-width:90px;padding:0 16px;border-radius:6px;border:1px solid var(--line);background:transparent;color:var(--text);font:600 13px var(--font);cursor:pointer;white-space:nowrap}
.btn:hover:not(:disabled){background:rgba(255,255,255,.07)}
.btn.fill{background:var(--accent);border-color:var(--accent);color:#fff}
.btn.fill:hover:not(:disabled){background:#6aa0ff}
.btn.danger{color:var(--red);border-color:rgba(248,81,73,.55)}
.btn.danger:hover:not(:disabled){background:rgba(248,81,73,.14)}
.btn:disabled{opacity:.45;cursor:default}
label.sk{display:flex;align-items:center;gap:8px;color:var(--dim);font-size:12px;cursor:pointer;width:max-content}
label.sk input{appearance:none;width:16px;height:16px;border:1px solid var(--line);border-radius:4px;margin:0;display:grid;place-content:center;cursor:pointer}
label.sk input:checked{background:var(--accent);border-color:var(--accent)}
label.sk input:checked::after{content:"";width:4px;height:8px;border:solid #fff;border-width:0 2px 2px 0;transform:rotate(45deg) translate(-1px,-1px)}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:14px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;text-align:center;padding:10px 0 8px}
.card b{display:block;font-size:12px;font-weight:400;color:var(--dim)}
.card span{display:block;font-size:28px;font-weight:700;line-height:1.3;color:var(--c)}
.tbl{flex:1;min-height:200px;background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:8px;display:flex}
.scroll{flex:1;overflow:auto;background:var(--field);scrollbar-color:var(--line) var(--field)}
.scroll::-webkit-scrollbar{width:12px}.scroll::-webkit-scrollbar-track{background:var(--field)}.scroll::-webkit-scrollbar-thumb{background:var(--line);border-radius:6px}
table{width:100%;border-collapse:collapse;table-layout:fixed;font-size:12px;user-select:none}
th{position:sticky;top:0;background:var(--head);color:var(--text);font-weight:600;font-size:12px;padding:8px 6px;text-align:center}
th:hover{background:var(--line)}
td{height:30px;text-align:center;border:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
tr.sel td{background:var(--sel);color:#fff!important}
.bottom{display:flex;align-items:center;gap:10px;margin-top:14px}
.prog{flex:1;height:10px;margin:0 8px;border-radius:5px;background:var(--field);border:1px solid var(--line);overflow:hidden}
.prog i{display:block;height:100%;width:0;background:var(--accent);transition:width .2s}
#pct{width:50px;text-align:center;font-size:13px;color:var(--dim)}
</style></head><body>
<div class="head">
  <span class="logo">SPECTER</span>
  <span class="spacer"></span><span id="dot">●</span><span id="status">Ready</span>
</div>
<div class="sub" style="display:flex"><span>AbuseIPDB &nbsp;·&nbsp; VirusTotal &nbsp;·&nbsp; bulk IP reputation lookup</span><span class="spacer"></span><span>developed by Sparsh Bisht // AshHunts.pvtltd</span></div>
<div id="keynote" class="sub" style="display:none;color:var(--yellow);margin-top:6px"></div>
<div id="strip"></div>

<div class="top">
  <div class="box">
    <h3>Target IPs</h3>
    <textarea id="ips" spellcheck="false"></textarea>
    <div class="row"><button class="btn" id="load">Load ips.txt</button><button class="btn" id="clear">Clear</button>
    <input type="file" id="file" accept=".txt,text/plain" hidden></div>
  </div>
  <div class="box">
    <h3>API Keys</h3>
    <input class="k" id="ak" type="password" placeholder="AbuseIPDB key" autocomplete="off">
    <input class="k" id="vk" type="password" placeholder="VirusTotal key" autocomplete="off">
    <input class="k" id="hk" type="password" placeholder="Honeypot key (optional)" autocomplete="off">
    <div style="display:flex;align-items:center;gap:8px"><label class="sk"><input type="checkbox" id="show"> show keys</label>
      <span class="spacer"></span><span style="color:var(--dim);font-size:12px">VT req/min</span>
      <input id="rate" type="text" value="4" inputmode="numeric" aria-label="VirusTotal requests per minute" style="width:56px;height:30px;text-align:center;background:var(--field);color:var(--text);border:1px solid var(--line);border-radius:6px;font:12px var(--mono);outline:none"></div>
  </div>
</div>

<div class="stats">
  <div class="card" style="--c:var(--text)"><b>Scanned</b><span id="s-Total">0</span></div>
  <div class="card" style="--c:var(--red)"><b>Malicious</b><span id="s-Malicious">0</span></div>
  <div class="card" style="--c:var(--yellow)"><b>Suspicious</b><span id="s-Suspicious">0</span></div>
  <div class="card" style="--c:var(--green)"><b>Clean</b><span id="s-Clean">0</span></div>
</div>

<div class="tbl"><div class="scroll" id="sc"><table>
  <colgroup><col style="width:150px"><col style="width:95px"><col style="width:200px"><col style="width:75px"><col style="width:75px"><col style="width:110px"><col style="width:120px"><col style="width:190px"><col style="width:230px"></colgroup>
  <thead><tr id="th"></tr></thead><tbody id="tb"></tbody></table></div></div>

<div class="bottom">
  <button class="btn fill" id="start" style="min-width:120px">▶&nbsp; Scan</button>
  <button class="btn danger" id="stop" style="min-width:100px" disabled>■&nbsp; Stop</button>
  <button class="btn" id="export" style="min-width:130px">Export CSV</button>
  <div class="prog"><i id="bar"></i></div><div id="pct">0%</div>
</div>

<script>
(function(){
var $=function(i){return document.getElementById(i)};
var COLS=["ip","abuse_score","verdict","country","reports","vt_malicious","vt_suspicious","honeypot","blacklisted"];
var HEADS=["IP Address","Abuse Score","Verdict","Country","Reports","VT Malicious","VT Suspicious","Honeypot","Blacklisted"];
var C={cyan:"#4c8dff",magenta:"#f0883e",green:"#3fb950",yellow:"#d29922",red:"#f85149",dim:"#8b949e"}; /* cyan = accent blue, magenta = error orange */
var TAGC={Malicious:C.red,Suspicious:C.yellow,Clean:C.green,Skipped:C.dim,Error:C.magenta};
var env={abuse:false,vt:false},vtTimes=[],MASK="\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022";
function kv(id){var v=$(id).value.trim();return v===MASK?"":v}
var st={total:0,done:0,counts:{Malicious:0,Suspicious:0,Clean:0},running:false,stop:false,tick:0};
var rows=[],last=-1;

$("th").innerHTML=HEADS.map(function(h){return"<th>"+h+"</th>"}).join("");
fetch("/api/env").then(function(r){return r.json()}).then(function(e){env=e;
  /* default keys stay on the server; the boxes just show a mask so you can see they are loaded */
  if(e.abuse)$("ak").value=MASK;
  if(e.vt)$("vk").value=MASK;
  if(e.hp)$("hk").value=MASK;
  if(e.rate)$("rate").value=e.rate;
  var n=(e.abuse?1:0)+(e.vt?1:0)+(e.hp?1:0);
  if(n)setStatus("Ready · default keys loaded "+n+"/3",C.green);
  else{setStatus("Ready · no default keys",C.yellow);var k=$("keynote");k.textContent=e.msg||"You don't have access to the API keys. Download the exe for more.";
    if(e.download){k.appendChild(document.createTextNode(" "));var a=document.createElement("a");a.href=e.download;a.target="_blank";a.rel="noopener";a.textContent="Download";a.style.color="var(--accent)";k.appendChild(a)}
    k.style.display="block"}
}).catch(function(){setStatus("Cannot reach /api/env - is another SPECTER window open? Close it and restart",C.magenta);var k=$("keynote");k.textContent="Default keys could not be loaded from the server.";k.style.display="block"});

function setStatus(t,c){$("status").textContent=t;$("status").style.color=c}
function stats(){$("s-Total").textContent=st.done;for(var k in st.counts)$("s-"+k).textContent=st.counts[k]}
function sleep(ms){return new Promise(function(r){setTimeout(r,ms)})}

setInterval(function(){st.tick++;if(st.running)$("dot").style.color=(Math.floor(st.tick/5)%2)?C.dim:C.cyan},100);

$("show").onchange=function(){var chk=this.checked,t=chk?"text":"password";
  function flip(){$("ak").type=t;$("vk").type=t;$("hk").type=t}
  if(chk&&($("ak").value===MASK||$("vk").value===MASK||$("hk").value===MASK)){
    fetch("/api/keys",{headers:{"X-Specter":"1"}}).then(function(r){return r.json()}).then(function(k){
      if($("ak").value===MASK)$("ak").value=k.abuse||"";
      if($("vk").value===MASK)$("vk").value=k.vt||"";
      if($("hk").value===MASK)$("hk").value=k.hp||"";flip()}).catch(flip)
  }else flip()};
$("clear").onclick=function(){$("ips").value=""};
$("load").onclick=function(){$("file").click()};
$("file").onchange=function(e){var f=e.target.files[0];if(!f)return;var r=new FileReader();
  r.onload=function(){$("ips").value=r.result};r.readAsText(f);e.target.value=""};

function addRow(vals,tag){
  var tr=document.createElement("tr"),i=rows.length;
  tr.style.color=TAGC[tag]||"#e6edf3";
  tr.innerHTML=vals.map(function(v){return"<td>"+String(v).replace(/[&<>]/g,function(c){return{"&":"&amp;","<":"&lt;",">":"&gt;"}[c]})+"</td>"}).join("");
  tr.onclick=function(ev){
    if(ev.shiftKey&&last>=0){var a=Math.min(last,i),b=Math.max(last,i);rows.forEach(function(r,j){r.tr.classList.toggle("sel",j>=a&&j<=b)})}
    else if(ev.ctrlKey||ev.metaKey){tr.classList.toggle("sel");last=i}
    else{rows.forEach(function(r){r.tr.classList.remove("sel")});tr.classList.add("sel");last=i}};
  rows.push({tr:tr,vals:vals});$("tb").appendChild(tr);
  $("sc").scrollTop=$("sc").scrollHeight}

document.addEventListener("keydown",function(e){
  if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==="c"&&!/INPUT|TEXTAREA/.test(document.activeElement.tagName)&&!String(getSelection())){
    var t=rows.filter(function(r){return r.tr.classList.contains("sel")}).map(function(r){return r.vals.join("\t")}).join("\n");
    if(t){e.preventDefault();navigator.clipboard.writeText(t)}}});

$("start").onclick=async function(){
  var ak=kv("ak"),vk=kv("vk"),hk=kv("hk"),rate=Math.max(1,Math.min(1000,parseInt($("rate").value,10)||4));
  if((!ak&&!env.abuse)||(!vk&&!env.vt)){alert("Enter both AbuseIPDB and VirusTotal keys.\n\n"+(env.msg||"You don't have access to the API keys. Download the exe for more."));return}
  var seen={},ips=[];
  $("ips").value.split(/\r?\n/).forEach(function(l){l=l.trim();if(l&&!seen[l]){seen[l]=1;ips.push(l)}});
  if(!ips.length){alert("Add some IPs first.");return}
  $("tb").innerHTML="";rows=[];last=-1;
  st.total=ips.length;st.done=0;st.counts={Malicious:0,Suspicious:0,Clean:0};st.stop=false;st.running=true;vtTimes=[];
  stats();$("bar").style.width="0";$("pct").textContent="0%";
  $("start").disabled=true;$("stop").disabled=false;
  for(var n=0;n<ips.length;n++){
    if(st.stop)break;
    for(;;){var now=Date.now();vtTimes=vtTimes.filter(function(t){return now-t<60000});
      if(vtTimes.length<rate||st.stop)break;
      setStatus("Rate limit cooldown  "+Math.ceil((60000-(now-vtTimes[0]))/1000)+"s",C.yellow);await sleep(1000)}
    if(st.stop)break;
    var ip=ips[n];setStatus("Scanning "+ip+"  ["+(n+1)+"/"+ips.length+"]",C.cyan);
    var res;
    try{
      var r=await fetch("/api/check",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({ip:ip,abuse_key:ak,vt_key:vk,hp_key:hk})});
      res=await r.json();
    }catch(e){res={row:[ip,"-","API error","-","-","-","-","-","-"],tag:"Error",kind:"api_error",err:"local server unreachable"}}
    addRow(res.row,res.tag);st.done++;
    if(st.counts.hasOwnProperty(res.tag))st.counts[res.tag]++;
    stats();var f=st.done/st.total;$("bar").style.width=(f*100)+"%";$("pct").textContent=Math.floor(f*100)+"%";
    if(res.err)setStatus("Error "+ip+": "+res.err,C.magenta);
    if(res.kind==="ok"||res.kind==="api_error"||res.kind==="vt_error")vtTimes.push(Date.now());
    if(res.err&&/VT.*429/.test(String(res.err))){for(var z=0;z<rate;z++)vtTimes.push(Date.now())}
  }
  st.running=false;$("dot").style.color=C.green;$("start").disabled=false;$("stop").disabled=true;
  setStatus("Done · "+st.done+"/"+st.total+" scanned",C.green)};

$("stop").onclick=function(){st.stop=true;setStatus("Aborting…",C.yellow)};

$("export").onclick=function(){
  if(!rows.length){alert("No results yet.");return}
  var q=function(v){v=String(v);return/[",\n]/.test(v)?'"'+v.replace(/"/g,'""')+'"':v};
  var csv=[COLS.join(",")].concat(rows.map(function(r){return r.vals.map(q).join(",")})).join("\r\n")+"\r\n";
  var a=document.createElement("a");a.href=URL.createObjectURL(new Blob([csv],{type:"text/csv"}));a.download="results.csv";
  document.body.appendChild(a);a.click();setTimeout(function(){URL.revokeObjectURL(a.href);a.remove()},500);
  setStatus("Saved · results.csv",C.green)};
})();
</script></body></html>"""


def main():
    print_banner()
    loaded = sum(bool(DEFAULT_KEYS[k]) for k in ("abuse", "vt", "hp"))
    print(f"  default keys loaded: {loaded}/3  (keys.json / env)")
    for note in KEYS_NOTES:
        print("  " + note)
    port = PORT
    for _ in range(10):
        try:
            srv = Server((HOST, port), Handler)
            break
        except OSError:
            port += 1
    else:
        sys.exit("No free port found, set PORT=xxxx and retry.")
    url = f"http://{HOST}:{port}"
    print(f"  running at {url}  (Ctrl+C to quit)")
    threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()
