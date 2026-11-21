# SPECTER GUI (AbuseIPDB + VirusTotal)
# Run: pip install customtkinter requests
#      python ioc_gui_neon.py
# Keys: fill keys.json (next to this file / the exe), or type them in the app, or set env vars
#       ABUSEIPDB_KEY, VT_KEY, HONEYPOT_KEY. Defaults load automatically at startup.

import os
import re
import sys
import csv
import json
import time
import queue
import threading
import ipaddress
import socket
from collections import deque
import requests
import customtkinter as ctk
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"
VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/"
VT_PER_MIN = 4  # VirusTotal free tier = 4 requests/min. Premium keys: raise it in the app (VT req/min box)


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

COLUMNS = ["ip", "abuse_score", "verdict", "country", "reports", "vt_malicious", "vt_suspicious", "honeypot", "blacklisted"]
HEADS = ["IP Address", "Abuse Score", "Verdict", "Country", "Reports", "VT Malicious", "VT Suspicious", "Honeypot", "Blacklisted"]
WIDTHS = [150, 95, 200, 75, 75, 110, 120, 190, 230]

# Palette: dark slate with one blue accent
BG = "#0d1117"
PANEL = "#161b22"
FIELD = "#0d1117"
BORDER = "#30363d"
TEXT = "#e6edf3"
DIM = "#8b949e"
ACCENT = "#4c8dff"
RED = "#f85149"
YELLOW = "#d29922"
GREEN = "#3fb950"
ORANGE = "#f0883e"
HEAD_BG = "#1c2128"
SEL_BG = "#1f3050"
CYAN = ACCENT      # legacy aliases
MAGENTA = ACCENT
VIOLET = BORDER
FONT = "Segoe UI"
MONO = "Consolas"

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


ctk.set_appearance_mode("dark")


def check_abuse(ip, key):
    r = requests.get(ABUSE_URL, headers={"Key": key, "Accept": "application/json"},
                     params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=10)
    r.raise_for_status()
    return r.json()["data"]


def check_vt(ip, key):
    r = requests.get(VT_URL + ip, headers={"x-apikey": key}, timeout=10)
    r.raise_for_status()
    return r.json()["data"]["attributes"]["last_analysis_stats"]


def explain(api, e):
    """Short human-readable reason for an API failure."""
    resp = getattr(e, "response", None)
    code = getattr(resp, "status_code", None) if resp is not None else None
    if code in (401, 403):
        return f"{api}: key rejected ({code})"
    if code == 429:
        return f"{api}: rate limit (429)"
    if code:
        return f"{api}: HTTP {code}"
    if isinstance(e, requests.exceptions.Timeout):
        return f"{api}: timeout"
    if isinstance(e, requests.exceptions.ConnectionError):
        return f"{api}: no connection"
    return f"{api}: bad response"


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


def verdict_for(score):
    if score >= 75:
        return "Malicious"
    if score >= 25:
        return "Suspicious"
    return "Clean"


def hex_to_rgb(h):
    return tuple(int(h[i:i + 2], 16) for i in (1, 3, 5))


def lerp(c1, c2, t):
    a, b = hex_to_rgb(c1), hex_to_rgb(c2)
    return "#%02x%02x%02x" % tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def neon_btn(parent, text, color, command, width=130, filled=False, **kw):
    """Primary (filled accent), secondary (neutral outline) and danger (red outline) buttons."""
    font = ctk.CTkFont(FONT, 13, "bold")
    if filled:
        return ctk.CTkButton(parent, text=text, width=width, height=34, corner_radius=6, fg_color=color,
                             text_color="#ffffff", hover_color=lerp(color, "#ffffff", 0.18), font=font,
                             command=command, **kw)
    danger = color == RED
    return ctk.CTkButton(parent, text=text, width=width, height=34, corner_radius=6, fg_color="transparent",
                         border_width=1, border_color=lerp(BORDER, RED, 0.6) if danger else BORDER,
                         text_color=RED if danger else TEXT, text_color_disabled=DIM,
                         hover_color=lerp(PANEL, RED, 0.2) if danger else lerp(PANEL, "#ffffff", 0.08),
                         font=font, command=command, **kw)


class App(ctk.CTk):
    def __init__(self):
        super().__init__(fg_color=BG)
        self.title(APP_NAME)
        self.after(250, self.set_icon)  # CTk resets the icon at startup, so set it after
        self.geometry("1420x800")
        self.minsize(980, 680)

        self.q = queue.Queue()
        self.stop_event = threading.Event()
        self.total = 0
        self.done = 0
        self.counts = {"Malicious": 0, "Suspicious": 0, "Clean": 0}
        self.running = False
        self.tick = 0

        self.build_ui()
        self.style_tree()
        n = sum(bool(DEFAULT_KEYS[k]) for k in ("abuse", "vt", "hp"))
        if n:
            self.set_status(f"Ready · default keys loaded {n}/3", GREEN)
        else:
            self.set_status("Ready · no default keys (keys.json not found or empty)", YELLOW)
        self.after(100, self.poll)

    # ---------- UI ----------
    def build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(4, weight=1)

        # Header
        head = ctk.CTkFrame(self, fg_color="transparent")
        head.grid(row=0, column=0, sticky="ew", padx=24, pady=(18, 4))
        head.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(head, text="SPECTER", font=ctk.CTkFont(FONT, 26, "bold"), text_color=TEXT
                     ).grid(row=0, column=0, sticky="w")
        self.dot = ctk.CTkLabel(head, text="●", font=ctk.CTkFont(FONT, 12), text_color=GREEN)
        self.dot.grid(row=0, column=2, sticky="e", padx=(0, 6))
        self.status = ctk.CTkLabel(head, text="Ready", font=ctk.CTkFont(FONT, 13, "bold"),
                                   text_color=GREEN, anchor="e")
        self.status.grid(row=0, column=3, sticky="e")
        ctk.CTkLabel(head, text="AbuseIPDB  ·  VirusTotal  ·  bulk IP reputation lookup",
                     font=ctk.CTkFont(FONT, 12), text_color=DIM).grid(row=1, column=0, columnspan=3, sticky="w")
        ctk.CTkLabel(head, text=CREDIT, font=ctk.CTkFont(FONT, 12), text_color=DIM
                     ).grid(row=1, column=3, sticky="e")

        # Gradient strip
        self.strip = tk.Canvas(self, height=1, bg=BORDER, highlightthickness=0)
        self.strip.grid(row=1, column=0, sticky="ew", padx=24, pady=(6, 10))
        self.strip.bind("<Configure>", self.draw_strip)

        # Input + keys
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.grid(row=2, column=0, sticky="ew", padx=24)
        top.grid_columnconfigure(0, weight=3)
        top.grid_columnconfigure(1, weight=2)

        left = ctk.CTkFrame(top, fg_color=PANEL, border_width=1, border_color=BORDER, corner_radius=8)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        left.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(left, text="Target IPs", font=ctk.CTkFont(FONT, 13, "bold"), text_color=TEXT
                     ).grid(row=0, column=0, sticky="w", padx=14, pady=(10, 0))
        self.ip_box = ctk.CTkTextbox(left, height=110, fg_color=FIELD, border_width=1, border_color=BORDER,
                                     text_color=TEXT, font=ctk.CTkFont(MONO, 13))
        self.ip_box.grid(row=1, column=0, columnspan=3, sticky="ew", padx=14, pady=8)
        bt = ctk.CTkFrame(left, fg_color="transparent")
        bt.grid(row=2, column=0, sticky="w", padx=14, pady=(0, 12))
        neon_btn(bt, "Load ips.txt", ACCENT, self.load_file, width=140).pack(side="left")
        neon_btn(bt, "Clear", DIM, self.clear_input, width=90).pack(side="left", padx=10)

        right = ctk.CTkFrame(top, fg_color=PANEL, border_width=1, border_color=BORDER, corner_radius=8)
        right.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        right.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(right, text="API Keys", font=ctk.CTkFont(FONT, 13, "bold"), text_color=TEXT
                     ).grid(row=0, column=0, sticky="w", padx=14, pady=(10, 0))
        ek = dict(fg_color=FIELD, border_color=BORDER, text_color=TEXT,
                  placeholder_text_color=DIM, show="*", font=ctk.CTkFont(MONO, 13), height=34)
        self.abuse_entry = ctk.CTkEntry(right, placeholder_text="AbuseIPDB key", **ek)
        self.abuse_entry.grid(row=1, column=0, sticky="ew", padx=14, pady=(8, 6))
        self.vt_entry = ctk.CTkEntry(right, placeholder_text="VirusTotal key", **ek)
        self.vt_entry.grid(row=2, column=0, sticky="ew", padx=14, pady=(0, 8))
        self.hp_entry = ctk.CTkEntry(right, placeholder_text="Honeypot key (optional)", **ek)
        self.hp_entry.grid(row=3, column=0, sticky="ew", padx=14, pady=(0, 8))
        opts = ctk.CTkFrame(right, fg_color="transparent")
        opts.grid(row=4, column=0, sticky="ew", padx=14, pady=(0, 12))
        self.show_keys = ctk.CTkCheckBox(opts, text="show keys", text_color=DIM, font=ctk.CTkFont(FONT, 12),
                                         fg_color=ACCENT, hover_color=ACCENT, border_color=BORDER,
                                         checkmark_color="#ffffff", command=self.toggle_keys)
        self.show_keys.pack(side="left")
        self.rate_entry = ctk.CTkEntry(opts, width=56, height=30, justify="center", fg_color=FIELD,
                                       border_color=BORDER, text_color=TEXT,
                                       font=ctk.CTkFont(MONO, 12))
        self.rate_entry.insert(0, str(DEFAULT_KEYS["rate"]))
        self.rate_entry.pack(side="right")
        ctk.CTkLabel(opts, text="VT req/min", text_color=DIM, font=ctk.CTkFont(FONT, 12)).pack(side="right", padx=(0, 8))
        if DEFAULT_KEYS["abuse"]:
            self.abuse_entry.insert(0, DEFAULT_KEYS["abuse"])
        if DEFAULT_KEYS["vt"]:
            self.vt_entry.insert(0, DEFAULT_KEYS["vt"])
        if DEFAULT_KEYS["hp"]:
            self.hp_entry.insert(0, DEFAULT_KEYS["hp"])

        # Stat cards
        stats = ctk.CTkFrame(self, fg_color="transparent")
        stats.grid(row=3, column=0, sticky="ew", padx=24, pady=12)
        for i in range(4):
            stats.grid_columnconfigure(i, weight=1)
        self.stat = {}
        for i, (key, label, color) in enumerate([("Total", "Scanned", TEXT), ("Malicious", "Malicious", RED),
                                                 ("Suspicious", "Suspicious", YELLOW), ("Clean", "Clean", GREEN)]):
            card = ctk.CTkFrame(stats, fg_color=PANEL, border_width=1, border_color=BORDER, corner_radius=8)
            card.grid(row=0, column=i, sticky="ew", padx=(0 if i == 0 else 6, 0 if i == 3 else 6))
            ctk.CTkLabel(card, text=label, font=ctk.CTkFont(FONT, 12), text_color=DIM
                         ).pack(pady=(8, 0))
            num = ctk.CTkLabel(card, text="0", font=ctk.CTkFont(FONT, 28, "bold"), text_color=color)
            num.pack(pady=(0, 6))
            self.stat[key] = num

        # Results table
        mid = ctk.CTkFrame(self, fg_color=PANEL, border_width=1, border_color=BORDER, corner_radius=8)
        mid.grid(row=4, column=0, sticky="nsew", padx=24)
        mid.grid_columnconfigure(0, weight=1)
        mid.grid_rowconfigure(0, weight=1)
        self.tree = ttk.Treeview(mid, columns=COLUMNS, show="headings", selectmode="extended")
        for c, h, w in zip(COLUMNS, HEADS, WIDTHS):
            self.tree.heading(c, text=h)
            self.tree.column(c, width=w, anchor="center")
        sb = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.grid(row=0, column=0, sticky="nsew", padx=(8, 0), pady=8)
        sb.grid(row=0, column=1, sticky="ns", pady=8, padx=(0, 8))
        self.tree.bind("<Control-c>", self.copy_selected)

        # Bottom bar
        bottom = ctk.CTkFrame(self, fg_color="transparent")
        bottom.grid(row=5, column=0, sticky="ew", padx=24, pady=14)
        bottom.grid_columnconfigure(3, weight=1)
        self.start_btn = neon_btn(bottom, "▶  Scan", ACCENT, self.start, width=120, filled=True)
        self.start_btn.grid(row=0, column=0)
        self.stop_btn = neon_btn(bottom, "■  Stop", RED, self.stop, width=100, state="disabled")
        self.stop_btn.grid(row=0, column=1, padx=10)
        neon_btn(bottom, "Export CSV", ACCENT, self.export, width=130).grid(row=0, column=2)
        self.progress = ctk.CTkProgressBar(bottom, height=10, corner_radius=5, fg_color=FIELD,
                                           progress_color=ACCENT, border_width=1, border_color=BORDER)
        self.progress.set(0)
        self.progress.grid(row=0, column=3, sticky="ew", padx=18)
        self.pct = ctk.CTkLabel(bottom, text="0%", width=50, font=ctk.CTkFont(FONT, 13), text_color=DIM)
        self.pct.grid(row=0, column=4)

    def draw_strip(self, e=None):
        pass  # flat 1px divider, nothing to draw

    def style_tree(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure("Treeview", background=FIELD, fieldbackground=FIELD, foreground=TEXT,
                    rowheight=30, borderwidth=0, font=(FONT, 10))
        s.configure("Treeview.Heading", background=HEAD_BG, foreground=TEXT, font=(FONT, 10, "bold"),
                    relief="flat", borderwidth=0, padding=6)
        s.map("Treeview", background=[("selected", SEL_BG)], foreground=[("selected", "#ffffff")])
        s.map("Treeview.Heading", background=[("active", BORDER)])
        s.configure("Vertical.TScrollbar", background=BORDER, troughcolor=FIELD, bordercolor=FIELD,
                    arrowcolor=DIM, relief="flat")
        self.tree.tag_configure("Malicious", foreground=RED)
        self.tree.tag_configure("Suspicious", foreground=YELLOW)
        self.tree.tag_configure("Clean", foreground=GREEN)
        self.tree.tag_configure("Skipped", foreground=DIM)
        self.tree.tag_configure("Error", foreground=ORANGE)

    # ---------- Actions ----------
    def toggle_keys(self):
        ch = "" if self.show_keys.get() else "*"
        self.abuse_entry.configure(show=ch)
        self.vt_entry.configure(show=ch)
        self.hp_entry.configure(show=ch)

    def load_file(self):
        path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            with open(path, encoding="utf-8", errors="ignore") as f:
                self.ip_box.delete("1.0", "end")
                self.ip_box.insert("1.0", f.read())

    def clear_input(self):
        self.ip_box.delete("1.0", "end")

    def copy_selected(self, _=None):
        rows = ["\t".join(str(v) for v in self.tree.item(i)["values"]) for i in self.tree.selection()]
        if rows:
            self.clipboard_clear()
            self.clipboard_append("\n".join(rows))

    def set_status(self, text, color):
        self.status.configure(text=text, text_color=color)

    def set_icon(self):
        try:
            base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
            self.iconbitmap(os.path.join(base, "specter.ico"))
        except Exception:
            pass  # missing icon file is not fatal

    def get_vt_rate(self):
        try:
            return max(1, min(1000, int(self.rate_entry.get().strip())))
        except ValueError:
            return DEFAULT_KEYS["rate"]

    def start(self):
        abuse_key = self.abuse_entry.get().strip()
        vt_key = self.vt_entry.get().strip()
        hp_key = self.hp_entry.get().strip()
        if not abuse_key or not vt_key:
            messagebox.showwarning("Keys missing", "Enter both AbuseIPDB and VirusTotal keys.")
            return
        seen, ips = set(), []
        for line in self.ip_box.get("1.0", "end").splitlines():
            ip = line.strip()
            if ip and ip not in seen:
                seen.add(ip)
                ips.append(ip)
        if not ips:
            messagebox.showinfo("No input", "Add some IPs first.")
            return

        self.tree.delete(*self.tree.get_children())
        self.total, self.done = len(ips), 0
        self.counts = {"Malicious": 0, "Suspicious": 0, "Clean": 0}
        self.refresh_stats()
        self.progress.set(0)
        self.pct.configure(text="0%")
        self.stop_event.clear()
        self.running = True
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        threading.Thread(target=self.run, args=(ips, abuse_key, vt_key, hp_key, self.get_vt_rate()), daemon=True).start()

    def stop(self):
        self.stop_event.set()
        self.set_status("Aborting…", YELLOW)

    def export(self):
        items = self.tree.get_children()
        if not items:
            messagebox.showinfo("Nothing to export", "No results yet.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", initialfile="results.csv",
                                            filetypes=[("CSV", "*.csv")])
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(COLUMNS)
            for i in items:
                w.writerow(self.tree.item(i)["values"])
        self.set_status(f"Saved · {os.path.basename(path)}", GREEN)

    def refresh_stats(self):
        self.stat["Total"].configure(text=str(self.done))
        for k, v in self.counts.items():
            self.stat[k].configure(text=str(v))

    # ---------- Worker thread ----------
    def run(self, ips, abuse_key, vt_key, hp_key="", vt_rate=VT_PER_MIN):
        vt_times = deque()  # timestamps of recent VirusTotal calls (sliding 60s window)
        for n, ip in enumerate(ips):
            if self.stop_event.is_set():
                break
            self.q.put(("status", f"Scanning {ip}  [{n + 1}/{len(ips)}]", ACCENT))
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                self.q.put(("row", (ip, "-", "Invalid IP", "-", "-", "-", "-", "-", "-"), "Error"))
                continue
            if addr.is_private:
                self.q.put(("row", (ip, "-", "Localhost" if addr.is_loopback else "Private", "-", "-", "-", "-", "-", "-"), "Skipped"))
                continue
            # sliding-window limiter: instant until the per-minute quota is used, then waits only as long as needed
            while not self.stop_event.is_set():
                now = time.time()
                while vt_times and now - vt_times[0] >= 60:
                    vt_times.popleft()
                if len(vt_times) < vt_rate:
                    break
                left = int(60 - (now - vt_times[0])) + 1
                self.q.put(("status", f"Rate limit cooldown  {left}s", YELLOW))
                self.stop_event.wait(1)
            if self.stop_event.is_set():
                break
            vt_times.append(time.time())
            try:
                d = check_abuse(ip, abuse_key)
            except (requests.RequestException, KeyError, ValueError) as e:
                reason = explain("Abuse", e)
                self.q.put(("row", (ip, "-", "Error: " + reason, "-", "-", "-", "-", "-", "-"), "Error"))
                self.q.put(("status", f"Error {ip}: {reason}", ORANGE))
                continue
            vt = None
            try:
                vt = check_vt(ip, vt_key)
            except (requests.RequestException, KeyError, ValueError) as e:
                self.q.put(("status", f"Error {ip}: {explain('VT', e)}", ORANGE))
                if getattr(getattr(e, "response", None), "status_code", None) == 429:
                    vt_times.extend([time.time()] * vt_rate)  # VT said slow down: wait a full window
            hp = check_honeypot(ip, hp_key) if hp_key else "-"
            score = d["abuseConfidenceScore"]
            v = verdict_for(score)
            vm = vt["malicious"] if vt else "n/a"
            vs = vt["suspicious"] if vt else "n/a"
            self.q.put(("row", (d["ipAddress"], score, v, d.get("countryCode") or "-",
                                d["totalReports"], vm, vs, hp, blacklist_status(score, vm, hp)), v))
        self.q.put(("done",))

    # ---------- Queue polling (main thread) ----------
    def poll(self):
        self.tick += 1
        if self.running:
            self.dot.configure(text_color=DIM if (self.tick // 5) % 2 else ACCENT)
        try:
            while True:
                msg = self.q.get_nowait()
                if msg[0] == "row":
                    self.tree.insert("", "end", values=msg[1], tags=(msg[2],))
                    self.tree.yview_moveto(1)
                    self.done += 1
                    if msg[2] in self.counts:
                        self.counts[msg[2]] += 1
                    self.refresh_stats()
                    frac = self.done / self.total
                    self.progress.set(frac)
                    self.pct.configure(text=f"{int(frac * 100)}%")
                elif msg[0] == "status":
                    self.set_status(msg[1], msg[2])
                elif msg[0] == "done":
                    self.running = False
                    self.dot.configure(text_color=GREEN)
                    self.start_btn.configure(state="normal")
                    self.stop_btn.configure(state="disabled")
                    self.set_status(f"Done · {self.done}/{self.total} scanned", GREEN)
        except queue.Empty:
            pass
        self.after(100, self.poll)


if __name__ == "__main__":
    print_banner()
    for note in KEYS_NOTES:
        print("  " + note)
    App().mainloop()
