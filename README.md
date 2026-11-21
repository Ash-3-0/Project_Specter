# SPECTER (Desktop + Local Web)

Bulk IP threat lookup using **AbuseIPDB**, **VirusTotal** and **Project Honey Pot**.
Runs a small local web UI on `127.0.0.1:8765` (listens on localhost only). Pure Python standard library, no `pip install` needed.

## Run

```
python ioc_web_neon.py
```

The browser opens automatically. Set `PORT=xxxx` to use another port.

## API keys

Pick one:

1. Copy `keys.example.json` to `keys.json` and fill in your keys.
2. Type them into the page.
3. Set env vars `ABUSEIPDB_KEY`, `VT_KEY`, `HONEYPOT_KEY`.

`keys.json` is in `.gitignore`. Never commit it. Keys loaded from `keys.json`/env stay on the server and are never sent to the browser.

`vt_per_min` is the VirusTotal request rate (free tier = 4).

## Build an exe (Windows)

Needs Python 3.9+ in PATH. Double-click `build_all.bat`. Output: `dist\SPECTER.exe` (desktop, needs `customtkinter` + `requests`) and `dist\SPECTER_Web.exe` (local web).

- With a `keys.json` in the folder: personal build, keys are embedded (do not share that exe).
- Without `keys.json`: public build, no keys inside. The app then shows "You don't have access to the API keys".
  Set `DOWNLOAD_URL` at the top of `ioc_web_neon.py` to your releases link to show a Download button.

## Verdict logic

- AbuseIPDB score >= 75 Malicious, >= 25 Suspicious, else Clean
- Blacklisted if AbuseIPDB >= 75, or VirusTotal >= 3 engines malicious, or Honey Pot listing

Developed by Sparsh Bisht (AshHunts.pvtltd).
