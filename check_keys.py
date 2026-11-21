import json, sys
try:
    with open("keys.json", encoding="utf-8-sig") as f:
        j = json.load(f)
except Exception as e:
    print("ERROR: keys.json cannot be read:", e)
    sys.exit(1)
for k in ("abuseipdb_key", "vt_key"):
    v = str(j.get(k, "")).strip()
    if not v or v.upper().startswith("PASTE"):
        print("ERROR: keys.json -> '%s' is empty. Paste your real key (keep the quotes)." % k)
        sys.exit(1)
hp = str(j.get("honeypot_key", "")).strip()
if hp.upper().startswith("PASTE"):
    print("NOTE: honeypot_key not filled, Honey Pot lookup will be skipped.")
print("keys.json OK")
