#!/usr/bin/env python3
"""VSXSentry - VS Code Extension Inventory & Threat Scanner (Python)
Scans local VS Code extension directories and checks against the VSXSentry feed.
Works on Windows, macOS, and Linux.
"""

import json, os, re, sys, csv, pathlib
from urllib.request import urlopen
from datetime import datetime

FEED_URL = "https://raw.githubusercontent.com/mthcht/awesome-lists/refs/heads/main/Lists/VSCODE%20Extensions/feeds/vsxsentry_feed.json"
OUTPUT = os.path.join(os.environ.get("TEMP", "/tmp"), "vscode_extension_inventory.csv")

def get_extension_dirs():
    """Return all VS Code extension directories for the current user."""
    home = pathlib.Path.home()
    candidates = [
        home / ".vscode" / "extensions",
        home / ".vscode-insiders" / "extensions",
        home / ".vscode-oss" / "extensions",      # VSCodium
        home / ".cursor" / "extensions",           # Cursor
    ]
    return [(p.parent.parent.name.replace(".", "").replace("-", " ").title(), p)
            for p in candidates if p.is_dir()]

def parse_extension_dir(d):
    """Parse extension ID and version from directory name."""
    name = d.name
    m = re.match(r'^([^.]+\.[^-]+)-(.+)$', name)
    if not m:
        return None, None
    return m.group(1), m.group(2)

def load_feed():
    """Download and parse the VSXSentry feed."""
    try:
        print("[*] Downloading VSXSentry feed...", flush=True)
        with urlopen(FEED_URL, timeout=15) as resp:
            feed = json.loads(resp.read().decode())
        iocs = {r["extension_id"].lower(): r for r in feed.get("records", [])}
        print(f"[+] Loaded {len(iocs)} IOCs")
        return iocs
    except Exception as e:
        print(f"[!] Feed download failed: {e}")
        return {}

def scan():
    iocs = load_feed()
    results = []

    for editor_name, ext_dir in get_extension_dirs():
        count = 0
        for d in ext_dir.iterdir():
            if not d.is_dir():
                continue
            ext_id, version = parse_extension_dir(d)
            if not ext_id:
                continue

            display_name = ""
            description = ""
            publisher = ""
            pkg = d / "package.json"
            if pkg.exists():
                try:
                    m = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
                    display_name = m.get("displayName", m.get("name", ""))
                    description = m.get("description", "")
                    publisher = m.get("publisher", "")
                except Exception:
                    pass

            install_date = ""
            try:
                install_date = datetime.fromtimestamp(d.stat().st_ctime).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                pass

            match_info = iocs.get(ext_id.lower())
            results.append({
                "editor": editor_name,
                "extension_id": ext_id,
                "display_name": display_name,
                "publisher": publisher,
                "version": version,
                "description": description[:200],
                "install_date": install_date,
                "marketplace_url": f"https://marketplace.visualstudio.com/items?itemName={ext_id}",
                "vsxsentry_match": "MATCH" if match_info else "clean",
                "vsxsentry_severity": match_info["metadata_severity"] if match_info else "",
                "vsxsentry_category": match_info["metadata_category"] if match_info else "",
                "vsxsentry_comment": match_info["metadata_comment"] if match_info else "",
            })
            count += 1
        if count:
            print(f"    {editor_name}: {count} extensions")

    # Write CSV
    if results:
        with open(OUTPUT, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=results[0].keys())
            w.writeheader()
            w.writerows(results)

    matched = [r for r in results if r["vsxsentry_match"] == "MATCH"]
    print(f"\n[+] {len(results)} extensions found")
    if matched:
        print(f"[!] MATCHED: {len(matched)} extension(s) in VSXSentry feed!")
        for r in matched:
            print(f"    >> {r['editor']}: {r['extension_id']} [{r['vsxsentry_severity']}] {r['vsxsentry_category']}")
    print(f"[+] Report: {OUTPUT}")

if __name__ == "__main__":
    scan()
