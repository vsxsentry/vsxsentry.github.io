#!/usr/bin/env bash
# VSXSentry - VS Code Extension Inventory & Threat Scanner (Bash)
# Works on macOS and Linux. Checks installed extensions against VSXSentry feed.

set -euo pipefail

FEED_URL="https://raw.githubusercontent.com/mthcht/awesome-lists/refs/heads/main/Lists/VSCODE%20Extensions/feeds/vsxsentry_feed.json"
OUTPUT="${TMPDIR:-/tmp}/vscode_extension_inventory.csv"
FEED_CACHE="${TMPDIR:-/tmp}/vsxsentry_feed.json"

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[0;33m'; NC='\033[0m'

echo -e "${CYAN}[*] Downloading VSXSentry feed...${NC}"
if curl -sSfL "$FEED_URL" -o "$FEED_CACHE" 2>/dev/null; then
    FEED_COUNT=$(python3 -c "import json; print(len(json.load(open('$FEED_CACHE'))['records']))" 2>/dev/null || echo "?")
    echo -e "${GREEN}[+] Loaded ${FEED_COUNT} IOCs${NC}"
else
    echo -e "${YELLOW}[!] Feed download failed, continuing without feed check${NC}"
    echo '{"records":[]}' > "$FEED_CACHE"
fi

# Build lookup set of extension IDs from feed
FEED_IDS=$(python3 -c "
import json, sys
feed = json.load(open('$FEED_CACHE'))
for r in feed.get('records', []):
    print(r['extension_id'].lower())
" 2>/dev/null || true)

echo "editor,extension_id,display_name,version,install_date,vsxsentry_match" > "$OUTPUT"

TOTAL=0
MATCHED=0
MATCH_LIST=""

for variant in \
    "VS Code:$HOME/.vscode/extensions" \
    "VS Code Insiders:$HOME/.vscode-insiders/extensions" \
    "VSCodium:$HOME/.vscode-oss/extensions" \
    "Cursor:$HOME/.cursor/extensions"; do

    IFS=':' read -r editor_name ext_dir <<< "$variant"
    [ ! -d "$ext_dir" ] && continue

    count=0
    for d in "$ext_dir"/*/; do
        [ ! -d "$d" ] && continue
        dirname=$(basename "$d")

        # Parse publisher.extension-version
        if [[ "$dirname" =~ ^([^.]+\.[^-]+)-(.+)$ ]]; then
            ext_id="${BASH_REMATCH[1]}"
            version="${BASH_REMATCH[2]}"
        else
            continue
        fi

        display_name=""
        pkg="$d/package.json"
        if [ -f "$pkg" ]; then
            display_name=$(python3 -c "
import json, sys
try:
    m = json.load(open('$pkg'))
    print(m.get('displayName', m.get('name', '')))
except: pass
" 2>/dev/null || true)
        fi

        install_date=""
        if [ -f "$pkg" ]; then
            install_date=$(stat -c '%Y' "$pkg" 2>/dev/null || stat -f '%m' "$pkg" 2>/dev/null || true)
            if [ -n "$install_date" ]; then
                install_date=$(date -d "@$install_date" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date -r "$install_date" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "$install_date")
            fi
        fi

        match="clean"
        ext_lower=$(echo "$ext_id" | tr '[:upper:]' '[:lower:]')
        if echo "$FEED_IDS" | grep -qxF "$ext_lower" 2>/dev/null; then
            match="MATCH"
            MATCHED=$((MATCHED + 1))
            MATCH_LIST="${MATCH_LIST}\n    >> ${editor_name}: ${ext_id}"
        fi

        echo "\"$editor_name\",\"$ext_id\",\"$display_name\",\"$version\",\"$install_date\",\"$match\"" >> "$OUTPUT"
        count=$((count + 1))
        TOTAL=$((TOTAL + 1))
    done

    [ "$count" -gt 0 ] && echo "    ${editor_name}: ${count} extensions"
done

echo ""
echo -e "${GREEN}[+] ${TOTAL} extensions found${NC}"
if [ "$MATCHED" -gt 0 ]; then
    echo -e "${RED}[!] MATCHED: ${MATCHED} extension(s) in VSXSentry feed!${NC}"
    echo -e "${RED}${MATCH_LIST}${NC}"
fi
echo -e "${GREEN}[+] Report: ${OUTPUT}${NC}"
