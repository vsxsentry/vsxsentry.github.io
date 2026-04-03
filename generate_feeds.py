#!/usr/bin/env python3
"""
Generate all VSXSentry feed formats from the source vsxsentry_feed.json.
Run by GitHub Actions after fetching the feed from mthcht/awesome-lists.
"""
import csv
import json
import sys
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape as xml_escape

FEEDS_DIR = Path("feeds")
SOURCE = FEEDS_DIR / "vsxsentry_feed.json"
RISKY_PREFIX = "risky-"
SEV_SCORE = {"critical": 90, "high": 75, "medium": 50, "low": 25, "info": 10}
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def now_utc():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_source():
    data = json.loads(SOURCE.read_text("utf-8"))
    return data.get("records", []), data.get("generated_utc", now_utc())


def is_risky(r):
    return (r.get("metadata_category") or "").startswith(RISKY_PREFIX)


def write_json(path, records, feed_type="all", generated=""):
    payload = {"generated_utc": generated or now_utc(), "project": "VSXSentry",
               "feed_type": feed_type, "total_records": len(records), "records": records}
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_csv(path, records, fields=None):
    if not records:
        path.write_text("", encoding="utf-8")
        return
    fields = fields or list(records[0].keys())
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in records:
            w.writerow(r)


def write_txt(path, lines):
    content = "\n".join(sorted({l.strip() for l in lines if l.strip()}))
    path.write_text(content + ("\n" if content else ""), encoding="utf-8")


def gen_splunk_lookup(path, records):
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["extension_id", "publisher_id", "severity", "category", "comment", "source", "reference"])
        for r in records:
            w.writerow([r.get("extension_id", ""), r.get("publisher_id", ""),
                        r.get("metadata_severity", ""), r.get("metadata_category", ""),
                        r.get("metadata_comment", ""), r.get("metadata_source", ""),
                        r.get("metadata_reference", "")])


def gen_sentinel_watchlist(path, records):
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ExtensionId", "PublisherId", "Severity", "Category", "Comment", "Source"])
        for r in records:
            w.writerow([r.get("extension_id", ""), r.get("publisher_id", ""),
                        r.get("metadata_severity", ""), r.get("metadata_category", ""),
                        r.get("metadata_comment", ""), r.get("metadata_source", "")])


def gen_stix2(path, records, generated):
    ts = generated or now_utc()
    objects = [{"type": "identity", "spec_version": "2.1", "id": "identity--vsxsentry",
                "name": "VSXSentry", "identity_class": "system", "created": ts, "modified": ts}]
    for i, r in enumerate(records):
        eid = r.get("extension_id", "")
        objects.append({
            "type": "indicator", "spec_version": "2.1",
            "id": f"indicator--vsxsentry-{i}",
            "created": ts, "modified": ts, "name": eid,
            "description": f"{r.get('metadata_comment', '')} [{r.get('metadata_category', '')}]",
            "pattern": f"[software:name='{eid}']", "pattern_type": "stix",
            "indicator_types": ["malicious-activity"],
            "confidence": SEV_SCORE.get(r.get("metadata_severity", ""), 50),
            "labels": [r.get("metadata_category", ""), r.get("metadata_severity", "")],
            "created_by_ref": "identity--vsxsentry"
        })
    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "spec_version": "2.1", "objects": objects}
    path.write_text(json.dumps(bundle, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def gen_misp_event(path, records):
    attrs = []
    for i, r in enumerate(records):
        attrs.append({
            "uuid": str(uuid.uuid4()), "type": "text", "category": "Payload delivery",
            "value": r.get("extension_id", ""), "comment": r.get("metadata_comment", ""),
            "Tag": [{"name": f"vsxsentry:severity={r.get('metadata_severity', '')}"},
                    {"name": f"vsxsentry:category={r.get('metadata_category', '')}"}]
        })
    event = {"Event": {"info": "VSXSentry - VS Code Extension Threat Feed",
                        "date": now_utc()[:10], "threat_level_id": "2",
                        "analysis": "2", "distribution": "0", "Attribute": attrs}}
    path.write_text(json.dumps(event, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def gen_misp_warninglist(path, records):
    wl = {"name": "VSXSentry VS Code extension threat feed", "type": "string",
          "version": now_utc()[:10].replace("-", ""),
          "description": "VS Code extension IDs from the VSXSentry feed",
          "matching_attributes": ["text", "comment"],
          "list": [r.get("extension_id", "") for r in records]}
    path.write_text(json.dumps(wl, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def gen_opencti_csv(path, records):
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["entity_type", "observable_type", "observable_value",
                     "x_opencti_score", "confidence", "x_opencti_description", "x_opencti_labels"])
        for r in records:
            score = SEV_SCORE.get(r.get("metadata_severity", ""), 50)
            w.writerow(["indicator", "Text", r.get("extension_id", ""), score, score,
                        r.get("metadata_comment", ""),
                        f"{r.get('metadata_category', '')};{r.get('metadata_severity', '')}"])


def gen_openioc(path, records):
    items = []
    for r in records:
        eid = xml_escape(r.get("extension_id", ""))
        items.append(
            f'  <IndicatorItem condition="contains">\n'
            f'    <Context document="processItem" search="processItem/arguments" type="mir"/>\n'
            f'    <Content type="string">{eid}</Content>\n'
            f'  </IndicatorItem>')
    ioc = (f'<?xml version="1.0" encoding="utf-8"?>\n'
           f'<ioc xmlns="http://schemas.mandiant.com/2010/ioc" id="vsxsentry-{uuid.uuid4()}">\n'
           f'<short_description>VSXSentry VS Code Extension Threat Feed</short_description>\n'
           f'<description>Generated: {now_utc()}</description>\n'
           f'<definition>\n<Indicator operator="OR">\n'
           + "\n".join(items) +
           f'\n</Indicator>\n</definition>\n</ioc>\n')
    path.write_text(ioc, encoding="utf-8")


def gen_stats(path, all_r, mal, risky):
    cats = Counter(r.get("metadata_category", "") for r in all_r)
    sevs = Counter(r.get("metadata_severity", "") for r in all_r)
    pubs = Counter(r.get("publisher_id", "") for r in all_r)
    payload = {
        "generated_utc": now_utc(), "total_records": len(all_r),
        "total_malicious": len(mal), "total_risky": len(risky),
        "severity_counts": dict(sorted(sevs.items())),
        "category_counts": dict(sorted(cats.items())),
        "total_publishers": len(pubs), "top_publishers": pubs.most_common(25)
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main():
    if not SOURCE.exists():
        print(f"[!] Source not found: {SOURCE}", file=sys.stderr)
        return 1

    records, generated = load_source()
    malicious = [r for r in records if not is_risky(r)]
    risky = [r for r in records if is_risky(r)]

    csv_fields = ["extension_id", "publisher_id", "extension_name", "metadata_comment",
                  "metadata_severity", "metadata_category", "metadata_source",
                  "metadata_reference", "metadata_status", "removal_date"]

    # Combined
    write_json(FEEDS_DIR / "vsxsentry_feed.json", records, "all", generated)
    write_csv(FEEDS_DIR / "vsxsentry_feed.csv", records, csv_fields)
    write_txt(FEEDS_DIR / "ioc_all_extension_ids.txt", [r["extension_id"] for r in records])

    # Malicious
    write_json(FEEDS_DIR / "vsxsentry_malicious_feed.json", malicious, "malicious", generated)
    write_csv(FEEDS_DIR / "vsxsentry_malicious_feed.csv", malicious, csv_fields)
    write_txt(FEEDS_DIR / "ioc_high_risk_extension_ids.txt",
              [r["extension_id"] for r in malicious if SEV_RANK.get(r.get("metadata_severity"), 0) >= 3])
    write_txt(FEEDS_DIR / "ioc_block_publishers.txt",
              [r["publisher_id"] for r in malicious if SEV_RANK.get(r.get("metadata_severity"), 0) >= 3])

    # Risky
    write_json(FEEDS_DIR / "vsxsentry_risky_feed.json", risky, "risky", generated)
    write_csv(FEEDS_DIR / "vsxsentry_risky_feed.csv", risky, csv_fields)
    write_txt(FEEDS_DIR / "risky_extension_ids.txt", [r["extension_id"] for r in risky])

    # Platform formats (all records)
    gen_splunk_lookup(FEEDS_DIR / "vsxsentry_splunk_lookup.csv", records)
    gen_sentinel_watchlist(FEEDS_DIR / "vsxsentry_sentinel_watchlist.csv", records)
    gen_stix2(FEEDS_DIR / "vsxsentry_stix2_bundle.json", records, generated)
    gen_misp_event(FEEDS_DIR / "vsxsentry_misp_event.json", records)
    gen_misp_warninglist(FEEDS_DIR / "vsxsentry_misp_warninglist.json", records)
    gen_opencti_csv(FEEDS_DIR / "vsxsentry_opencti_import.csv", records)
    gen_openioc(FEEDS_DIR / "vsxsentry_openioc.ioc", records)
    gen_stats(FEEDS_DIR / "stats.json", records, malicious, risky)

    print(f"[+] Generated feeds: {len(records)} total = {len(malicious)} malicious + {len(risky)} risky")
    print(f"[+] {len(list(FEEDS_DIR.glob('*')))} files in {FEEDS_DIR}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
