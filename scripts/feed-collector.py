#!/usr/bin/env python3
"""
feed_collector.py - CTI Feed Collector (OTX + URLhaus)

Now configured via config.py for consistent project-wide settings.
"""

import os
import sys
import time
import json
import logging
import requests
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

# --- Import project config ---
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from config import (
    FEED_OUTPUT_DIR,
    FEED_LOG_FILE,
    OTX_ENDPOINTS,
    URLHAUS_RECENT_URL
)

# --- Logging setup ---
os.makedirs(os.path.dirname(FEED_LOG_FILE), exist_ok=True)
logging.basicConfig(
    filename=FEED_LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

# Ensure output dir exists
os.makedirs(FEED_OUTPUT_DIR, exist_ok=True)

# -------------------------
# Helpers & Normalizers
# -------------------------
def guess_type_from_value(val):
    if not val:
        return "unknown"
    if "/" in val or val.startswith("http"):
        return "url"
    if val.count(".") == 3 and all(p.isdigit() for p in val.split(".")):
        return "ip"
    if len(val) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in val):
        return "hash"
    return "unknown"

def normalize_otx_item(item: Dict[str, Any], feed_name: str) -> Dict[str, Any]:
    value = item.get("indicator") or item.get("url") or item.get("sha256") or item.get("md5") or item.get("sha1")
    return {
        "id": item.get("id") or value or f"otx-{int(time.time())}",
        "source": "otx",
        "feed": feed_name,
        "type": item.get("type") or item.get("indicator_type") or guess_type_from_value(value),
        "value": value,
        "description": item.get("description") or item.get("pulse_info", {}).get("description"),
        "first_seen": item.get("first_seen") or item.get("created"),
        "last_seen": item.get("last_seen") or item.get("modified"),
        "confidence": item.get("confidence"),
        "raw": item
    }

def normalize_urlhaus_item(item: Dict[str, Any]) -> Dict[str, Any]:
    value = item.get("url") or item.get("host")
    return {
        "id": item.get("id") or value or f"urlhaus-{int(time.time())}",
        "source": "urlhaus",
        "feed": "recent",
        "type": "url",
        "value": value,
        "description": item.get("threat") or None,
        "first_seen": item.get("date_added") or None,
        "last_seen": None,
        "confidence": None,
        "raw": item
    }

def write_ndjson(filename: Path, items: List[Dict[str, Any]]):
    with filename.open("a", encoding="utf-8") as f:
        for it in items:
            f.write(json.dumps(it, default=str) + "\n")
    logging.info("Wrote %d items to %s", len(items), filename)

# -------------------------
# HTTP helper with retries
# -------------------------
def http_get(url: str, headers=None, params=None, timeout=20, retries=3, backoff=2):
    attempt = 0
    while attempt < retries:
        try:
            r = requests.get(url, headers=headers, params=params, timeout=timeout)
            if r.status_code == 200:
                return r
            else:
                logging.warning("GET %s returned HTTP %s", url, r.status_code)
        except requests.RequestException as e:
            logging.warning("GET %s exception: %s", url, e)
        attempt += 1
        time.sleep(backoff ** attempt)
    logging.error("Failed to GET %s after %d attempts", url, retries)
    return None

# -------------------------
# Fetchers
# -------------------------
def fetch_otx_endpoint(endpoint_path: str) -> List[Dict[str, Any]]:
    OTX_API_KEY = "7b44b622301c2b38f4f1235c9c713a748121985b5ef95455b74bf48c8be620b5"
    if not OTX_API_KEY:
        logging.info("OTX_API_KEY not configured; skipping OTX endpoint %s", endpoint_path)
        return []

    base = "https://otx.alienvault.com"
    url = f"{base}/{endpoint_path.lstrip('/')}"
    headers = {"X-OTX-API-KEY": OTX_API_KEY, "User-Agent": "cti-mvp/1.0"}
    resp = http_get(url, headers=headers, timeout=30, retries=4, backoff=2)
    if not resp:
        return []

    try:
        data = resp.json()
    except Exception as e:
        logging.error("Failed to parse JSON from OTX for %s: %s", endpoint_path, e)
        return []

    for k in ("results", "data", "indicators", "items", "url_list"):
        if isinstance(data.get(k), list):
            return data.get(k)
    if isinstance(data, list):
        return data
    if "indicator" in data:
        return [data["indicator"]]
    logging.warning("OTX %s response parsing uncertain; returning empty", endpoint_path)
    return []

def fetch_urlhaus_recent() -> List[Dict[str, Any]]:
    URLHAUS_AUTH_KEY = "2077cb494c1faeb176f24e2273ba28b944025bdf8b27645c"
    if not URLHAUS_AUTH_KEY:
        logging.info("URLHAUS_AUTH_KEY not configured; skipping URLhaus")
        return []

    headers = {"Auth-Key": URLHAUS_AUTH_KEY, "User-Agent": "cti-mvp/1.0"}
    resp = http_get(URLHAUS_RECENT_URL, headers=headers, timeout=30, retries=3, backoff=2)
    if not resp:
        return []

    try:
        js = resp.json()
    except Exception as e:
        logging.error("Failed to parse JSON from URLhaus: %s", e)
        return []

    if js.get("query_status") in ("ok", "success"):
        data_key = "urls" if isinstance(js.get("urls"), list) else "data"
        if isinstance(js.get(data_key), list):
            return js.get(data_key)
    logging.warning("URLhaus returned unexpected payload: %s", js.keys())
    return []

# -------------------------
# Main runner
# -------------------------
def run_collection():
    timestamp = datetime.utcnow().isoformat() + "Z"
    total = 0

    # --- Fetch OTX feeds ---
    for name, path, max_items in OTX_ENDPOINTS:
        items = fetch_otx_endpoint(path)
        if not items:
            logging.info("No items returned for OTX endpoint %s", path)
            continue

        if max_items and isinstance(max_items, int):
            items = items[:max_items]

        normalized = []
        for it in items:
            try:
                rec = normalize_otx_item(it, name)
                rec["collected_at"] = timestamp
                normalized.append(rec)
            except Exception as e:
                logging.debug("normalize_otx_item error: %s", e)

        if normalized:
            outfn = Path(FEED_OUTPUT_DIR) / f"otx_{name}.ndjson"
            write_ndjson(outfn, normalized)
            total += len(normalized)
        else:
            logging.info("No items normalized for OTX %s", name)

    # --- Fetch URLhaus ---
    url_items = fetch_urlhaus_recent()
    normalized_uh = []
    for it in url_items:
        try:
            rec = normalize_urlhaus_item(it)
            rec["collected_at"] = timestamp
            normalized_uh.append(rec)
        except Exception as e:
            logging.debug("normalize_urlhaus_item error: %s", e)

    if normalized_uh:
        outfn = Path(FEED_OUTPUT_DIR) / "urlhaus_recent.ndjson"
        write_ndjson(outfn, normalized_uh)
        total += len(normalized_uh)
    else:
        logging.info("No URLhaus items collected")

    logging.info("Collection finished. Total normalized items: %d", total)


if __name__ == "__main__":
    logging.info("=== Starting feed_collector.py ===")
    try:
        run_collection()
    except KeyboardInterrupt:
        logging.info("Interrupted by user.")
        sys.exit(1)
    except Exception as e:
        logging.exception("Collector failed: %s", e)
        sys.exit(2)
    logging.info("=== feed_collector.py Completed ===\n")
