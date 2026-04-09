#!/usr/bin/env python3
"""
convert_to_cdb.py

Read NDJSON from FEED_OUTPUT (filtered-feeds.ndjson) and produce Wazuh list files
under /var/ossec/etc/lists/ in key(:value) format.

Logic:
- URLs: Preserves 'http://' scheme. Stored ONLY in ioc-urls.
- IPs: Populated from 'indicator_type="ipv4"' OR the JSON 'host' field. Stored in ioc-ips.
- No cross-contamination: IPs not extracted from URL strings.
"""

import json
import re
import os
import sys
import shutil
from pathlib import Path

# === CONFIG ===
FEED_FILE = os.path.expanduser("/home/elisha/TFA/filter-output/filtered-feeds.ndjson")
WAZUH_LIST_DIR = "/var/ossec/etc/lists"
OWNER_USER = "wazuh"
OWNER_GROUP = "wazuh"
FILE_MODE = 0o640

# Output source (plain text) files
OUT_IPS = Path(WAZUH_LIST_DIR) / "ioc-ips"
OUT_DOMAINS = Path(WAZUH_LIST_DIR) / "ioc-domains"
OUT_URLS = Path(WAZUH_LIST_DIR) / "ioc-urls"
OUT_HASHES = Path(WAZUH_LIST_DIR) / "ioc-hashes"

# Lightweight detectors
IP_RE = re.compile(r"^(?:(?:\d{1,3}\.){3}\d{1,3})$")
HASH_RE = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")

def is_ipv4(s: str) -> bool:
    """Validate IPv4 format."""
    if not s:
        return False
    if IP_RE.match(s):
        try:
            parts = s.split(".")
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
    return False

def is_hash(s: str) -> bool:
    """Validate MD5/SHA1/SHA256."""
    return bool(HASH_RE.match(s))

def normalize_url(url: str) -> str:
    """
    Clean URL but PRESERVE scheme (http://) and port.
    Wazuh rules need the exact string found in audit logs.
    """
    if not url:
        return ""
    # Strip whitespace and trailing slashes only
    return url.strip().rstrip('/')

def safe_write_atomic(path: Path, lines):
    """Write list to temp file and move it atomically to prevent partial reads."""
    path_tmp = Path(str(path) + ".tmp")
    try:
        with open(path_tmp, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
            # Ensure trailing newline
            f.write("\n")
        
        os.chmod(path_tmp, FILE_MODE)
        try:
            shutil.chown(path_tmp, OWNER_USER, OWNER_GROUP)
        except Exception:
            # Non-fatal if not running as root, but warn if needed
            pass
            
        path_tmp.replace(path)
    except Exception as e:
        print(f"[ERROR] Failed to write {path}: {e}", file=sys.stderr)
        if path_tmp.exists():
            os.remove(path_tmp)

def parse_and_build_lists(feed_file):
    ips = []
    domains = []
    urls = []
    hashes = []

    if not os.path.exists(feed_file):
        print(f"[ERROR] Feed file not found: {feed_file}", file=sys.stderr)
        return False

    print(f"[INFO] Reading from {feed_file}...")
    
    with open(feed_file, "r", encoding="utf-8") as f:
        line_no = 0
        for line in f:
            line_no += 1
            line = line.strip()
            if not line:
                continue
            
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                print(f"[WARN] JSON parse failed on line {line_no}", file=sys.stderr)
                continue

            # Extract fields
            indicator = rec.get("indicator") or ""
            itype = (rec.get("indicator_type") or "").lower()
            threat = rec.get("threat_type") or rec.get("threat") or "unknown"
            
            # The 'host' field from the JSON (e.g. "115.63.48.195")
            host_field = rec.get("host") or ""

            indicator = indicator.strip()
            threat = str(threat).strip()

            # --- LOGIC START ---

            # 1. IPv4 Type Indicators
            if itype in ("ipv4", "ip", "ip_address", "ip_address_v4"):
                if is_ipv4(indicator):
                    ips.append(f"{indicator}:{threat}")

            # 2. URL Type Indicators
            elif itype in ("url",):
                if indicator:
                    # Store full URL (with http://) in URLs list
                    norm_url = normalize_url(indicator)
                    urls.append(f"{norm_url}:{threat}")

                    # Store 'host' field in IPs list IF it is a valid IP
                    if host_field and is_ipv4(host_field):
                        ips.append(f"{host_field}:{threat}")
                    
                    # If 'host' is a domain, add to domains, 
                    elif host_field:
                        domains.append(f"{host_field}:{threat}")

            # 3. Domain Type Indicators
            elif itype in ("domain", "hostname", "fqdn"):
                if indicator:
                    domains.append(f"{indicator.lower()}:{threat}")
                    # Edge case: If a domain indicator is actually an IP
                    if is_ipv4(indicator):
                        ips.append(f"{indicator}:{threat}")

            # 4. Hash Type Indicators
            elif "hash" in itype or itype in ("md5", "sha1", "sha256"):
                if is_hash(indicator):
                    hashes.append(f"{indicator}:{threat}")

    # Deduplicate
    def dedup(seq):
        seen = set()
        out = []
        for s in seq:
            if s not in seen:
                seen.add(s)
                out.append(s)
        return out

    ips = dedup(ips)
    domains = dedup(domains)
    urls = dedup(urls)
    hashes = dedup(hashes)

    # Ensure directory exists
    Path(WAZUH_LIST_DIR).mkdir(parents=True, exist_ok=True)
    
    # Write files
    safe_write_atomic(OUT_IPS, ips)
    safe_write_atomic(OUT_DOMAINS, domains)
    safe_write_atomic(OUT_URLS, urls)
    safe_write_atomic(OUT_HASHES, hashes)
    
    # Uncomment in production if you want auto-compilation
    # try:
    #     subprocess.call(["/var/ossec/bin/ossec-makelists"])
    # except Exception:
    #     pass

    print(f"[OK] Completed converting to lists:")
    print(f"     IPs: {len(ips)}")
    print(f"     URLs: {len(urls)}")
    print(f"     Domains: {len(domains)}")
    print(f"     Hashes: {len(hashes)}")
    return True

if __name__ == "__main__":
    parse_and_build_lists(FEED_FILE)
