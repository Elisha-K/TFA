#!/usr/bin/env python3
import os
import json
import ndjson
import logging
import sys
from datetime import datetime

# --- Import configuration ---
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from config import (
    FEED_OUTPUT_DIR,
    FILTER_OUTPUT_DIR,
    FILTER_OUTPUT_FILE,
    LOG_DIR,
    FILTER_LOG_FILE,
    FILTER_KEYWORDS,
    CONFIDENCE_WEIGHTS
)

# --- Logging setup ---
logging.basicConfig(
    filename=FILTER_LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


# ----------------------------------------------------------
# Helper: Extract indicator from OTX, URLHaus, or mixed feeds
# ----------------------------------------------------------
def extract_indicator(record):
    """
    Extracts the most meaningful indicator from the feed record
    respecting OTX + URLHaus variations.
    """

    # 1. Direct indicator
    if "indicator" in record and record["indicator"]:
        return record["indicator"]

    # 2. Main value field (URL, domain, IP, hash)
    if "value" in record and record["value"]:
        return record["value"]

    # 3. Raw OTX fields
    raw = record.get("raw", {})
    if isinstance(raw, dict):
        if raw.get("indicator"):
            return raw.get("indicator")
        if raw.get("url"):
            return raw.get("url")

    return None


# ----------------------------------------------------------
# Helper: Derive threat type using heuristics
# ----------------------------------------------------------
def infer_threat_type(record):
    """
    Determines threat type using record keywords, fields, and feed metadata.
    """

    text = json.dumps(record).lower()

    if "ransom" in text:
        return "ransomware"
    if "phish" in text:
        return "phishing"
    if "remote access" in text or "rat" in text or "c2" in text:
        return "rat/c2"
    if "mozi" in text:
        return "botnet"
    if "trojan" in text:
        return "trojan"
    if "malware" in text:
        return "malware"

    return "unknown"


# ----------------------------------------------------------
# Confidence score calculator
# ----------------------------------------------------------
def compute_confidence(entry):
    score = 0.0

    # --- Source weighting ---
    source = entry.get("source", "").lower()
    if "otx" in source:
        score += 1.0 * CONFIDENCE_WEIGHTS["source"]
    elif "urlhaus" in source:
        score += 0.9 * CONFIDENCE_WEIGHTS["source"]
    else:
        score += 0.5 * CONFIDENCE_WEIGHTS["source"]

    # --- Recency weighting ---
    date_str = entry.get("collected_at") or entry.get("first_seen") or entry.get("date")
    if date_str:
        try:
            # Try multiple formats
            date = None
            try:
                date = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            except Exception:
                date = datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S %Z")

            days_old = (datetime.utcnow() - date).days

            if days_old < 1:
                score += 1.0 * CONFIDENCE_WEIGHTS["recency"]
            elif days_old < 3:
                score += 0.8 * CONFIDENCE_WEIGHTS["recency"]
            elif days_old < 7:
                score += 0.6 * CONFIDENCE_WEIGHTS["recency"]
            else:
                score += 0.3 * CONFIDENCE_WEIGHTS["recency"]
        except Exception:
            score += 0.3 * CONFIDENCE_WEIGHTS["recency"]

    # --- Threat type weighting ---
    threat = entry.get("threat_type", "").lower()
    if threat == "ransomware":
        score += 1.0 * CONFIDENCE_WEIGHTS["threat_type"]
    elif threat == "phishing":
        score += 0.8 * CONFIDENCE_WEIGHTS["threat_type"]
    elif threat in ["rat/c2", "trojan", "botnet", "malware"]:
        score += 0.7 * CONFIDENCE_WEIGHTS["threat_type"]
    else:
        score += 0.4 * CONFIDENCE_WEIGHTS["threat_type"]

    return round(score * 100, 2)


# ----------------------------------------------------------
# Load all feeds from FEED_OUTPUT_DIR
# ----------------------------------------------------------
def load_feeds(input_dir):
    feeds = []
    for file_name in os.listdir(input_dir):
        if file_name.endswith(".ndjson"):
            file_path = os.path.join(input_dir, file_name)
            try:
                with open(file_path, "r") as f:
                    data = ndjson.load(f)
                    feeds.extend(data)
                    logging.info(f"Loaded {len(data)} records from {file_name}")
            except Exception as e:
                logging.error(f"Error loading {file_name}: {e}")
    return feeds


# ----------------------------------------------------------
# Keyword filter
# ----------------------------------------------------------
def filter_iocs(feeds, keywords):
    filtered = []
    for entry in feeds:
        text = json.dumps(entry).lower()
        if any(kw.lower() in text for kw in keywords):
            filtered.append(entry)

    logging.info(f"Filtered {len(filtered)} IOCs using keyword set: {keywords}")
    return filtered


# ----------------------------------------------------------
# Normalize and enrich final structure
# ----------------------------------------------------------
def normalize_entry(entry):
    indicator = extract_indicator(entry)
    threat_type = infer_threat_type(entry)
    source = entry.get("source", "unknown")

    return {
        "indicator": indicator,
        "indicator_type": entry.get("type", "unknown"),
        "threat_type": threat_type,
        "source": source,
        "feed": entry.get("feed", None),

        # Timestamps
        "first_seen": entry.get("first_seen"),
        "last_seen": entry.get("last_seen"),
        "collected_at": entry.get("collected_at", datetime.utcnow().isoformat()),

        # URLHaus extras
        "url_status": entry.get("raw", {}).get("url_status"),
        "host": entry.get("raw", {}).get("host"),
        "tags": entry.get("raw", {}).get("tags"),

        # OTX extras
        "title": entry.get("raw", {}).get("title"),
        "is_active": entry.get("raw", {}).get("is_active"),
        "expiration": entry.get("raw", {}).get("expiration"),

        # Confidence score (computed)
        "confidence": compute_confidence({
            "source": source,
            "date": entry.get("collected_at"),
            "threat_type": threat_type
        })
    }


# ----------------------------------------------------------
# Write output to NDJSON
# ----------------------------------------------------------
def write_filtered_data(filtered_data, output_file):
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w") as f:     # Overwrite by design
        ndjson.dump(filtered_data, f)
    logging.info(f"Wrote {len(filtered_data)} records to {output_file}")


# ----------------------------------------------------------
# Main
# ----------------------------------------------------------
def main():
    logging.info("=== Starting NLP Filter ===")

    feeds = load_feeds(FEED_OUTPUT_DIR)
    filtered = filter_iocs(feeds, FILTER_KEYWORDS)
    normalized = [normalize_entry(e) for e in filtered]
    write_filtered_data(normalized, FILTER_OUTPUT_FILE)

    logging.info("=== NLP Filter Complete ===\n")


if __name__ == "__main__":
    main()
