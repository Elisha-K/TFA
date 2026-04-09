import os

# -------------------
# Directory Structure
# -------------------

# Base directory for the Threat Feed Aggregator (TFA)
BASE_DIR = os.path.expanduser("~/TFA")

# Subdirectories
SCRIPTS_DIR = os.path.join(BASE_DIR, "scripts")
FEED_OUTPUT_DIR = os.path.join(BASE_DIR, "feed-output")
FILTER_OUTPUT_DIR = os.path.join(BASE_DIR, "filter-output")
LOG_DIR = os.path.join(BASE_DIR, "logs")

# Output & log file paths
FILTER_OUTPUT_FILE = os.path.join(FILTER_OUTPUT_DIR, "filtered-feeds.ndjson")
FEED_LOG_FILE = os.path.join(LOG_DIR, "feed-collector.log")
FILTER_LOG_FILE = os.path.join(LOG_DIR, "nlp-filter.log")
CRON_LOG_FILE = os.path.join(LOG_DIR, "cron.log")


# -------------------
# Feed Collector Config
# -------------------

# OTX endpoints configuration
OTX_ENDPOINTS = [
    ("submitted_urls", "api/v1/indicators/submitted_urls", 1000),
    ("submitted_files", "api/v1/indicators/submitted_files", 1000),
    ("remcos_rat", "api/v1/pulses/654e38ed47abf8664ae89057/indicators", 1000),
    ("operation_endgame", "api/v1/pulses/687992eceac6f12e9cebd65f/indicators", 1000),
    ("fed_paypal", "api/v1/pulses/68c5743593a4bcc81dd94b0b/indicators", 1000),
    ("endclient_rat", "api/v1/pulses/690db706163c92798ce1bef9/indicators", 1000)
]

# URLhaus recent endpoint
URLHAUS_RECENT_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"


# -------------------
# NLP Filter Config
# -------------------

# Keywords for filtering (used by NLP Filter)
FILTER_KEYWORDS = ["spyware", "phishing"]

# Confidence scoring configuration
CONFIDENCE_WEIGHTS = {
    "source": 0.4,
    "recency": 0.3,
    "threat_type": 0.3
}
