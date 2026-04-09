#!/bin/bash
# ===========================================
# Sheduled Threat Feed Collection Pipeline
# ===========================================

# Define paths
PROJECT_DIR="/home/elisha/TFA/"
LOG_FILE="$PROJECT_DIR/logs/cron.log"
PYTHON="/usr/bin/python3"   # Or your venv Python, e.g. $PROJECT_DIR/venv/bin/python

# Move into the project directory
cd "$PROJECT_DIR/scripts" || exit 1

# Timestamp header for logs
echo "===================================" >> "$LOG_FILE"
echo "Pipeline started at: $(date)" >> "$LOG_FILE"
echo "===================================" >> "$LOG_FILE"

# Run the scripts in sequence
$PYTHON feed-collector.py >> "$LOG_FILE" 2>&1
$PYTHON nlp-filter.py >> "$LOG_FILE" 2>&1
sudo $PYTHON convert-to-cdb.py >> "$LOG_FILE" 2>&1

# Record completion
echo "Pipeline completed at: $(date)" >> "$LOG_FILE"
echo "" >> "$LOG_FILE"
