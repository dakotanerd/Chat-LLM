# logger.py
import json
from datetime import datetime

LOG_FILE = "chat_log.jsonl"

def save_to_log(report, input_desc):
    entry = {
        "timestamp": datetime.now().isoformat(),
        "input": input_desc,
        "report": report
    }
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
