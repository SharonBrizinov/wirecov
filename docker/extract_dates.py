#!/usr/bin/env python3
"""Extract first_created / last_updated dates for all packet-*.c dissectors."""

import json
import os
import subprocess
import sys

dates = {}

result = subprocess.run(
    ["git", "log", "--format=COMMIT %aI", "--name-only", "--",
     "epan/dissectors/packet-*.c"],
    capture_output=True, text=True, cwd="/src/wireshark",
)

current_date = None
for line in result.stdout.splitlines():
    line = line.strip()
    if not line:
        continue
    if line.startswith("COMMIT "):
        current_date = line[7:].strip()[:10]  # YYYY-MM-DD
    elif line.startswith("epan/dissectors/packet-") and line.endswith(".c"):
        fname = os.path.basename(line)
        if fname not in dates:
            dates[fname] = {"last_updated": current_date, "first_created": current_date}
        else:
            # Older commits come later in git log, so keep overwriting first_created
            dates[fname]["first_created"] = current_date

json.dump(dates, open("/src/dissector_dates.json", "w"), indent=2)
print(f"Extracted dates for {len(dates)} dissectors", file=sys.stderr)
