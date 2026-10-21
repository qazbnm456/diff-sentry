"""Runs inside the container: `bash -n` and `dash -n` on each fragment, and reports what each said on stderr.

A shell that reaches the end of a fragment inside a quote, a substitution, `${…}` or a here-document says so; one that meets a different syntax error earlier stops there. Nothing is executed (`-n` only parses).
"""
import json
import os
import subprocess
import sys
import tempfile

fragments = json.load(sys.stdin)
out = []
with tempfile.TemporaryDirectory() as d:
    path = os.path.join(d, "s.sh")
    for text in fragments:
        with open(path, "w") as f:
            f.write(text)
        row = {}
        for sh in ("bash", "dash"):
            try:
                done = subprocess.run([sh, "-n", path], capture_output=True, timeout=3)
                row[sh] = done.stderr.decode("utf-8", "replace")[-400:]      # a shell may echo an internal marker byte
            except subprocess.TimeoutExpired:
                row[sh] = "timeout"
        out.append(row)
print(json.dumps(out))
