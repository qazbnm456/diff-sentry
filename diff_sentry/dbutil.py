"""One place to open a versioned SQLite state file, so an older build's file fails loudly at startup.

`CREATE TABLE IF NOT EXISTS` never alters an existing table, so a state directory written by a different build would otherwise crash later with `no such column`, or silently mis-read. Each store stamps `PRAGMA user_version` and refuses a file that has tables but a different (or no) stamp.

Pure stdlib; no dspy.
"""

from __future__ import annotations

import sqlite3
from urllib.parse import quote


def open_versioned(path: str, schema: str, version: int, marker_table: str, *,
                   read_only: bool = False) -> sqlite3.Connection:
    """Open a state file, creating and stamping it unless `read_only`, which opens it `mode=ro` and changes nothing (a peek at the state must not create tables, stamp a version, or fail on a read-only file)."""
    if read_only:
        db = sqlite3.connect(f"file:{quote(path)}?mode=ro", uri=True, check_same_thread=False)
    else:
        db = sqlite3.connect(path, check_same_thread=False)
    db.row_factory = sqlite3.Row
    try:
        stamped = db.execute("PRAGMA user_version").fetchone()[0]
        has_tables = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                                (marker_table,)).fetchone()
    except sqlite3.DatabaseError as exc:                 # a file that is not SQLite at all
        db.close()
        raise RuntimeError(f"{path} is not a diff-sentry state file ({exc}); move it aside or delete it") from exc
    if (has_tables or read_only) and stamped != version:
        db.close()
        raise RuntimeError(
            f"{path} was written by a different build of diff-sentry (schema {stamped or 'unversioned'}, this "
            f"build needs {version}). Move the state directory aside or delete it; there is no migration.")
    if read_only:
        return db
    db.executescript(schema)
    db.execute(f"PRAGMA user_version={int(version)}")
    db.commit()
    return db
