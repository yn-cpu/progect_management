#!/usr/bin/env python3
"""Show all tables, columns, and top 10 rows from each table in received_data.db."""

import sqlite3
from pathlib import Path

DB = Path(__file__).parent / "received_data.db"

conn = sqlite3.connect(str(DB))
conn.row_factory = sqlite3.Row

# Get all tables
tables = [r[0] for r in conn.execute(
    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
).fetchall()]

print(f"\nDatabase: {DB}")
print(f"Tables: {tables}\n")

for table in tables:
    print("═" * 100)
    print(f"  TABLE: {table}")
    print("═" * 100)

    # Columns
    cols_info = conn.execute(f"PRAGMA table_info({table})").fetchall()
    cols = [c[1] for c in cols_info]
    print(f"  Columns ({len(cols)}): {', '.join(cols)}")

    # Row count
    total = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    print(f"  Total rows: {total}")

    # Top 10 rows
    print(f"\n  Top 10 rows:")
    rows = conn.execute(f"SELECT * FROM {table} LIMIT 10").fetchall()
    if not rows:
        print("    (empty)")
    else:
        for i, row in enumerate(rows, 1):
            print(f"\n  [{i}]")
            for col in cols:
                val = row[col]
                val_str = str(val) if val is not None else "NULL"
                if len(val_str) > 80:
                    val_str = val_str[:80] + "…"
                print(f"    {col:<20} {val_str}")
    print()

conn.close()
