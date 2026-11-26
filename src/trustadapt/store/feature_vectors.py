"""Write the FR-03 feature vectors to the shared SQLite store (table `feature_vectors`).

Lives in the `store` module because every module reads and writes the same SQLite file. Written by the Data & Features work as a
first version; the owner of the shared store can merge it with the other tables (one connection helper, one place for all DDL).

The architecture (Integration & Docs, Week 8) lets every module read and write one SQLite file in WAL mode.
This module only covers the feature table; the table layout is the proposal in that design and should be
confirmed by the team before other modules depend on it. One row per device x window; writing the same
window again replaces the row, so re-running the pipeline never creates duplicates.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pandas as pd

from trustadapt.features.schema import FEATURE_COLUMNS

_TYPES = {
    "window_start": "REAL NOT NULL", "device_mac": "TEXT NOT NULL", "ip_src": "TEXT", "ip_dst": "TEXT",
    "port_src": "INTEGER", "port_dst": "INTEGER", "protocol_type": "TEXT", "app_protocol": "TEXT",
    "packet_rate_10s": "REAL", "bytes_sent_rate": "REAL", "connection_count": "INTEGER",
    "new_destination_count": "INTEGER", "activity_time": "REAL", "mean_packet_size": "REAL",
    "std_packet_size": "REAL", "mean_inter_arrival": "REAL", "std_inter_arrival": "REAL",
    "traffic_spike_flag": "INTEGER", "unusual_port_flag": "INTEGER", "failed_conn_count": "INTEGER",
}


def _connect(db_path: str | Path) -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(db_path))
    con.execute("PRAGMA journal_mode=WAL")           # the pipeline writes while the dashboard reads
    cols = ", ".join(f"{c} {_TYPES[c]}" for c in FEATURE_COLUMNS)
    con.execute(f"CREATE TABLE IF NOT EXISTS feature_vectors ({cols}, PRIMARY KEY (device_mac, window_start))")
    return con


def write_feature_vectors(db_path: str | Path, table: pd.DataFrame) -> int:
    """Insert or replace every row of the feature table. Returns the number of rows written."""
    if list(table.columns) != FEATURE_COLUMNS:
        raise ValueError("table columns differ from the schema (FEATURE_COLUMNS)")
    records = table.astype(object).where(table.notna(), None).values.tolist()   # plain Python values for sqlite3
    marks = ", ".join("?" * len(FEATURE_COLUMNS))
    with _connect(db_path) as con:                   # one transaction: all rows or none
        con.executemany(f"INSERT OR REPLACE INTO feature_vectors ({', '.join(FEATURE_COLUMNS)}) VALUES ({marks})", records)
    return len(records)


def read_feature_vectors(db_path: str | Path, device_mac: str | None = None) -> pd.DataFrame:
    """Read the vectors back in time order, optionally for one device."""
    with _connect(db_path) as con:
        sql, args = "SELECT * FROM feature_vectors", ()
        if device_mac:
            sql, args = sql + " WHERE device_mac = ?", (device_mac,)
        return pd.read_sql_query(sql + " ORDER BY window_start, device_mac", con, params=args)
