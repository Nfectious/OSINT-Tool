"""Anonymous aggregate stats — stored in a tiny SQLite DB.

No PII is ever recorded. Only: date, metric name, numeric value.
Metrics tracked:
  - run_count: total OSINT runs
  - analysis_count: total AI analyses
  - error_count: total errors
  - target_phone, target_email, target_username, target_domain,
    target_ip, target_name, target_social, target_file: counts by type
"""

import sqlite3
import logging
from datetime import date
from pathlib import Path

logger = logging.getLogger(__name__)

DB_PATH = Path("/app/data/anon_stats.db")


def _get_conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute(
        "CREATE TABLE IF NOT EXISTS anon_stats ("
        "  date TEXT NOT NULL,"
        "  metric TEXT NOT NULL,"
        "  value INTEGER NOT NULL DEFAULT 0,"
        "  PRIMARY KEY (date, metric)"
        ")"
    )
    conn.commit()
    return conn


def _increment(metric: str, amount: int = 1):
    today = date.today().isoformat()
    try:
        conn = _get_conn()
        conn.execute(
            "INSERT INTO anon_stats (date, metric, value) VALUES (?, ?, ?)"
            " ON CONFLICT(date, metric) DO UPDATE SET value = value + ?",
            (today, metric, amount, amount),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning(f"anon_stats write failed: {e}")


def record_run(entity_types: list[str]):
    """Record an OSINT run with its entity type breakdown."""
    _increment("run_count")
    for et in entity_types:
        _increment(f"target_{et}")


def record_analysis():
    _increment("analysis_count")


def record_error():
    _increment("error_count")


def get_aggregate() -> dict:
    """Return all-time aggregate stats (no dates, just totals)."""
    try:
        conn = _get_conn()
        rows = conn.execute(
            "SELECT metric, SUM(value) FROM anon_stats GROUP BY metric"
        ).fetchall()
        conn.close()
    except Exception as e:
        logger.warning(f"anon_stats read failed: {e}")
        return {}

    totals = {row[0]: row[1] for row in rows}

    total_runs = totals.get("run_count", 0)
    total_analyses = totals.get("analysis_count", 0)
    total_errors = totals.get("error_count", 0)

    # Build target type breakdown
    target_types = {}
    total_targets = 0
    for key, val in totals.items():
        if key.startswith("target_"):
            t = key.removeprefix("target_")
            target_types[t] = val
            total_targets += val

    # Convert to percentages
    type_pct = {}
    if total_targets > 0:
        for t, v in target_types.items():
            type_pct[t] = round(v / total_targets * 100, 1)

    error_rate = 0.0
    if total_runs > 0:
        error_rate = round(total_errors / total_runs * 100, 1)

    return {
        "total_runs": total_runs,
        "total_analyses": total_analyses,
        "total_errors": total_errors,
        "error_rate_pct": error_rate,
        "target_type_counts": target_types,
        "target_type_pct": type_pct,
    }


def get_daily(days: int = 30) -> list[dict]:
    """Return daily breakdown for the last N days."""
    try:
        conn = _get_conn()
        rows = conn.execute(
            "SELECT date, metric, value FROM anon_stats"
            " WHERE date >= date('now', ?)"
            " ORDER BY date DESC, metric",
            (f"-{days} days",),
        ).fetchall()
        conn.close()
    except Exception as e:
        logger.warning(f"anon_stats daily read failed: {e}")
        return []

    daily: dict[str, dict] = {}
    for d, metric, value in rows:
        if d not in daily:
            daily[d] = {"date": d}
        daily[d][metric] = value

    return list(daily.values())
