"""Anonymous aggregate stats endpoints — no auth required."""

from fastapi import APIRouter, Query
from services.anon_stats import get_aggregate, get_daily

router = APIRouter(prefix="/stats", tags=["stats"])


@router.get("/aggregate")
def aggregate_stats():
    """Return all-time anonymous aggregate usage stats (no PII)."""
    return get_aggregate()


@router.get("/daily")
def daily_stats(days: int = Query(default=30, ge=1, le=365)):
    """Return per-day anonymous stats for the last N days."""
    return get_daily(days)
