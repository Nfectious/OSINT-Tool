import requests
import logging
from tools.base_tool import BaseTool
from config import get_settings

logger = logging.getLogger(__name__)


class HIBPTool(BaseTool):
    """Checks if an email has been in data breaches using Have I Been Pwned."""

    premium_only = True

    @property
    def name(self) -> str:
        return "HaveIBeenPwned"

    @property
    def category(self) -> str:
        return "email"

    def run(self, entity_value: str) -> dict:
        settings = get_settings()
        api_key = settings.HIBP_API_KEY

        if not api_key:
            return self._make_finding(
                raw_data={"error": "HIBP_API_KEY not configured"},
                summary="HIBP skipped: API key not configured",
                severity="info",
                tags=["email", "skipped"],
            )

        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{entity_value}"
        headers = {
            "hibp-api-key": api_key,
            "user-agent": "Valkyrie-OSINT",
        }
        params = {"truncateResponse": "false"}

        try:
            resp = requests.get(url, headers=headers, params=params, timeout=15)
        except requests.RequestException as e:
            return self._make_finding(
                raw_data={"error": str(e)},
                summary=f"HIBP lookup failed: {str(e)}",
                severity="error",
                tags=["error", "email"],
            )

        if resp.status_code == 404:
            return self._make_finding(
                raw_data={"breaches": [], "email": entity_value},
                summary=f"No breaches found for {entity_value}",
                severity="info",
                tags=["email", "hibp", "clean"],
            )

        if resp.status_code == 401:
            return self._make_finding(
                raw_data={"error": "Invalid HIBP API key"},
                summary="HIBP: Invalid API key",
                severity="error",
                tags=["error", "email", "auth"],
            )

        if resp.status_code != 200:
            return self._make_finding(
                raw_data={"error": f"HTTP {resp.status_code}", "body": resp.text[:500]},
                summary=f"HIBP returned status {resp.status_code}",
                severity="error",
                tags=["error", "email"],
            )

        breaches = resp.json()
        breach_names = [b.get("Name", "Unknown") for b in breaches]
        total_records = sum(b.get("PwnCount", 0) for b in breaches)

        data_classes = set()
        for b in breaches:
            data_classes.update(b.get("DataClasses", []))

        raw_data = {
            "email": entity_value,
            "breach_count": len(breaches),
            "breach_names": breach_names,
            "total_records_exposed": total_records,
            "data_classes": sorted(data_classes),
            "breaches": breaches,
        }

        if len(breaches) > 5:
            severity = "high"
        elif len(breaches) > 0:
            severity = "medium"
        else:
            severity = "info"

        summary = (
            f"HIBP: {entity_value} found in {len(breaches)} breach(es): "
            + ", ".join(breach_names[:5])
        )
        if len(breach_names) > 5:
            summary += f" (+{len(breach_names) - 5} more)"

        return self._make_finding(
            raw_data=raw_data,
            summary=summary,
            severity=severity,
            tags=["email", "hibp", "breach"],
        )
