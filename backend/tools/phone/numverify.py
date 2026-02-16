import requests
import logging
from tools.base_tool import BaseTool
from config import get_settings

logger = logging.getLogger(__name__)


class NumVerifyTool(BaseTool):
    """Validates phone numbers using the NumVerify API."""

    @property
    def name(self) -> str:
        return "NumVerify"

    @property
    def category(self) -> str:
        return "phone"

    def run(self, entity_value: str) -> dict:
        settings = get_settings()
        api_key = settings.NUMVERIFY_API_KEY

        if not api_key:
            return self._make_finding(
                raw_data={"skipped": True, "reason": "NUMVERIFY_API_KEY not configured"},
                summary="NumVerify key not configured — skipping",
                severity="info",
                tags=["phone", "numverify", "skipped"],
            )

        params = {
            "access_key": api_key,
            "number": entity_value,
            "country_code": "",
            "format": 1,
        }

        try:
            resp = requests.get(
                "http://apilayer.net/api/validate", params=params, timeout=15
            )
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as e:
            return self._make_finding(
                raw_data={"error": str(e)},
                summary=f"NumVerify lookup failed: {str(e)}",
                severity="error",
                tags=["error", "phone", "numverify"],
            )

        # Check for API-level errors (e.g. invalid key, quota exceeded)
        if "error" in data:
            err_info = data["error"]
            err_msg = err_info.get("info", str(err_info)) if isinstance(err_info, dict) else str(err_info)
            return self._make_finding(
                raw_data=data,
                summary=f"NumVerify API error: {err_msg}",
                severity="error",
                tags=["error", "phone", "numverify"],
            )

        valid = data.get("valid", False)
        country_code = data.get("country_code", "")
        country_name = data.get("country_name", "Unknown")
        carrier = data.get("carrier", "") or "Unknown"
        line_type = data.get("line_type", "") or "Unknown"
        location = data.get("location", "") or "Unknown"
        intl_format = data.get("international_format", entity_value)
        local_format = data.get("local_format", "")

        raw_data = data

        summary = (
            f"Valid: {'Yes' if valid else 'No'} | "
            f"Carrier: {carrier} | "
            f"Line Type: {line_type} | "
            f"Location: {location}, {country_name}"
        )
        severity = "low" if valid else "info"

        return self._make_finding(
            raw_data=raw_data,
            summary=summary,
            severity=severity,
            tags=["phone", "numverify", "validation", "carrier-lookup"],
        )
