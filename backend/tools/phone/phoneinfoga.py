import re
import requests
import logging
from tools.base_tool import BaseTool
from config import get_settings

logger = logging.getLogger(__name__)


class PhoneInfogaTool(BaseTool):
    """Queries the PhoneInfoga REST API for phone number intelligence."""

    @property
    def name(self) -> str:
        return "PhoneInfoga"

    @property
    def category(self) -> str:
        return "phone"

    def run(self, entity_value: str) -> dict:
        settings = get_settings()
        base_url = settings.PHONEINFOGA_URL

        # Strip + prefix — PhoneInfoga API wants digits only
        number = re.sub(r"[^\d]", "", entity_value)
        if not number:
            return self._make_finding(
                raw_data={"error": "Invalid phone number", "input": entity_value},
                summary=f"PhoneInfoga: invalid number {entity_value}",
                severity="error",
                tags=["error", "phone"],
            )

        # Call local scanner for basic info
        local_data = {}
        try:
            resp = requests.get(
                f"{base_url}/api/numbers/{number}/scan/local", timeout=30
            )
            resp.raise_for_status()
            body = resp.json()
            if body.get("success"):
                local_data = body.get("result", {})
        except requests.RequestException as e:
            logger.warning(f"PhoneInfoga local scan failed: {e}")

        # Call googlesearch scanner for OSINT dorks
        google_data = {}
        try:
            resp = requests.get(
                f"{base_url}/api/numbers/{number}/scan/googlesearch", timeout=30
            )
            resp.raise_for_status()
            body = resp.json()
            if body.get("success"):
                google_data = body.get("result", {})
        except requests.RequestException as e:
            logger.warning(f"PhoneInfoga googlesearch scan failed: {e}")

        if not local_data and not google_data:
            return self._make_finding(
                raw_data={"error": "Both scanners returned no data", "number": number},
                summary=f"PhoneInfoga: no data for {entity_value}",
                severity="error",
                tags=["error", "phone", "phoneinfoga"],
            )

        country = local_data.get("country", "Unknown")
        carrier = local_data.get("carrier", "Unknown")
        line_type = local_data.get("line_type", "Unknown")
        e164 = local_data.get("e164", entity_value)

        raw_data = {
            "local": local_data,
            "googlesearch": google_data,
        }

        summary = f"Phone: {carrier} {line_type} in {country}"

        return self._make_finding(
            raw_data=raw_data,
            summary=summary,
            severity="info",
            tags=["phone", "phoneinfoga"],
        )
