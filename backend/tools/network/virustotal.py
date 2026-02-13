import requests
import logging
from tools.base_tool import BaseTool
from config import get_settings

logger = logging.getLogger(__name__)


class VirusTotalTool(BaseTool):
    """Queries VirusTotal API v3 for domain/IP/file reputation."""

    @property
    def name(self) -> str:
        return "VirusTotal"

    @property
    def category(self) -> str:
        return "network"

    def run(self, entity_value: str) -> dict:
        settings = get_settings()
        api_key = settings.VIRUSTOTAL_API_KEY

        if not api_key:
            return self._make_finding(
                raw_data={"skipped": True, "reason": "VIRUSTOTAL_API_KEY not configured"},
                summary="VirusTotal key not configured — skipping",
                severity="info",
                tags=["network", "virustotal", "skipped"],
            )

        headers = {"x-apikey": api_key}

        # Determine resource type based on entity value
        if "." in entity_value and not any(c == "/" for c in entity_value):
            # Domain or IP
            url = f"https://www.virustotal.com/api/v3/domains/{entity_value}"
            resource_type = "domain"
        else:
            # File hash
            url = f"https://www.virustotal.com/api/v3/files/{entity_value}"
            resource_type = "file"

        try:
            resp = requests.get(url, headers=headers, timeout=15)
        except requests.RequestException as e:
            return self._make_finding(
                raw_data={"error": str(e)},
                summary=f"VirusTotal lookup failed: {str(e)}",
                severity="error",
                tags=["error", "network", "virustotal"],
            )

        if resp.status_code == 404:
            return self._make_finding(
                raw_data={"resource": entity_value, "found": False},
                summary=f"VirusTotal: no data found for {entity_value}",
                severity="info",
                tags=["network", "virustotal"],
            )

        if resp.status_code != 200:
            return self._make_finding(
                raw_data={"error": f"HTTP {resp.status_code}", "body": resp.text[:500]},
                summary=f"VirusTotal returned status {resp.status_code}",
                severity="error",
                tags=["error", "network", "virustotal"],
            )

        data = resp.json()
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected
        reputation = attributes.get("reputation", "N/A")

        raw_data = {
            "resource": entity_value,
            "resource_type": resource_type,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "total_scanners": total,
            "reputation": reputation,
            "last_analysis_stats": stats,
        }

        if malicious > 5:
            severity = "critical"
        elif malicious > 0:
            severity = "high"
        elif suspicious > 0:
            severity = "medium"
        else:
            severity = "info"

        summary = (
            f"{malicious} engines flagged malicious, "
            f"{suspicious} suspicious out of {total} scanners"
        )

        return self._make_finding(
            raw_data=raw_data,
            summary=summary,
            severity=severity,
            tags=["network", "reputation", "virustotal"],
        )
