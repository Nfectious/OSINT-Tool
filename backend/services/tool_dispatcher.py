import logging
from typing import Any

from tools.phone.phoneinfoga import PhoneInfogaTool
from tools.phone.numverify import NumVerifyTool
from tools.email.holehe import HoleheTool
from tools.email.hibp import HIBPTool
from tools.email.email_rep import EmailRepTool
from tools.username.sherlock import SherlockTool
from tools.network.whois_tool import WHOISTool
from tools.network.dnsdumpster import DNSDumpsterTool
from tools.network.virustotal import VirusTotalTool
from tools.network.ip_geo import IPGeoTool
from tools.network.domain_rep import DomainRepTool
from tools.name.name_osint import NameOSINTTool
from tools.general.exiftool import ExifToolTool

logger = logging.getLogger(__name__)

# Map entity types to ordered tool lists.
# Tools marked premium_only=True are filtered out for free users at dispatch time.
ENTITY_TOOL_MAP: dict[str, list[type]] = {
    "phone":    [PhoneInfogaTool, NumVerifyTool],
    "email":    [HoleheTool, HIBPTool, EmailRepTool, VirusTotalTool],
    "username": [SherlockTool],
    "domain":   [WHOISTool, DNSDumpsterTool, VirusTotalTool, DomainRepTool],
    "ip":       [WHOISTool, IPGeoTool],
    "name":     [NameOSINTTool],
    "social":   [SherlockTool],
    "file":     [ExifToolTool],
}


class ToolDispatcher:
    """Dispatches OSINT tools based on entity type, respecting premium status."""

    def dispatch(
        self,
        entity_type: str,
        entity_value: str,
        is_premium: bool = False,
    ) -> list[dict[str, Any]]:
        all_tool_classes = ENTITY_TOOL_MAP.get(entity_type, [])
        if not all_tool_classes:
            logger.warning(f"No tools mapped for entity_type={entity_type}")
            return []

        # Filter premium-only tools for free users
        tool_classes = [
            cls for cls in all_tool_classes
            if not cls.premium_only or is_premium
        ]

        skipped = len(all_tool_classes) - len(tool_classes)
        if skipped:
            logger.info(
                f"Skipping {skipped} premium tool(s) for {entity_type}={entity_value} "
                "(user is not premium)"
            )

        results = []
        for tool_cls in tool_classes:
            tool = tool_cls()
            try:
                logger.info(f"Running {tool.name} on {entity_type}={entity_value}")
                result = tool.run(entity_value)
                results.append(result)
            except Exception as e:
                logger.error(f"Tool {tool.name} failed: {e}")
                results.append({
                    "tool_name": tool.name,
                    "category": tool.category,
                    "raw_data": {"error": str(e)},
                    "summary": f"Tool {tool.name} failed: {str(e)}",
                    "severity": "error",
                    "tags": ["error", "tool-failure"],
                })

        return results
