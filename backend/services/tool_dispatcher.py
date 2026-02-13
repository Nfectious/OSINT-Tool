import logging
from typing import Any

from tools.phone.phoneinfoga import PhoneInfogaTool
from tools.phone.numverify import NumVerifyTool
from tools.email.holehe import HoleheTool
from tools.email.hibp import HIBPTool
from tools.username.sherlock import SherlockTool
from tools.network.whois_tool import WHOISTool
from tools.network.dnsdumpster import DNSDumpsterTool
from tools.network.virustotal import VirusTotalTool
from tools.general.exiftool import ExifToolTool

logger = logging.getLogger(__name__)

# Map entity types to the tools that should be run
ENTITY_TOOL_MAP: dict[str, list[type]] = {
    "phone": [PhoneInfogaTool, NumVerifyTool],
    "email": [HoleheTool, VirusTotalTool],
    "username": [SherlockTool],
    "domain": [WHOISTool, VirusTotalTool],
    "ip": [WHOISTool],
    "file": [ExifToolTool],
}


class ToolDispatcher:
    """Dispatches OSINT tools based on entity type."""

    def dispatch(self, entity_type: str, entity_value: str) -> list[dict[str, Any]]:
        tool_classes = ENTITY_TOOL_MAP.get(entity_type, [])
        if not tool_classes:
            logger.warning(f"No tools mapped for entity_type={entity_type}")
            return []

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
