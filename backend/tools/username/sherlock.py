import subprocess
import logging
from tools.base_tool import BaseTool

logger = logging.getLogger(__name__)


class SherlockTool(BaseTool):
    """Searches for username across social networks using Sherlock."""

    @property
    def name(self) -> str:
        return "Sherlock"

    @property
    def category(self) -> str:
        return "username"

    def run(self, entity_value: str) -> dict:
        try:
            result = subprocess.run(
                ["sherlock", entity_value, "--print-found", "--no-color", "--timeout", "10"],
                capture_output=True,
                text=True,
                timeout=60,
            )
        except subprocess.TimeoutExpired:
            return self._make_finding(
                raw_data={"error": "Sherlock timed out after 60s"},
                summary="Sherlock scan timed out",
                severity="error",
                tags=["error", "username", "timeout"],
            )
        except FileNotFoundError:
            return self._make_finding(
                raw_data={"error": "sherlock binary not found"},
                summary="Sherlock not installed",
                severity="error",
                tags=["error", "username", "missing-tool"],
            )

        stdout = result.stdout or ""
        found_urls = []

        for line in stdout.splitlines():
            line = line.strip()
            # Format: [+] Platform: https://url
            if line.startswith("[+]") and ": http" in line:
                url = line.split(": ", 1)[-1].strip()
                if url.startswith("http"):
                    found_urls.append(url)

        count = len(found_urls)
        raw_data = {
            "found_on": found_urls,
            "count": count,
        }

        if count > 0:
            summary = f"Found {count} platforms for username {entity_value}"
            severity = "medium"
        else:
            summary = f"Found 0 platforms for username {entity_value}"
            severity = "info"

        return self._make_finding(
            raw_data=raw_data,
            summary=summary,
            severity=severity,
            tags=["username", "social", "sherlock"],
        )
