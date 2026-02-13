import subprocess
import logging
from tools.base_tool import BaseTool

logger = logging.getLogger(__name__)


class HoleheTool(BaseTool):
    """Checks email address registration across platforms using holehe."""

    @property
    def name(self) -> str:
        return "Holehe"

    @property
    def category(self) -> str:
        return "email"

    def run(self, entity_value: str) -> dict:
        try:
            result = subprocess.run(
                ["holehe", entity_value, "--only-used", "--no-color"],
                capture_output=True,
                text=True,
                timeout=90,
            )
        except subprocess.TimeoutExpired:
            return self._make_finding(
                raw_data={"error": "Holehe timed out after 90s"},
                summary="Holehe scan timed out",
                severity="error",
                tags=["error", "email", "timeout"],
            )
        except FileNotFoundError:
            return self._make_finding(
                raw_data={"error": "holehe binary not found"},
                summary="Holehe not installed",
                severity="error",
                tags=["error", "email", "missing-tool"],
            )

        stdout = result.stdout or ""
        found_platforms = []

        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith("[+]"):
                platform = line.replace("[+]", "").strip()
                # Skip footer lines like "Email used, [-] Email not used..."
                if platform and "Email" not in platform and "http" not in platform:
                    found_platforms.append(platform)

        count = len(found_platforms)
        raw_data = {
            "found_on": found_platforms,
            "count": count,
        }

        if count > 0:
            summary = f"Email found on {count} platforms"
            severity = "medium"
        else:
            summary = f"Email found on 0 platforms"
            severity = "info"

        return self._make_finding(
            raw_data=raw_data,
            summary=summary,
            severity=severity,
            tags=["email", "accounts", "holehe"],
        )
