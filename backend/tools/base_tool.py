from abc import ABC, abstractmethod
from typing import Any
import logging

logger = logging.getLogger(__name__)


class BaseTool(ABC):
    """Abstract base class for all OSINT tools."""

    # Set to True on subclasses that require a premium account to run
    premium_only: bool = False

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable tool name."""
        ...

    @property
    @abstractmethod
    def category(self) -> str:
        """Tool category: phone, email, username, network, general."""
        ...

    @abstractmethod
    def run(self, entity_value: str) -> dict[str, Any]:
        """
        Execute the tool against the given entity value.

        Returns:
            dict with keys: tool_name, category, raw_data, summary, severity, tags
        """
        ...

    def execute(self, entity_value: str) -> dict[str, Any]:
        """Wrapper that catches exceptions and returns error findings on failure."""
        try:
            return self.run(entity_value)
        except Exception as e:
            logger.error(f"Tool {self.name} failed on '{entity_value}': {e}")
            return {
                "tool_name": self.name,
                "category": self.category,
                "raw_data": {"error": str(e), "entity_value": entity_value},
                "summary": f"Tool {self.name} encountered an error: {str(e)}",
                "severity": "error",
                "tags": ["error", "tool-failure"],
            }

    def _make_finding(
        self,
        raw_data: dict,
        summary: str,
        severity: str = "info",
        tags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Helper to build a standardized finding dict."""
        return {
            "tool_name": self.name,
            "category": self.category,
            "raw_data": raw_data,
            "summary": summary,
            "severity": severity,
            "tags": tags or [],
        }
